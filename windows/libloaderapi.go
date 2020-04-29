package windows

import (
	"github.com/carbonblack/binee/pefile"
	"github.com/carbonblack/binee/util"
	"strconv"
)

func FindResource(emu *WinEmulator, in *Instruction) bool {
	var resourceName interface{}
	var resourceType interface{}
	wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
	resourceNameArg := in.Args[1]
	resourceTypeArg := in.Args[2]
	resourceName = uint32(resourceNameArg)
	resourceType = uint32(resourceTypeArg)
	if (resourceNameArg >> 16) > 0 {
		if wide {
			resourceName = util.ReadWideChar(emu.Uc, resourceNameArg, 0)
		} else {
			resourceName = util.ReadASCII(emu.Uc, resourceNameArg, 0)
		}
		if resourceName.(string)[0] == '#' {
			var err error
			resourceName, err = strconv.Atoi(resourceName.(string)[1:])
			if err != nil {
				return SkipFunctionStdCall(true, 0)(emu, in) //Failed to parse
			}
		}
	}
	if (resourceTypeArg >> 16) > 0 {
		if wide {
			resourceType = util.ReadWideChar(emu.Uc, resourceTypeArg, 0)
		} else {
			resourceType = util.ReadASCII(emu.Uc, resourceTypeArg, 0)
		}
		if resourceType.(string)[0] == '#' {
			var err error
			resourceType, err = strconv.Atoi(resourceType.(string)[1:])
			if err != nil {
				return SkipFunctionStdCall(true, 0)(emu, in) //Failed to parse
			}
		}
	}

	handle := in.Args[0]
	if handle == emu.MemRegions.ImageAddress || handle == 0 {
		dataEntry := pefile.FindResource(emu.ResourcesRoot, resourceName, resourceType)
		addr := emu.Heap.Malloc(4)
		handle := &Handle{ResourceDataEntry: dataEntry}
		emu.Handles[addr] = handle
		return SkipFunctionStdCall(true, addr)(emu, in)

	} else {
		//Handle for other loaded files.

	}
	return SkipFunctionStdCall(true, 0)(emu, in)
}

func LibloaderapiHooks(emu *WinEmulator) {
	emu.AddHook("", "DisableThreadLibraryCalls", &Hook{
		Parameters: []string{"hLibModule"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "ResolveDelayLoadedAPI", &Hook{
		Parameters: []string{"ParentModuleBase", "DelayloadedDescriptor", "FailureDllHook", "FailureSystemHook", "ThunkAddress", "Flags"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "SetDefaultDllDirectories", &Hook{
		Parameters: []string{"DirectoryFlags"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	//HGLOBAL LoadResource(
	//  HMODULE hModule,
	//  HRSRC   hResInfo
	//);
	emu.AddHook("", "LoadResource", &Hook{
		Parameters: []string{"hModule", "hResInfo"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			baseAddress := in.Args[0]
			addr := in.Args[1]
			if _, ok := emu.Handles[addr]; !ok {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			dataEntry := emu.Handles[addr].ResourceDataEntry
			location := baseAddress + uint64(dataEntry.OffsetToData)
			return SkipFunctionStdCall(true, location)(emu, in)
		},
	})
	emu.AddHook("", "SizeofResource", &Hook{
		Parameters: []string{"hModule", "hResInfo"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			addr := in.Args[1]
			if handle, ok := emu.Handles[addr]; ok {
				return SkipFunctionStdCall(true, uint64(handle.ResourceDataEntry.Size))(emu, in)
			}
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})
	emu.AddHook("", "LockResource", &Hook{
		Parameters: []string{"HGlobal"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, in.Args[0])(emu, in)
		},
	})

	emu.AddHook("", "FindResourceA", &Hook{
		Parameters: []string{"hModule", "a:lpName", "a:lpType"},
		Fn:         FindResource,
	})

	emu.AddHook("", "FindResourceW", &Hook{
		Parameters: []string{"hModule", "a:lpName", "a:lpType"},
		Fn:         FindResource,
	})

}
