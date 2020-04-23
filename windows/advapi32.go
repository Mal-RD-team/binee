package windows

import (
	"encoding/binary"
	"github.com/carbonblack/binee/util"
)

type ServiceTableEntry struct {
	ServiceName string
	ServiceProc uint64
}

func startServiceCtrlDispatcher(emu *WinEmulator, addr uint64, wide bool) ServiceTableEntry {
	entry := ServiceTableEntry{}
	nameAddrBytes, _ := emu.Uc.MemRead(addr, emu.PtrSize)
	nameAddr := uint64(binary.LittleEndian.Uint32(nameAddrBytes))

	var name string
	if wide == true {
		name = util.ReadWideChar(emu.Uc, nameAddr, 0)
	} else {
		name = util.ReadASCII(emu.Uc, nameAddr, 0)
	}

	procAddrBytes, _ := emu.Uc.MemRead(addr+emu.PtrSize, emu.PtrSize)
	procAddr := uint64(binary.LittleEndian.Uint32(procAddrBytes))

	entry.ServiceName = name
	entry.ServiceProc = procAddr
	return entry
}
func getComputerName(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	sizeRaw := make([]byte, 4)
	err := emu.Uc.MemReadInto(sizeRaw, in.Args[1])
	if err != nil {
		return SkipFunctionStdCall(true, 0)
	}
	size := binary.LittleEndian.Uint32(sizeRaw)

	//Writes the size to second parameter anyways.
	rawLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(rawLength, uint32(len(emu.Opts.ComputerName)+1))
	err = emu.Uc.MemWrite(in.Args[1], rawLength)
	if len(emu.Opts.ComputerName)+1 > int(size) {
		emu.setLastError(ERROR_INSUFFICIENT_BUFFER)
		return SkipFunctionStdCall(true, 0)
	}
	if wide {
		wideString := util.ASCIIToWinWChar(emu.Opts.ComputerName)
		wideString = append(wideString, 0, 0)
		emu.Uc.MemWrite(in.Args[0], wideString)
	} else {
		emu.Uc.MemWrite(in.Args[0], append([]byte(emu.Opts.ComputerName), 0))
	}
	return SkipFunctionStdCall(true, 1)
}

func getUsername(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	sizeRaw := make([]byte, 4)
	err := emu.Uc.MemReadInto(sizeRaw, in.Args[1])
	if err != nil {
		return SkipFunctionStdCall(true, 0)
	}
	size := binary.LittleEndian.Uint32(sizeRaw)

	//Writes the size to second parameter anyways.
	rawLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(rawLength, uint32(len(emu.Opts.User)+1))
	err = emu.Uc.MemWrite(in.Args[1], rawLength)
	if len(emu.Opts.User)+1 > int(size) {
		emu.setLastError(ERROR_INSUFFICIENT_BUFFER)
		return SkipFunctionStdCall(true, 0)
	}
	if wide {
		wideString := util.ASCIIToWinWChar(emu.Opts.User)
		wideString = append(wideString, 0, 0)
		emu.Uc.MemWrite(in.Args[0], wideString)
	} else {
		emu.Uc.MemWrite(in.Args[0], append([]byte(emu.Opts.User), 0))
	}
	return SkipFunctionStdCall(true, 1)
}
func AdvApi32Hooks(emu *WinEmulator) {
	emu.AddHook("", "FreeSid", &Hook{
		Parameters: []string{"pSide"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
	emu.AddHook("", "CheckTokenMembership", &Hook{
		Parameters: []string{"TokenHandle", "SidToCheck", "IsMember"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "StartServiceCtrlDispatcherA", &Hook{
		Parameters: []string{"v:lpServiceStartTable"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			entry := startServiceCtrlDispatcher(emu, in.Args[0], false)
			in.Hook.Values[0] = entry
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})

	emu.AddHook("", "GetSecurityInfo", &Hook{
		Parameters: []string{"handle", "ObjectType", "SecurityInfo", "ppsidOwnerr", "ppsideGroup", "ppDacl", "ppSacl", "ppSecurityDescriptor"},
		Fn:         SkipFunctionStdCall(true, ERROR_SUCCESS),
	})
	emu.AddHook("", "GetUserNameA", &Hook{
		Parameters: []string{"lpBuffer", "pcbBuffer"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return getUsername(emu, in, false)(emu, in)
		},
	})
	emu.AddHook("", "GetUserNameW", &Hook{
		Parameters: []string{"lpBuffer", "pcbBuffer"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return getUsername(emu, in, true)(emu, in)
		},
	})
	emu.AddHook("", "GetComputerNameA", &Hook{
		Parameters: []string{"lpBuffer", "pcbBuffer"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return getComputerName(emu, in, false)(emu, in)
		},
	})
	emu.AddHook("", "GetComputerNameW", &Hook{
		Parameters: []string{"lpBuffer", "pcbBuffer"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return getComputerName(emu, in, true)(emu, in)
		},
	})
	emu.AddHook("", "StartServiceCtrlDispatcherW", &Hook{
		Parameters: []string{"v:lpServiceStartTable"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			entry := startServiceCtrlDispatcher(emu, in.Args[0], true)
			in.Hook.Values[0] = entry
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})

	emu.AddHook("", "OpenSCManagerA", &Hook{
		Parameters: []string{"a:MachineName", "a:DatabaseName", "dwDesiredAccess"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0x1313)(emu, in)
		},
	})
	emu.AddHook("", "OpenSCManagerW", &Hook{
		Parameters: []string{"w:MachineName", "w:DatabaseName", "dwDesiredAccess"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0x1313)(emu, in)
		},
	})

	emu.AddHook("", "OpenServiceA", &Hook{
		Parameters: []string{"hSCManager", "a:lpServiceName", "dwDesiredAccess"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})
	emu.AddHook("", "OpenServiceW", &Hook{
		Parameters: []string{"hSCManager", "w:lpServiceName", "dwDesiredAccess"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})

	emu.AddHook("", "ControlService", &Hook{
		Parameters: []string{"hService", "dwControl", "lpServiceStatus"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})

	emu.AddHook("", "CloseServiceHandle", &Hook{
		Parameters: []string{"hSCObject"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 1)(emu, in)
		},
	})

	emu.AddHook("", "DeleteService", &Hook{
		Parameters: []string{"hService"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 1)(emu, in)
		},
	})
}
