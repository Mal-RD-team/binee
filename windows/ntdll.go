package windows

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/carbonblack/binee/pefile"
	"io/ioutil"

	"github.com/carbonblack/binee/util"

	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func allocateVirtualMemory(emu *WinEmulator, in *Instruction) bool {
	// Get the pointers
	baseAddr := in.Args[1]
	sizePtr := in.Args[3]

	// Get the values at those pointers
	sizeBytes, _ := emu.Uc.MemRead(sizePtr, emu.PtrSize)
	startBytes, _ := emu.Uc.MemRead(baseAddr, emu.PtrSize)

	// Convert to uint64
	size := uint64(0)
	start := uint64(0)
	if emu.UcMode == uc.MODE_32 {
		size = uint64(binary.LittleEndian.Uint32(sizeBytes))
		start = uint64(binary.LittleEndian.Uint32(startBytes))
	} else {
		size = binary.LittleEndian.Uint64(sizeBytes)
		start = binary.LittleEndian.Uint64(startBytes)
	}

	// allocate the memory
	addr, size := emu.Heap.MMap(start, size)

	// write the new values into memory
	if emu.UcMode == uc.MODE_32 {
		util.StructWrite(emu.Uc, baseAddr, uint32(addr))
		util.StructWrite(emu.Uc, sizePtr, uint32(size))
	} else {
		util.StructWrite(emu.Uc, baseAddr, addr)
		util.StructWrite(emu.Uc, sizePtr, size)
	}

	return SkipFunctionStdCall(true, 0x0)(emu, in)
}

func freeVirtualMemory(emu *WinEmulator, in *Instruction) bool {
	// Get the pointers
	baseAddr := in.Args[1]
	sizePtr := in.Args[2]

	// Get the values at those pointers
	sizeBytes, _ := emu.Uc.MemRead(sizePtr, emu.PtrSize)
	startBytes, _ := emu.Uc.MemRead(baseAddr, emu.PtrSize)
	// Convert to uint64
	size := uint64(0)
	start := uint64(0)
	if emu.UcMode == uc.MODE_32 {
		size = uint64(binary.LittleEndian.Uint32(sizeBytes))
		start = uint64(binary.LittleEndian.Uint32(startBytes))
	} else {
		size = binary.LittleEndian.Uint64(sizeBytes)
		start = binary.LittleEndian.Uint64(startBytes)
	}
	if size == 0 && emu.Heap.Free(start) == 1 {
		return SkipFunctionStdCall(true, 0x0)(emu, in)
	}
	return SkipFunctionStdCall(true, 0x1)(emu, in)
}

func imageNtHeaderEX(emu *WinEmulator, in *Instruction) bool {
	//in.Args[4]+118
	pointerOut := in.Args[4]
	baseAddress := in.Args[1]
	dosHeader := &pefile.DosHeader{}
	byte1, _ := emu.Uc.MemRead(baseAddress, 64)
	r := bytes.NewReader(byte1)
	if err := binary.Read(r, binary.LittleEndian, dosHeader); err != nil {
		return SkipFunctionStdCall(true, 1)(emu, in)
	}
	byte := make([]byte, 4)
	NTheaderPointer := uint32(in.Args[1]) + dosHeader.AddressExeHeader
	binary.LittleEndian.PutUint32(byte, NTheaderPointer)
	emu.Uc.MemWrite(pointerOut, byte)
	return SkipFunctionStdCall(true, 0)(emu, in)
}

func zwQueryInformationProcess(emu *WinEmulator, in *Instruction) bool {

	return SkipFunctionStdCall(true, 1)(emu, in)
}
func zwQuerySystemInformation(emu *WinEmulator, in *Instruction) bool {
	class := in.Args[0]
	actualClass := GetSystemInformationClass(int(class))
	in.Hook.Parameters[0] = "s:" + in.Hook.Parameters[0]
	in.Hook.Values[0] = actualClass
	//typedef struct _SYSTEM_BASIC_INFORMATION {
	//    BYTE Reserved1[24];
	//    PVOID Reserved2[4];
	//    CCHAR NumberOfProcessors;
	//} SYSTEM_BASIC_INFORMATION;

	if actualClass == "SystemBasicInformation" {
		var reserved [24]byte
		var reserved2 [4]uint32
		val := struct {
			Reserved1          [24]byte
			Reserved2          [4]uint32
			NumberOfProcessors byte
		}{reserved,
			reserved2,
			1,
		}
		buff := new(bytes.Buffer)
		binary.Write(buff, binary.LittleEndian, &val)
		emu.Uc.MemWrite(in.Args[2], buff.Bytes())
	}
	return SkipFunctionStdCall(true, 1)(emu, in)
}
func zwMapViewOfSection(emu *WinEmulator, in *Instruction) func(emu *WinEmulator, in *Instruction) bool {
	//Doesnt support  other process yet.
	//if in.Args[1]!=0xFFFFFFFF {
	//	return SkipFunctionStdCall(true,STATUS_SUCCESS)
	//}
	if emu.PtrSize == 4 {
		buf := make([]byte, 4)
		pointerToVar := in.Args[2]
		//write pointer value
		//ptr := emu.Malloc(emu.PtrSize)
		binary.LittleEndian.PutUint32(buf, uint32(in.Args[0]))
		emu.Uc.MemWrite(pointerToVar, buf)
	} else {
	}
	return SkipFunctionStdCall(true, STATUS_SUCCESS)

}
func NtdllHooks(emu *WinEmulator) {
	hRtlSetThreadPoolStartFunc := &Hook{
		Parameters: []string{"StartPoolThread", "ExitPoolThread"},
		Fn:         SkipFunctionStdCall(true, STATUS_SUCCESS),
	}
	emu.AddHook("", "_aullshr", &Hook{
		Parameters: []string{"A", "B"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, in.Args[0]>>in.Args[1])(emu, in)
		},
	})
	emu.AddHook("", "RtlSetProtectedPolicy", &Hook{
		Parameters: []string{"PolicyGuid", "PolicyValue", "OldPolicyValue"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "LdrControlFlowGuardEnforced", &Hook{
		Parameters: []string{""},
	})
	emu.AddHook("", "ApiSetQueryApiSetPresence", &Hook{
		Parameters: []string{"Namespace", "Present"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "CsrClientConnectToServer", &Hook{
		Parameters: []string{"ObjectDirectory", "ServerId", "ConnectionInfo", "ConnectionInfoSize", "ServerToServerCall"},
		//Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "KernelBaseGetGlobalData", &Hook{
		Parameters: []string{},
	})
	emu.AddHook("", "LdrDisableThreadCalloutsForDll", &Hook{
		Parameters: []string{"unknown"},
	})
	emu.AddHook("", "LdrQueryImageFileExecutionOptions", &Hook{
		Parameters: []string{"lpImageFile", "lpszOption", "dwType", "lpData", "cbData", "lpcbData"},
	})
	emu.AddHook("", "LdrQueryImageFileExecutionOptionsEx", &Hook{
		Parameters: []string{"lpImageFile", "lpszOption", "dwType", "lpData", "cbData", "lpcbData"},
	})
	emu.AddHook("", "LdrQueryImageFileKeyOption", &Hook{
		Parameters: []string{"hKey", "lpszOption", "dwType", "lpData", "cbData", "lpcbData"},
	})
	emu.AddHook("", "LdrSetDllManifestProber", &Hook{
		Parameters: []string{"Routine"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
	emu.AddHook("", "NtAllocateVirtualMemory", &Hook{
		Parameters: []string{"ProcessHandle", "BaseAddress", "ZeroBits", "RegionSize", "AllocationType", "Protect"},
		Fn:         allocateVirtualMemory,
	})
	emu.AddHook("", "ZwFreeVirtualMemory", &Hook{
		Parameters: []string{"ProcessHandle", "BaseAddress", "RegionSize", "FreeType"},
		Fn:         freeVirtualMemory,
	})
	// https://googleprojectzero.blogspot.com/2017/08/windows-exploitation-tricks-arbitrary.html
	emu.AddHook("", "NtGetNlsSectionPtr", &Hook{
		Parameters: []string{"NlsType", "CodePage", "ContextData", "SectionPointer", "SectionSize"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			// read NLS file
			data, err := ioutil.ReadFile(emu.Opts.Root + fmt.Sprintf("windows/system32/c_%d.nls", in.Args[1]))
			if err == nil {
				//allocate data to write NLS into user memory
				addr := emu.Heap.Malloc(uint64(len(data)))
				emu.Uc.MemWrite(addr, data)

				if emu.PtrSize == 4 {
					buf := make([]byte, 4)

					//write pointer value
					//ptr := emu.Malloc(emu.PtrSize)
					binary.LittleEndian.PutUint32(buf, uint32(addr))
					emu.Uc.MemWrite(in.Args[3], buf)

					//write address into argument pointer value
					//binary.LittleEndian.PutUint32(buf, uint32(addr))
					//emu.Uc.MemWrite(ptr, buf)

					// write size of buffer to SectionSize pointer
					binary.LittleEndian.PutUint32(buf, uint32(len(data)))
					emu.Uc.MemWrite(in.Args[4], buf)

				} else {
				}

				return SkipFunctionStdCall(true, 0x0)(emu, in)
			} else {
				return SkipFunctionStdCall(true, 0x1)(emu, in)
			}
		},
	})
	emu.AddHook("", "NtOpenKeyTransacted", &Hook{
		Parameters: []string{"KeyHandle", "DesiredAccess", "ObjectAttributes", "TransactionHandle"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(emu.PtrSize)
			buf := make([]byte, emu.PtrSize)
			if emu.PtrSize == 4 {
				binary.LittleEndian.PutUint32(buf, uint32(handle))
			} else {
				binary.LittleEndian.PutUint64(buf, handle)
			}
			emu.Uc.MemWrite(in.Args[0], buf)
			return SkipFunctionStdCall(true, 0x0)(emu, in)
		},
	})
	emu.AddHook("", "NtQueryInformationProcess", &Hook{Parameters: []string{}})
	emu.AddHook("", "NtQueryInformationThread", &Hook{Parameters: []string{"ThreadHandle", "ThreadInformationClass", "ThreadInformation", "ThreadInformationLength", "ReturnLength"}})
	emu.AddHook("", "NtSetInformationFile", &Hook{
		Parameters: []string{"FileHandle", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
	emu.AddHook("", "NtSetInformationThread", &Hook{Parameters: []string{"ThreadHandle", "threadInformationClass", "threadInformation", "threadInformationLength"}})
	emu.AddHook("", "NtUserMapVirtualKeyEx", &Hook{Parameters: []string{"keyCode", "transType", "keyboardld", "dwhkl"}})
	emu.AddHook("", "RtlAllocateHeap", &Hook{
		Parameters: []string{"HeapHandle", "Flags", "Size"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, emu.Heap.Malloc(in.Args[2]))(emu, in)
		},
		NoLog: true,
	})
	emu.AddHook("", "RtlReAllocateHeap", &Hook{
		Parameters: []string{"HeapHandle", "Flags", "MemoryPointer", "Size"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, emu.Heap.Malloc(in.Args[3]))(emu, in)
		},
		NoLog: true,
	})

	emu.AddHook("", "RtlSizeHeap", &Hook{
		Parameters: []string{"heap", "flags", "ptr"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			size := emu.Heap.Size(in.Args[2])
			if size != 0 {
				return SkipFunctionStdCall(true, size)(emu, in)

			}
			return SkipFunctionStdCall(true, 0xFFFFFFFF)(emu, in)
		},
	})
	emu.AddHook("", "RtlAcquirePebLock", &Hook{Parameters: []string{}})
	emu.AddHook("", "RtlAcquireSRWLockExclusive", &Hook{
		Parameters: []string{"SRWLock"},
	})
	emu.AddHook("", "RtlCharToInteger", &Hook{
		Parameters: []string{"String", "Base", "Value"},
	})
	emu.AddHook("", "RtlExitUserThread", &Hook{
		Parameters: []string{"dwExitCode"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			emu.Scheduler.ThreadEnded(emu.Scheduler.CurThreadId())
			return true
		},
	})
	emu.AddHook("", "RtlCreateHeap", &Hook{
		Parameters: []string{"Flags", "HeapBase", "ReserveSize", "CommitSize", "Lock", "Parameters"},
		Fn:         SkipFunctionStdCall(true, 0x123456),
	})
	emu.AddHook("", "RtlDeleteCriticalSection", &Hook{
		Parameters: []string{"lpCriticalSection"},
		Fn:         SkipFunctionStdCall(false, 0),
	})
	emu.AddHook("", "RtlComputeCrc32", &Hook{
		Parameters: []string{"dwInitial", "pData", "iLen"},
	})
	emu.AddHook("", "RtlDebugPrintTimes", &Hook{
		Parameters: []string{""},
	})
	emu.AddHook("", "RtlGetCurrentServiceSessionId", &Hook{
		Parameters: []string{},
	})
	emu.AddHook("", "RtlGetSuiteMask", &Hook{
		Parameters: []string{},
	})
	emu.AddHook("", "RtlImageNtHeader", &Hook{
		Parameters: []string{"ModuleAddress"},
	})
	emu.AddHook("", "RtlImageNtHeaderEx", &Hook{
		Parameters: []string{"Flags", "Base", "Size", "UNDOCUMENTED", "OutHeaders"},
		Fn:         imageNtHeaderEX,
	})
	emu.AddHook("", "RtlInitializeCriticalSectionAndSpinCount", &Hook{
		Parameters: []string{"lpCriticalSection", "dwSpinCount"},
	})
	emu.AddHook("", "RtlInitializeCriticalSection", &Hook{
		Parameters: []string{"lpCriticalSection"},
		NoLog:      true,
	})
	emu.AddHook("", "RtlInitializeCriticalSectionEx", &Hook{
		Parameters: []string{"lpCriticalSection", "dwSpinCount", "flags"},
		NoLog:      true,
	})
	emu.AddHook("", "RtlInitAnsiStringEx", &Hook{
		Parameters: []string{"unknown1", "unknown2"},
	})
	emu.AddHook("", "RtlInitUnicodeString", &Hook{
		Parameters: []string{"DestinationString", "SourceString"},
	})
	emu.AddHook("", "RtlInitUnicodeStringEx", &Hook{
		Parameters: []string{"DestinationString", "SourceString"},
	})
	emu.AddHook("", "RtlFreeHeap", &Hook{
		Parameters: []string{"HeapHandle", "Flags", "BaseAddress"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			emu.Heap.Free(in.Args[2])
			return SkipFunctionStdCall(true, 1)(emu, in)
		},
	})
	emu.AddHook("", "RtlNtStatusToDosError", &Hook{
		Parameters: []string{"Status"},
	})
	emu.AddHook("", "RtlInitializeNtUserPfn", &Hook{
		Parameters: []string{},
	})
	emu.AddHook("", "RtlEncodePointer", &Hook{
		Parameters: []string{"ptr"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, in.Args[0])(emu, in)
		},
	})
	emu.AddHook("", "RtlDecodePointer", &Hook{
		Parameters: []string{"ptr"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, in.Args[0])(emu, in)
		},
	})
	emu.AddHook("", "RtlNtStatusToDosErrorNoTeb", &Hook{
		Parameters: []string{"Status"},
	})
	emu.AddHook("", "RtlSetThreadPoolStartFunc", hRtlSetThreadPoolStartFunc)
	emu.AddHook("", "RtlRandomEx", &Hook{
		Parameters: []string{"Seed"},
	})
	emu.AddHook("", "RtlReleaseSRWLockExclusive", &Hook{
		Parameters: []string{"SRWLock"},
		//Fn:         SkipFunctionStdCall(false, 0x1),
	})
	emu.AddHook("", "RtlRunOnceComplete", &Hook{
		Parameters: []string{"RunOnce", "Flags", "Context"},
	})
	emu.AddHook("", "RtlRunOnceExecuteOnce", &Hook{
		Parameters: []string{"RunOnce", "InitFn", "Context", "Parameter"},
	})
	emu.AddHook("", "RtlQueryHeapInformation", &Hook{
		Parameters: []string{"HeapHandle", "HeapInformationClass", "HeapInformation", "HeapInformationLength", "ReturnLength"},
	})
	emu.AddHook("", "RtlSetLastWin32Error", &Hook{Parameters: []string{"err"}, NoLog: true})
	emu.AddHook("", "RtlSetUnhandledExceptionFilter", &Hook{
		Parameters: []string{"lpTopLevelExceptionFilter"},
	})
	emu.AddHook("", "RtlUnicodeStringToAnsiString", &Hook{
		Parameters: []string{"DestinationString", "SourceString", "AllocateDestinationString"},
	})
	emu.AddHook("", "RtlUnicodeToMultiByteSize", &Hook{
		Parameters: []string{"BytesInUnicodeString", "MultiByteString", "BytesInMultiByteString"},
	})
	emu.AddHook("", "WinSqmEventEnabled", hRtlSetThreadPoolStartFunc)
	emu.AddHook("", "WinSqmGetEscalationRuleStatus", hRtlSetThreadPoolStartFunc)
	emu.AddHook("", "ZwAllocateVirtualMemory", &Hook{
		Parameters: []string{"ProcessHandle", "BaseAddress", "ZeroBits", "RegionSize", "AllocationType", "Protect"},
		Fn:         allocateVirtualMemory,
	})
	emu.AddHook("", "ZwClose", &Hook{
		Parameters: []string{"Handle"},
	})

	emu.AddHook("", "ZwConnectPort", &Hook{
		Parameters: []string{"PortHandle", "PortName", "SecurityQos", "ClientView", "ServerView", "MaxMessageLength", "ConnectionInformation", "ConnectionInformationLength"},
	})
	emu.AddHook("", "ZwMapViewOfSection", &Hook{
		Parameters: []string{"SectionHandle", "ProcessHandle", "BaseAddress", "ZeroBits", "CommitSize", "SectionOffset", "ViewSize", "InheritDisposition", "AllocationType", "Win32Protect"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return zwMapViewOfSection(emu, in)(emu, in)
		},
	})
	emu.AddHook("", "ZwOpenKey", &Hook{
		Parameters: []string{"KeyHandle", "DesiredAccess", "ObjectAttributes"},
	})
	emu.AddHook("", "ZwQueryInformationProcess", &Hook{
		Parameters: []string{"ProcessHandle", "ProcessInformationClass", "ProcessInformation", "ProcessInformationLength", "ReturnLength"},
		Fn:         zwQueryInformationProcess,
	})
	emu.AddHook("", "ZwQuerySystemInformation", &Hook{
		Parameters: []string{"SystemInformationClass", "SystemInformation", "SystemInformationLength", "ReturnLength"},
		Fn:         zwQuerySystemInformation,
	})
	emu.AddHook("", "ZwQueryValueKey", &Hook{
		Parameters: []string{"KeyHandle", "ValueName", "KeyValueInformationClass", "KeyValueInformation", "Length", "ResultLength"},
	})
	emu.AddHook("", "ZwReadFile", &Hook{
		Parameters: []string{"FileHandle", "Event", "ApcRoutine", "ApcContext", "IoStatusBlock", "Buffer", "Length", "ByteOffset", "Key"},
	})
	emu.AddHook("", "ZwSetInformationFile", &Hook{
		Parameters: []string{"FileHandle", "IoStatusBlock", "FileInformation", "Length", "FileInformationClass"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
	emu.AddHook("", "RtlInitializeSListHead", &Hook{Parameters: []string{"ListHead"}})

	emu.AddHook("", "ZwWaitForAlertByThreadId", &Hook{
		Parameters: []string{"first", "second"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
}
