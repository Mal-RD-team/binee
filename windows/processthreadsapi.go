package windows

import "github.com/carbonblack/binee/util"

type ProcessInformation struct {
	Hprocess    uint32
	HThread     uint32
	DwProcessId uint32
	DwThreadId  uint32
}

func createProcess(emu *WinEmulator, in *Instruction) bool {
	stub := make(map[string]interface{})
	threadStub := make(map[string]interface{})
	wide := in.Hook.Name[len(in.Hook.Name)-1] == 'W'
	var applicationName, commandLine string
	if wide {
		applicationName = util.ReadWideChar(emu.Uc, in.Args[0], 0)
		commandLine = util.ReadWideChar(emu.Uc, in.Args[1], 0)
	} else {
		applicationName = util.ReadASCII(emu.Uc, in.Args[0], 0)
		commandLine = util.ReadASCII(emu.Uc, in.Args[1], 0)
	}
	if (applicationName+commandLine) == "" || in.Args[9] == 0 || in.Args[8] == 0 { // params are not right
		return SkipFunctionStdCall(true, 0)(emu, in)
	}
	stub["szExeFile"] = applicationName + commandLine
	stub["dwFlags"] = uint32(in.Args[5])
	stub["creatorProcessID"] = emu.ProcessManager.currentPid
	processInfo := &ProcessInformation{}
	emu.ProcessManager.startProcess(stub)
	//process := emu.ProcessManager.processMap[uint32(emu.ProcessManager.numberOfProcesses)-1]
	process := emu.ProcessManager.processList[uint32(emu.ProcessManager.numberOfProcesses)-1]
	procHandle := &Handle{
		Process: &process,
	}
	handleAddr := emu.Heap.Malloc(4)
	emu.Handles[handleAddr] = procHandle
	processInfo.Hprocess = uint32(handleAddr)
	processInfo.DwProcessId = process.the32ProcessID
	threadStub["dwCreationFlags"] = uint32(in.Args[5])
	threadStub["creatorProcessID"] = emu.ProcessManager.currentPid
	threadStub["ownerProcessID"] = process.the32ProcessID
	remoteThreadID := emu.ProcessManager.startRemoteThread(threadStub)
	remoteThread := emu.ProcessManager.remoteThreadMap[remoteThreadID]
	remoteThreadHandle := &Handle{
		Object: &remoteThread,
	}
	rThreadhandleAddr := emu.Heap.Malloc(4)
	emu.Handles[rThreadhandleAddr] = remoteThreadHandle
	processInfo.DwThreadId = remoteThreadID
	processInfo.HThread = uint32(rThreadhandleAddr)
	util.StructWrite(emu.Uc, in.Args[9], processInfo)

	return SkipFunctionStdCall(true, 1)(emu, in)
}

func ProcessthreadsapiHooks(emu *WinEmulator) {
	emu.AddHook("", "CreateProcessA", &Hook{
		Parameters: []string{"a:lpApplicationName", "a:lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"},
		Fn:         createProcess,
	})
	emu.AddHook("", "CreateProcessW", &Hook{
		Parameters: []string{"w:lpApplicationName", "w:lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"},
		Fn:         createProcess,
	})
	emu.AddHook("", "CreateProcessAsUserA", &Hook{
		Parameters: []string{"hToken", "a:lpApplicationName", "a:lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "CreateProcessAsUserW", &Hook{
		Parameters: []string{"hToken", "w:lpApplicationName", "w:lpCommandLine", "lpProcessAttributes", "lpThreadAttributes", "bInheritHandles", "dwCreationFlags", "lpEnvironment", "lpCurrentDirectory", "lpStartupInfo", "lpProcessInformation"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "GetCurrentProcess", &Hook{
		Parameters: []string{""},
		Fn:         SkipFunctionStdCall(true, FCT_SELF_PROCESS_ID),
	})
	emu.AddHook("", "OpenProcess", &Hook{
		Parameters: []string{"dwDesiredAccess", "bInheritHandle", "dwProcessId"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			procID := in.Args[2]
			if _, ok := emu.ProcessManager.processMap[uint32(procID)]; !ok {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			process := emu.ProcessManager.processMap[uint32(procID)]
			procHandle := &Handle{
				Process: &process,
			}
			handleAddr := emu.Heap.Malloc(4)
			emu.Handles[handleAddr] = procHandle
			return SkipFunctionStdCall(true, handleAddr)(emu, in)
		},
	})
	emu.AddHook("", "TerminateProcess", &Hook{
		Parameters: []string{"hProcess", "uExitCode"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			if in.Args[0] == 0xffffffff {
				return false
			}
			if _, ok := emu.Handles[in.Args[0]]; !ok {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			if emu.Handles[in.Args[0]].Process == nil {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			process := emu.Handles[in.Args[0]].Process
			success := emu.ProcessManager.terminateProcess(process.the32ProcessID)
			if success {
				return SkipFunctionStdCall(true, 0x1337)(emu, in)
			} else {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
		},
	})
	emu.AddHook("", "GetPriorityClass", &Hook{
		Parameters: []string{"Handle"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "SetPriorityClass", &Hook{
		Parameters: []string{"hProcess", "dwPriorityClass"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "SetProcessPriorityBoost", &Hook{
		Parameters: []string{"hProcess", "dwPriorityClass"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})
	emu.AddHook("", "CreateThread", &Hook{
		Parameters: []string{"lpThreadAttributes", "dwStackSize", "lpStartAddress", "lpParameter", "dwCreationFlags", "lpThreadId"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			stackSize := uint64(1 * 1024 * 1024)
			if in.Args[1] != 0x0 {
				stackSize = in.Args[1]
			}
			//stack should start at the top of the newly allocated space on the heap
			stackAddr := emu.Heap.Malloc(stackSize) + stackSize - 0x20
			threadEip := in.Args[2]

			//create new ThreadContext
			threadHandle := emu.Scheduler.NewThread(threadEip, stackAddr, in.Args[3], in.Args[4])

			// write thread ID back to pointer lpThreadId
			util.PutPointer(emu.Uc, emu.PtrSize, in.Args[5], uint64(threadHandle.Thread.ThreadId))

			return SkipFunctionStdCall(true, uint64(threadHandle.Thread.ThreadId))(emu, in)
		},
	})

	emu.AddHook("", "NtCreateThreadEx ", &Hook{
		/*
			typedef NTSTATUS(WINAPI* LPFN_NTCREATETHREADEX)(
				OUT PHANDLE ThreadHandle,
				IN ACCESS_MASK DesiredAccess,
				IN LPVOID ObjectAttributes,
				IN HANDLE ProcessHandle,
				IN LPTHREAD_START_ROUTINE ThreadProcedure,
				IN LPVOID ParameterData,
				IN BOOL CreateSuspended,
				IN SIZE_T StackZeroBits,
				IN SIZE_T SizeOfStackCommit,
				IN SIZE_T SizeOfStackReserve,
				OUT LPVOID BytesBuffer);
		*/
		Parameters: []string{"ThreadHandle", "DesiredAccess", "ObjectAttributes",
			"ProcessHandle", "ThreadProcedure", "ParameterData",
			"CreateSuspended", "StackZeroBits", "SizeOfStackCommit", "SizeOfStackReserve",
			"BytesBuffer"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			if int(in.Args[3]) != -1 { //remote thread created
				stub := make(map[string]interface{})
				currentProcId := emu.ProcessManager.currentPid
				hproc := &Handle{}
				hproc = emu.Handles[in.Args[3]]
				if hproc == nil {
					//ToDo Create dummy process
					return SkipFunctionStdCall(true, 0)(emu, in)
				}
				ownerProcessID := hproc.Process.the32ProcessID
				stackSize := uint32(1 * 1024 * 1024)
				if uint32(in.Args[8])+uint32(in.Args[9]) != 0x0 {
					stackSize = uint32(in.Args[8]) + uint32(in.Args[9])
				}
				lpParameter := uint32(in.Args[5])
				//stack should start at the top of the newly allocated space on the heap
				size := uint64(stackSize)
				stackAddress := emu.Heap.Malloc(size) + size - 0x20
				lpStartAddress := uint32(in.Args[4])
				dwCreationFlags := uint32(0)
				if in.Args[6] != 0 {
					dwCreationFlags = uint32(0x4)
				}
				stub["creatorProcessID"] = currentProcId
				stub["lpParameter"] = lpParameter
				stub["stackAddress"] = uint32(stackAddress)
				stub["stackSize"] = stackSize
				stub["lpStartAddress"] = lpStartAddress
				stub["ownerProcessID"] = ownerProcessID
				stub["dwCreationFlags"] = dwCreationFlags

				//create new ThreadContext
				remotethreadid := emu.ProcessManager.startRemoteThread(stub)
				if remotethreadid < 0xca7 {
					//Todo the dummy process
				}
				remoteThread := emu.ProcessManager.remoteThreadMap[remotethreadid]
				remoteThreadHandle := &Handle{
					Object: &remoteThread,
				}
				handleAddr := emu.Heap.Malloc(4)
				emu.Handles[handleAddr] = remoteThreadHandle
				// write thread ID back to pointer lpThreadId
				util.PutPointer(emu.Uc, 4, in.Args[0], handleAddr)
				//util.StructWrite(emu.Uc, in.Args[0], remoteThread.remoteThreadID)
				return SkipFunctionStdCall(true, 0x0)(emu, in)
			} else { //normal thread
				stackSize := uint32(1 * 1024 * 1024)
				if uint32(in.Args[8])+uint32(in.Args[9]) != 0x0 {
					stackSize = uint32(in.Args[8]) + uint32(in.Args[9])
				}
				//stack should start at the top of the newly allocated space on the heap
				size := uint64(stackSize)
				stackAddr := emu.Heap.Malloc(size) + size - 0x20
				//lpStartAddress := uint32(in.Args[4])
				threadEip := in.Args[4]
				lpParameter := in.Args[5]
				//create new ThreadContext

				threadHandle := emu.Scheduler.NewThread(threadEip, stackAddr, lpParameter, in.Args[6])
				util.StructWrite(emu.Uc, in.Args[0], threadHandle)

				return SkipFunctionStdCall(true, 0)(emu, in)
			}
		},
	})

	emu.AddHook("", "GetCurrentThread", &Hook{
		Parameters: []string{},
		Fn:         SkipFunctionStdCall(true, uint64(emu.Scheduler.CurThreadId())),
	})

	emu.AddHook("", "OpenProcessToken", &Hook{
		Parameters: []string{"ProcessHandle", "DesiredAccess", "TokenHandle"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "OpenThreadToken", &Hook{
		Parameters: []string{"ThreadHandle", "DesiredAccess", "OpenAsSelf", "TokenHandle"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			util.PutPointer(emu.Uc, emu.PtrSize, in.Args[3], uint64(emu.Scheduler.CurThreadId()))
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})
	emu.AddHook("", "TerminateThread", &Hook{
		Parameters: []string{"hThread", "dwExitCode"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			threadHandle := in.Args[0]
			handle := emu.Handles[threadHandle]
			if handle.Thread != nil {
				threadId := handle.Thread.ThreadId
				emu.Scheduler.DelThread(threadId)
				delete(emu.Handles, threadHandle)
				return SkipFunctionStdCall(true, 0x1337)(emu, in)
			}
			rthreadHandle := handle.Object.(*RemoteThread)
			if rthreadHandle != nil {
				threadId := rthreadHandle.remoteThreadID
				status := emu.ProcessManager.terminateRemoteThread(threadId)
				if status {
					emu.setLastError(0)
					delete(emu.Handles, threadHandle)
					return SkipFunctionStdCall(true, 1337)(emu, in)
				} else {
					emu.setLastError(0xFFFFFFFF)
					return SkipFunctionStdCall(true, 0)(emu, in)
				}
			}
			emu.setLastError(0xFFFFFFFF)
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})

	emu.AddHook("", "CreateRemoteThread", &Hook{
		Parameters: []string{"hProcess", "lpThreadAttributes", "dwStackSize", "lpParameter", "lpStartAddress", "dwCreationFlags", "lpThreadId"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			// checking the proc handle exists
			stub := make(map[string]interface{})
			currentProcId := emu.ProcessManager.currentPid
			hproc := &Handle{}
			hproc = emu.Handles[in.Args[0]]
			if hproc == nil {
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			ownerProcessID := hproc.Process.the32ProcessID
			stackSize := uint32(1 * 1024 * 1024)
			if in.Args[1] != 0x0 {
				stackSize = uint32(in.Args[1])
			}
			lpParameter := uint32(in.Args[3])
			//stack should start at the top of the newly allocated space on the heap
			size := uint64(stackSize)
			stackAddress := emu.Heap.Malloc(size) + size - 0x20
			lpStartAddress := uint32(in.Args[4])
			dwCreationFlags := uint32(in.Args[5])
			stub["creatorProcessID"] = currentProcId
			stub["lpParameter"] = lpParameter
			stub["lpParameter"] = lpParameter
			stub["stackAddress"] = uint32(stackAddress)
			stub["stackSize"] = stackSize
			stub["lpStartAddress"] = lpStartAddress
			stub["ownerProcessID"] = ownerProcessID
			stub["dwCreationFlags"] = dwCreationFlags

			//create new ThreadContext
			remotethreadid := emu.ProcessManager.startRemoteThread(stub)
			if remotethreadid < 0xca7 {
				//Todo the dummy process
			}
			remoteThread := emu.ProcessManager.remoteThreadMap[remotethreadid]
			remoteThreadHandle := &Handle{
				Object: &remoteThread,
			}
			handleAddr := emu.Heap.Malloc(4)
			emu.Handles[handleAddr] = remoteThreadHandle
			// write thread ID back to pointer lpThreadId
			//util.PutPointer(emu.Uc, 4, uint32(Args[6]), remoteThread.remoteThreadID)
			util.StructWrite(emu.Uc, in.Args[6], remoteThread.remoteThreadID)
			return SkipFunctionStdCall(true, handleAddr)(emu, in)
		},
	})

	emu.AddHook("", "ResumeThread", &Hook{
		Parameters: []string{"hThread"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			threadHandle := in.Args[0]
			handle := emu.Handles[threadHandle]
			if handle.Thread != nil {
				threadId := handle.Thread.ThreadId
				status := emu.Scheduler.ResumeThread(threadId)
				if status {
					emu.setLastError(0)
					return SkipFunctionStdCall(true, 0x1337)(emu, in)
				} else {
					emu.setLastError(0xFFFFFFFF)
					return SkipFunctionStdCall(true, 0)(emu, in)
				}
			}
			rthreadHandle := handle.Object.(*RemoteThread)
			if rthreadHandle != nil {
				threadId := rthreadHandle.remoteThreadID
				status := emu.ProcessManager.resumeRemoteThread(threadId)
				if status {
					emu.setLastError(0)
					return SkipFunctionStdCall(true, 1337)(emu, in)
				} else {
					emu.setLastError(0xFFFFFFFF)
					return SkipFunctionStdCall(true, 0)(emu, in)
				}
			}
			emu.setLastError(0xFFFFFFFF)
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})
	emu.AddHook("", "SuspendThread", &Hook{
		Parameters: []string{"hThread"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			threadHandle := in.Args[0]
			handle := emu.Handles[threadHandle]
			if handle.Thread != nil {
				threadId := handle.Thread.ThreadId
				status := emu.Scheduler.SuspendThread(threadId)
				if status {
					emu.setLastError(0)
					return SkipFunctionStdCall(true, 0x1337)(emu, in)
				} else {
					emu.setLastError(0xFFFFFFFF)
					return SkipFunctionStdCall(true, 0)(emu, in)
				}
			}
			rthreadHandle := handle.Object.(*RemoteThread)
			if rthreadHandle != nil {
				threadId := rthreadHandle.remoteThreadID
				status := emu.ProcessManager.suspendRemoteThread(threadId)
				if status {
					emu.setLastError(0)
					return SkipFunctionStdCall(true, 0x1337)(emu, in)
				} else {
					emu.setLastError(0xFFFFFFFF)
					return SkipFunctionStdCall(true, 0)(emu, in)
				}
			}
			emu.setLastError(0xFFFFFFFF)
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})
	emu.AddHook("", "SetThreadContext", &Hook{
		Parameters: []string{"hThread", "lpContext"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "QueueUserAPC", &Hook{
		Parameters: []string{"pfnAPC", "hThread", "dwData"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "NtQueueApcThread", &Hook{
		Parameters: []string{"threadHandle", "ApcRoutine", "ApcRoutineContxt", "ApcStatusBlock", "ApcReserved"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "ZwQueueApcThread", &Hook{
		Parameters: []string{"threadHandle", "ApcRoutine", "ApcRoutineContxt", "ApcStatusBlock", "ApcReserved"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "NtCreateProcessEx", &Hook{
		Parameters: []string{"ProcessHandle", "DesiredAccess", "OBJECT_ATTRIBUTES", "ParentProcess", "InheritObjectTable", "SectionHandle", "DebugPort", "ExceptionPort", "arg9"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "OpenThread", &Hook{
		Parameters: []string{"dwDesiredAccess", "bInheritHandle", "dwThreadId"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "GetProcessIdOfThread", &Hook{
		Parameters: []string{"Thread"},
		Fn:         SkipFunctionStdCall(true, 0x3),
	})

	emu.AddHook("", "GetThreadContext", &Hook{
		Parameters: []string{"hThread", "lpContext"},
		Fn:         SkipFunctionStdCall(true, 0),
	})

	emu.AddHook("", "SetThreadPriority", &Hook{
		Parameters: []string{"hThread", "dwPriorityClass"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "FlushInstructionCache", &Hook{
		Parameters: []string{"hProcess", "lpBaseAddress", "dwSize"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "ZwSuspendProcess", &Hook{
		Parameters: []string{"hProcess"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
	emu.AddHook("", "ZwResumeProcess", &Hook{
		Parameters: []string{"hProcess"},
		Fn:         SkipFunctionStdCall(true, 0),
	})

	//Threadpool

	emu.AddHook("", "CreateThreadpoolTimer", &Hook{
		Parameters: []string{"pfnti", "pv", "pcbe"},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

}
