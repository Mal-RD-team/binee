package windows

func SyncapiHooks(emu *WinEmulator) {
	emu.AddHook("", "AcquireSRWLockExclusive", &Hook{
		Parameters: []string{"SRWLock"},
		Fn:         SkipFunctionStdCall(false, 0x0),
	})
	emu.AddHook("", "CreateEventA", &Hook{
		Parameters: []string{"lpEventAttributes", "bManualReset", "bInitialState", "a:lpName"},
		Fn:         SkipFunctionStdCall(false, 0x1),
	})
	emu.AddHook("", "CreateEventW", &Hook{
		Parameters: []string{"lpEventAttributes", "bManualReset", "bInitialState", "w:lpName"},
		Fn:         SkipFunctionStdCall(false, 0x1),
	})
	emu.AddHook("", "ResetEvent", &Hook{
		Parameters: []string{"hEvent"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "SetEvent", &Hook{
		Parameters: []string{"hEvent"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {

			if _, ok := emu.Handles[in.Args[0]]; !ok {
				emu.setLastError(ERROR_INVALID_HANDLE)
				return SkipFunctionStdCall(true, 0)(emu, in)
			}
			return SkipFunctionStdCall(true, 1)(emu, in)
		},
	})
	emu.AddHook("", "CreateMutexA", &Hook{
		Parameters: []string{"lpMutexAttributes", "bInitialOwner", "a:lpName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(emu.PtrSize)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "CreateMutexW", &Hook{
		Parameters: []string{"lpMutexAttributes", "bInitialOwner", "w:lpName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(emu.PtrSize)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "OpenMutexA", &Hook{
		Parameters: []string{"lpMutexAttributes", "bInitialOwner", "a:lpName"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
	emu.AddHook("", "OpenMutexW", &Hook{
		Parameters: []string{"lpMutexAttributes", "bInitialOwner", "w:lpName"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
	emu.AddHook("", "ReleaseSRWLockExclusive", &Hook{
		Parameters: []string{"SRWLock"},
		Fn:         SkipFunctionStdCall(false, 0x0),
	})
}
