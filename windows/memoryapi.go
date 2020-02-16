package windows

func virtualAlloc(emu *WinEmulator, in *Instruction) bool {
	baseAddr := in.Args[0]
	size := in.Args[1]
	addr, _ := emu.Heap.MMap(baseAddr, size)
	return SkipFunctionStdCall(true, addr)(emu, in)
}
func MemoryApiHooks(emu *WinEmulator) {
	emu.AddHook("", "VirtualAlloc", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "flAllocationType", "flProtect"},
		Fn:         virtualAlloc,
	})
	emu.AddHook("", "VirtualFree", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "dwFreeType"},
	})
	emu.AddHook("", "VirtualAllocEx", &Hook{
		Parameters: []string{"hProcess", "lpAddress", "dwSize", "flAllocationType", "flProtect"},
	})
	emu.AddHook("", "VirtualProtect", &Hook{
		Parameters: []string{"lpAddress", "dwSize", "flNewProtect", "lpflOldProtect"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
}
