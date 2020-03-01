package windows

func MprHook(emu *WinEmulator) {
	//This might be implemented later with a manager just like a process manager, but I don't know yet if its applicable.
	emu.AddHook("", "WNetOpenEnumA", &Hook{
		Parameters: []string{"dwScope", "dwType", "dwUsage", "a:lpNetResource", "lphEnum"},
		Fn:         SkipFunctionStdCall(true, 0x4c6), //ERROR NO INTERNET
	})
}
