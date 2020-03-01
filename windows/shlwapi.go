package windows

func ShwlapiHooks(emu *WinEmulator) {
	//LPCSTR PathFindFileNameA(
	//  LPCSTR pszPath
	//);
	emu.AddHook("", "PathFindFileNameA", &Hook{
		Parameters: []string{"a:pszPath"},
	})
	emu.AddHook("", "PathFindFileNameW", &Hook{
		Parameters: []string{"w:pszPath"},
	})
	emu.AddHook("", "PathFindExtensionA", &Hook{
		Parameters: []string{"a:pszPath"},
	})
	emu.AddHook("", "PathFindExtensionW", &Hook{
		Parameters: []string{"w:pszPath"},
	})
}
