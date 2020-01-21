package windows

func Internal(emu *WinEmulator) {
	//int __getmainargs(
	//    int * _Argc,
	//   char *** _Argv,
	//   char *** _Env,
	//   int _DoWildCard,
	//_startupinfo * _StartInfo);
	//
	//int __wgetmainargs (
	//   int *_Argc,
	//   wchar_t ***_Argv,
	//   wchar_t ***_Env,
	//   int _DoWildCard,
	//   _startupinfo * _StartInfo)
	emu.AddHook("", "__getmainargs", &Hook{
		Parameters: []string{"_Argc", "_Argv", "_Env", "_DoWildCard", "_StartInfo"},
		Fn:         SkipFunctionCdecl(true, 0),
	})
	emu.AddHook("", "__wgetmainargs", &Hook{
		Parameters: []string{"_Argc", "_Argv", "_Env", "_DoWildCard", "_StartInfo"},
		Fn:         SkipFunctionCdecl(true, 0),
	})
}
