package windows

func CryptHooks(emu *WinEmulator) {
	emu.AddHook("", "CryptAcquireContextA", &Hook{
		Parameters: []string{"phProv", "a:szContainer", "a:szProvider", "dwProvType", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptAcquireContextW", &Hook{
		Parameters: []string{"phProv", "w:szContainer", "w:szProvider", "dwProvType", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "CryptGenKey", &Hook{
		Parameters: []string{"hProv", "Algid", "dwFlags", "phKey"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptExportKey", &Hook{
		Parameters: []string{"hKey", "hExpKey", "dwBlobType", "dwFlags", "pbData", "pdwDataLen"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptDestroyKey", &Hook{
		Parameters: []string{"hKey"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptReleaseContext", &Hook{
		Parameters: []string{"hProv", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptGenKey", &Hook{
		Parameters: []string{"hProv", "Algid", "dwFlags", "phKey"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CryptGenRandom", &Hook{
		Parameters: []string{"hProve", "dwLen", "pbBuffer"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	//BOOL CryptBinaryToStringA(
	//  const BYTE *pbBinary,
	//  DWORD      cbBinary,
	//  DWORD      dwFlags,
	//  LPSTR      pszString,
	//  DWORD      *pcchString
	//);
	emu.AddHook("", "CryptBinaryToStringA", &Hook{
		Parameters: []string{"pbBinary", "cbBinary", "dwFlags", "pszString", "pcchString"},
		Fn:         SkipFunctionStdCall(true, 0),
	})

}
