package windows

func internetOpen(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	//This should be implemented to return a handle to be used.
	return SkipFunctionStdCall(true, 0xbeef)
}
func internetConnect(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	//This should be implemented as we want
	return SkipFunctionStdCall(true, 0xdead)
}
func httpOpenRequest(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	//This should be implemented as we want
	return SkipFunctionStdCall(true, 0xdeb0)
}
func httpAddRequestHeaders(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	//This should be implemented as we want
	return SkipFunctionStdCall(true, 1)
}
func httpSendRequest(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	//This should be implemented as we want
	return SkipFunctionStdCall(true, 1)
}

func WininetHooks(emu *WinEmulator) {

	emu.AddHook("", "InternetOpenA", &Hook{
		Parameters: []string{"a:lpszAgent", "dwAccessType", "a:lpszProxy", "a:lpszProxyBypass", "dwFlags"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return internetOpen(emu, in, false)(emu, in)
		},
	})
	emu.AddHook("", "InternetOpenW", &Hook{
		Parameters: []string{"w:lpszAgent", "dwAccessType", "w:lpszProxy", "w:lpszProxyBypass", "dwFlags"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return internetOpen(emu, in, true)(emu, in)
		},
	})
	emu.AddHook("", "InternetCloseHandle", &Hook{
		Parameters: []string{"hInternet"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "InternetConnectA", &Hook{
		Parameters: []string{"hInternet", "a:ServerName", "nServerPort", "a:Username", "a:Password", "dwService", "dwFlags", "dwContext"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return internetConnect(emu, in, false)(emu, in)
		},
	})
	emu.AddHook("", "InternetConnectW", &Hook{
		Parameters: []string{"hInternet", "w:ServerName", "nServerPort", "w:Username", "w:Password", "dwService", "dwFlags", "dwContext"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return internetConnect(emu, in, true)(emu, in)
		},
	})

	emu.AddHook("", "HttpOpenRequestA", &Hook{
		Parameters: []string{"hConnect", "a:Verb", "a:ObjectName", "a:Version", "a:Referrer", "lpAcceptTypes", "dwFlags", "dwContext"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return httpOpenRequest(emu, in, false)(emu, in)
		},
	})
	emu.AddHook("", "HttpOpenRequestW", &Hook{
		Parameters: []string{"hConnect", "w:Verb", "w:ObjectName", "w:Version", "w:Referrer", "lpAcceptTypes", "dwFlags", "dwContext"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return httpOpenRequest(emu, in, true)(emu, in)
		},
	})

	emu.AddHook("", "HttpAddRequestHeadersA", &Hook{
		Parameters: []string{"hRequest", "a:Headers", "dwHeadersLength", "dwModifiers"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return httpAddRequestHeaders(emu, in, true)(emu, in)
		},
	})
	emu.AddHook("", "HttpAddRequestHeadersW", &Hook{
		Parameters: []string{"hRequest", "w:Headers", "dwHeadersLength", "dwModifiers"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return httpAddRequestHeaders(emu, in, true)(emu, in)
		},
	})
	emu.AddHook("", "HttpSendRequestA", &Hook{
		Parameters: []string{"hRequest", "a:Headers", "dwHeadersLength", "Optional", "OptionalLength"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return httpSendRequest(emu, in, true)(emu, in)
		},
	})
	emu.AddHook("", "HttpSendRequestW", &Hook{
		Parameters: []string{"hRequest", "w:Headers", "dwHeadersLength", "Optional", "OptionalLength"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return httpSendRequest(emu, in, true)(emu, in)
		},
	})
	//BOOLAPI InternetReadFile(
	//  HINTERNET hFile,
	//  LPVOID    lpBuffer,
	//  DWORD     dwNumberOfBytesToRead,
	//  LPDWORD   lpdwNumberOfBytesRead
	//);
	emu.AddHook("", "InternetReadFile", &Hook{
		Parameters: []string{"hFile", "lpBuffer", "dwNumberOfBytesToRead", "lpdwNumberOfBytesRead"},
		Fn:         SkipFunctionStdCall(true, 0),
	})
}
