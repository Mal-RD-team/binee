package windows

func WlanapiHook(emu *WinEmulator) {
	//DWORD WlanScan(
	//  HANDLE               hClientHandle,
	//  const GUID           *pInterfaceGuid,
	//  const PDOT11_SSID    pDot11Ssid,
	//  const PWLAN_RAW_DATA pIeData,
	//  PVOID                pReserved
	//);
	emu.AddHook("", "WlanScan", &Hook{
		Parameters: []string{"hClientHandle", "pInterfaceGuid", "pDot11Ssid", "pIeData", "pReserved"},
		Fn:         SkipFunctionStdCall(true, ERROR_SUCCESS),
	})
	//BOOL CreateWellKnownSid(
	//  WELL_KNOWN_SID_TYPE WellKnownSidType,
	//  PSID                DomainSid,
	//  PSID                pSid,
	//  DWORD               *cbSid
	//);
	emu.AddHook("", "CreateWellKnownSid", &Hook{
		Parameters: []string{"WellKnownSidType", "pSid", "*cbSid"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	//DWORD WlanOpenHandle(
	//	DWORD   dwClientVersion,
	//	PVOID   pReserved,
	//	PDWORD  pdwNegotiatedVersion,
	//	PHANDLE phClientHandle
	//);
	emu.AddHook("", "WlanOpenHandle", &Hook{
		Parameters: []string{"dwClientVersion", "pReserved", "pdwNegotiateVersion", "phClientHandle"},
		Fn:         SkipFunctionStdCall(true, ERROR_SUCCESS),
	})

	emu.AddHook("", "ConvertSidToStringSidA", &Hook{
		Parameters: []string{"sid", "stringSid"},
		Fn:         SkipFunctionStdCall(true, ERROR_SUCCESS),
	})
	//NET_API_STATUS NET_API_FUNCTION NetUnjoinDomain(
	//  LPCWSTR lpServer,
	//  LPCWSTR lpAccount,
	//  LPCWSTR lpPassword,
	//  DWORD   fUnjoinOptions
	//);
	emu.AddHook("", "NetUnjoinDomain", &Hook{
		Parameters: []string{"a:lpServer", "a:lpAccount", "a:lpPassword", "fUnjoinOptions"},
		Fn:         SkipFunctionStdCall(true, ERROR_SUCCESS),
	})
}
