package windows

//RPC_STATUS RpcStringBindingCompose(
//RPC_CSTR ObjUuid,
//RPC_CSTR ProtSeq,
//RPC_CSTR NetworkAddr,
//RPC_CSTR Endpoint,
//RPC_CSTR Options,
//RPC_CSTR *StringBinding
//);
func RpcrtHooks(emu *WinEmulator) {

	emu.AddHook("", "RpcStringBindingComposeA", &Hook{
		Parameters: []string{"a:ObjUuid", "a:ProtSeq", "a:NetworkAddr", "a:Endpoint", "a:Options", "StringBinding"},
		//Fn:SkipFunctionStdCall(true,ERROR_SUCCESS),
	})
	emu.AddHook("", "RpcStringBindingComposeW", &Hook{
		Parameters: []string{"w:ObjUuid", "w:ProtSeq", "w:NetworkAddr", "w:Endpoint", "w:Options", "StringBinding"},
		//Fn:SkipFunctionStdCall(true,ERROR_SUCCESS),
	})
}
