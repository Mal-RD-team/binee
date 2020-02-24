package windows

import (
	"github.com/carbonblack/binee/util"
	"github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

func wsprintf(emu *WinEmulator, in *Instruction, wide bool) {
	var format string
	if wide {
		format = util.ReadWideChar(emu.Uc, in.Args[1], 0)
	} else {
		format = util.ReadASCII(emu.Uc, in.Args[1], 0)
	}
	parameters := util.ParseFormatter(format)
	var startAddr uint64
	//Get stack address
	if emu.PtrSize == 4 {
		startAddr, _ = emu.Uc.RegRead(unicorn.X86_REG_ESP)
	} else {
		startAddr, _ = emu.Uc.RegRead(unicorn.X86_REG_ESP)
	}
	//Jump 2 entries
	startAddr += 3 * emu.PtrSize
	in.VaArgsParse(startAddr, len(parameters))
	in.FmtToParameters(parameters)
}
func User32Hooks(emu *WinEmulator) {
	emu.AddHook("", "GetWindowRect", &Hook{Parameters: []string{"hWnd", "lpRect"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "CreateDialogParamA", &Hook{Parameters: []string{"hInstance", "a:lpTemplateName", "hWndParent", "lpDialogFunc", "dwInitParam"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "MapWindowPoints", &Hook{Parameters: []string{"hWndFrom", "hWndTo", "lpPoints", "cPoints"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "NtUserGetThreadState", &Hook{
		Parameters: []string{"Routine"},
	})
	emu.AddHook("", "ShowWindow", &Hook{Parameters: []string{"hWnd", "nCmdShow"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "SendMessageA", &Hook{Parameters: []string{"hWnd", "Msg", "wParam", "lParam"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "SetCursorPos", &Hook{Parameters: []string{"X", "Y"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "SetTimer", &Hook{Parameters: []string{"hWnd", "nIDEvent", "uElapse", "lpTimerFunc"}, Fn: SkipFunctionStdCall(true, 0x1)})
	emu.AddHook("", "wsprintfA", &Hook{
		Parameters: []string{"lpstr", "a:lpcstr"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			wsprintf(emu, in, false)
			return true
		},
	})
	emu.AddHook("", "wsprintfW", &Hook{
		Parameters: []string{"lpwstr", "w:lpcwstr"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			wsprintf(emu, in, true)
			return true
		},
	})

	emu.AddHook("", "LoadBitmapA", &Hook{
		Parameters: []string{"hInstance", "a:lpBitmapName"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "DialogBoxParamA", &Hook{
		Parameters: []string{"hInstance", "a:lpTemplateName", "hWndParent", "lpDialogFunc", "dwInitParam"},
		Fn:         SkipFunctionStdCall(true, 1),
	})

	emu.AddHook("", "wvsprintfA", &Hook{
		Parameters: []string{"lpstr", "a:lpcstr", "arglist"},
	})

	//int wvsprintfW(
	//  LPWSTR  ,
	//  LPCWSTR ,
	//  va_list arglist
	//);
	emu.AddHook("", "wvsprintfW", &Hook{
		Parameters: []string{"lpwstr", "w:lpcwstr", "arglist"},
	})

}
