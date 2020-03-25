package windows

import (
	"fmt"
	"github.com/carbonblack/binee/util"
	"github.com/unicorn-engine/unicorn/bindings/go/unicorn"
	"math"
	"strings"
)

func wsprintf(emu *WinEmulator, in *Instruction, wide bool) bool {
	var format string
	if wide {
		format = util.ReadWideChar(emu.Uc, in.Args[1], 0)
	} else {
		format = util.ReadASCII(emu.Uc, in.Args[1], 0)
	}
	format = strings.ReplaceAll(format, "%ws", "%S")
	parameters := util.ParseFormatter(format)
	var startAddr uint64
	//Get stack address
	if emu.PtrSize == 4 {
		startAddr, _ = emu.Uc.RegRead(unicorn.X86_REG_ESP)
	} else {
		startAddr, _ = emu.Uc.RegRead(unicorn.X86_REG_ESP)
	}
	//Jump 3 entries
	startAddr += 3 * emu.PtrSize
	in.VaArgsParse(startAddr, len(parameters))
	in.FmtToParameters(parameters)
	var values []interface{}
	for index, val := range in.Hook.Parameters[2:] {
		if val[0:2] == "a:" {
			values = append(values, util.ReadASCII(emu.Uc, in.Hook.Values[index+2].(uint64), 0))
		} else if val[0:2] == "w:" {
			values = append(values, util.ReadWideChar(emu.Uc, in.Hook.Values[index+2].(uint64), 0))
		} else {
			values = append(values, in.Hook.Values[index+2].(uint64))
		}
	}
	format = strings.ReplaceAll(format, "%S", "%s")
	formattedString := fmt.Sprintf(format, values...)
	var raw []byte
	if wide {
		raw = append(util.ASCIIToWinWChar(formattedString), 0, 0)
		maxLen := uint64(math.Min(float64(len(raw)), float64(1024)))
		raw = raw[:maxLen]
	} else {
		raw = append([]byte(formattedString), 0)
		maxLen := uint64(math.Min(float64(len(raw)), float64(1024)))
		raw = raw[:maxLen]
	}
	err := emu.Uc.MemWrite(in.Args[0], raw)
	len := uint64(math.Min(float64(len(raw)), float64(1024)))
	if err != nil {
		return SkipFunctionCdecl(true, len)(emu, in)
	}
	return SkipFunctionCdecl(true, 0)(emu, in)

}

func getClassName(emu *WinEmulator, in *Instruction, wide bool) bool {
	classname := "Progman"
	length := uint64(len(classname))
	destination := in.Args[1]
	maxCount := in.Args[2]
	if length >= maxCount {
		length = maxCount - 1
	}
	classname = classname[0:length]
	if wide {
		raw := util.ASCIIToWinWChar(classname)
		emu.Uc.MemWrite(destination, raw)
	} else {
		raw := []byte(classname)
		emu.Uc.MemWrite(destination, raw)
	}
	return SkipFunctionStdCall(true, length)(emu, in)
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
			return wsprintf(emu, in, false)
		},
	})
	emu.AddHook("", "wsprintfW", &Hook{
		Parameters: []string{"lpwstr", "w:lpcwstr"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return wsprintf(emu, in, true)
		},
	})
	emu.AddHook("", "EnableMenuItem", &Hook{
		Parameters: []string{"hMenu", "uIDEnableItem", "uEnable"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0)(emu, in)
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

	emu.AddHook("", "wvsprintfW", &Hook{
		Parameters: []string{"lpwstr", "w:lpcwstr", "arglist"},
	})
	emu.AddHook("", "GetShellWindow", &Hook{
		Parameters: []string{},
		Fn:         SkipFunctionStdCall(true, 0x1337),
	})

	emu.AddHook("", "GetClassNameA", &Hook{
		Parameters: []string{"hWnd", "lpClassName", "nMaxCount"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return getClassName(emu, in, false)
		},
	})
	emu.AddHook("", "GetClassNameW", &Hook{
		Parameters: []string{"hWnd", "lpClassName", "nMaxCount"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return getClassName(emu, in, true)
		},
	})
}
