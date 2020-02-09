package windows

import (
	"encoding/binary"
	"fmt"
	"github.com/carbonblack/binee/pefile"
)

//nt LoadStringA(
//  HINSTANCE hInstance,
//  UINT      uID,
//  LPSTR     lpBuffer,
//  int       cchBufferMax
//);
func loadString(emu *WinEmulator, in *Instruction, wide bool) func(emu *WinEmulator, in *Instruction) bool {
	if in.Args[0] == emu.MemRegions.ImageAddress {
		resourceID := uint32(((in.Args[1] & 0xFFFF) >> 4) + 1)
		typeID := uint32(6) //An enum should be added
		dataEntry := pefile.FindResource(emu.ResourcesRoot, resourceID, typeID)
		stringNum := in.Args[1] & 0x000f
		if dataEntry == nil {
			return SkipFunctionStdCall(true, 0)
		}
		bytes, _ := emu.Uc.MemRead(uint64(dataEntry.OffsetToData)+emu.MemRegions.ImageAddress, uint64(dataEntry.Size))
		index := uint64(0)
		//The weird operation to get the offset
		for i := uint64(0); i < stringNum; i++ {
			index += (uint64(binary.LittleEndian.Uint16(bytes[index:index+2])) + 1) * 2
		}
		offset := uint64(dataEntry.OffsetToData) + emu.MemRegions.ImageAddress + index //stringNum is multiplied by 2 because its wide chars.

		if in.Args[3] == 0 {
			addr := make([]byte, 4)
			//TODO Enums should be added to represent size of data types.
			binary.LittleEndian.PutUint32(addr, uint32(offset+2))
			emu.Uc.MemWrite(in.Args[2], addr)

		}
		bytes, ok := emu.Uc.MemRead(offset, uint64(2))
		length := uint64(binary.LittleEndian.Uint16(bytes))
		if in.Args[3] > length {
			if ok == nil {
				bytes, ok = emu.Uc.MemRead(offset+2, length*2) //Multiplied by 2 because its a unicode string.
				if ok == nil {
					if !wide {
						actualString := pefile.WideStringToString(bytes, int(length*2))
						fmt.Println(actualString)
						emu.Uc.MemWrite(in.Args[2], []byte(actualString))
						emu.Uc.MemWrite(in.Args[2]+length, []byte{0}) //Write null byte
					} else {
						emu.Uc.MemWrite(in.Args[2], bytes)
						emu.Uc.MemWrite(in.Args[2]+(2*length), []byte{0}) //Write null byte
					}
					return SkipFunctionStdCall(true, length)
				}
			}

		} else {
			bytes, ok := emu.Uc.MemRead(offset, in.Args[3])
			if ok != nil {
				emu.Uc.MemWrite(in.Args[2], bytes)
				return SkipFunctionStdCall(true, in.Args[3])
			}
		}
	} else {

		//This should be handled too
		//Loading for another module

	}
	return SkipFunctionStdCall(true, 0)
}
func WinuserHooks(emu *WinEmulator) {

	//LPSTR CharNextA(
	//	LPCSTR lpsz
	//);
	emu.AddHook("", "CharNextA", &Hook{
		Parameters: []string{"a:lpsz"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			lpsz := in.Args[0]
			buffer, _ := emu.Uc.MemRead(lpsz, 1)
			if buffer[0] == 0 {
				return SkipFunctionStdCall(true, lpsz)(emu, in)
			}
			return SkipFunctionStdCall(true, lpsz+1)(emu, in)
		},
	})
	//Currently only handling single byte characters
	emu.AddHook("", "CharPrevA", &Hook{
		Parameters: []string{"a:lpszStart", "a:lpszCurrent"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			lpszStart := in.Args[0]
			lpszCurrent := in.Args[1]
			if lpszStart == lpszCurrent {
				return SkipFunctionStdCall(true, lpszStart)(emu, in)
			} else {
				return SkipFunctionStdCall(true, lpszCurrent-1)(emu, in)
			}
		},
	})
	emu.AddHook("", "DestroyWindow", &Hook{
		Parameters: []string{"hWnd"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "DrawEdge", &Hook{
		Parameters: []string{"hdc", "qrc", "edge", "grfFlags"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "GetKeyboardType", &Hook{
		Parameters: []string{"nTypeFlag"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			switch in.Args[0] {
			case 0:
				return SkipFunctionStdCall(true, uint64(emu.Opts.KeyboardType))(emu, in)
			case 1:
				return SkipFunctionStdCall(true, uint64(emu.Opts.KeyboardSubType))(emu, in)
			case 2:
				return SkipFunctionStdCall(true, uint64(emu.Opts.KeyboardFuncKeys))(emu, in)
			}
			return SkipFunctionStdCall(true, 0)(emu, in)
		},
	})
	emu.AddHook("", "GetSystemMetrics", &Hook{
		Parameters: []string{"nIndex"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "LoadAcceleratorsA", &Hook{
		Parameters: []string{"hInstance", "a:lpTableName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(emu.PtrSize)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadAcceleratorsW", &Hook{
		Parameters: []string{"hInstance", "w:lpTableName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(emu.PtrSize)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadCursorA", &Hook{
		Parameters: []string{"hInstance", "a:lpCursorName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(32 * 4)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadCursorW", &Hook{
		Parameters: []string{"hInstance", "w:lpCursorName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(32 * 4)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadIconA", &Hook{
		Parameters: []string{"hInstance", "a:lpIconName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(32 * 4)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadIconW", &Hook{
		Parameters: []string{"hInstance", "w:lpIconName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Heap.Malloc(32 * 4)
			return SkipFunctionStdCall(true, handle)(emu, in)
		},
	})
	emu.AddHook("", "LoadStringA", &Hook{
		Parameters: []string{"hInstance", "uID", "lpBuffer", "cchBufferMax"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return loadString(emu, in, false)(emu, in)
		},
	})
	emu.AddHook("", "LoadStringW", &Hook{
		Parameters: []string{"hInstance", "uID", "lpBuffer", "cchBufferMax"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			return loadString(emu, in, true)(emu, in)
		},
	})
	emu.AddHook("", "MapVirtualKeyW", &Hook{
		Parameters: []string{"uCode", "uMapType"},
	})
	emu.AddHook("", "MessageBoxA", &Hook{
		Parameters: []string{"hWnd", "a:lpText", "a:lpCaption", "uType"},
		Fn:         SkipFunctionStdCall(true, 11),
	})
	emu.AddHook("", "MessageBoxIndirectA", &Hook{
		Parameters: []string{"lpmbp"},
		Fn:         SkipFunctionStdCall(true, 11),
	})
	emu.AddHook("", "PeekMessageA", &Hook{
		Parameters: []string{"lpMsg", "hWnd", "wMsgFilterMin", "wMsgFilterMax", "wRemoveMsg"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
	emu.AddHook("", "RegisterClassA", &Hook{
		Parameters: []string{"lpWndClass"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "RegisterClipboardFormatA", &Hook{
		Parameters: []string{"a:lpszFormat"},
		Fn:         SkipFunctionStdCall(true, 0xC000),
	})
	emu.AddHook("", "RegisterClipboardFormatW", &Hook{
		Parameters: []string{"w:lpszFormat"},
		Fn:         SkipFunctionStdCall(true, 0xC000),
	})
	emu.AddHook("", "RegisterWindowMessageA", &Hook{
		Parameters: []string{"a:lpString"},
		Fn:         SkipFunctionStdCall(true, 0xC001),
	})
	emu.AddHook("", "GetDesktopWindow", &Hook{
		Parameters: []string{},
		Fn:         SkipFunctionStdCall(true, 0xC001),
	})
	emu.AddHook("", "RegisterWindowMessageW", &Hook{
		Parameters: []string{"w:lpString"},
		Fn:         SkipFunctionStdCall(true, 0xC001),
	})
	emu.AddHook("", "MsgWaitForMultipleObjects", &Hook{
		Parameters: []string{"nCount", "pHandles", "fWaitAll", "dwMilliseconds", "dwWakeMask"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})

}
