package windows

import (
	"encoding/binary"
	"strings"

	"github.com/carbonblack/binee/util"
)

//import "fmt"
func createDirectory(emu *WinEmulator, in *Instruction, wide bool) func(*WinEmulator, *Instruction) bool {
	stringAddress := in.Args[0]
	var path string
	if wide {
		path = util.ReadWideChar(emu.Uc, stringAddress, 0)
	} else {
		path = util.ReadASCII(emu.Uc, stringAddress, 0)
	}
	//its an absolute path we have to check if the drive exists.
	//Some malwares add weird directory to check if its being emulated.
	if strings.Contains(path, ":\\") {
		drive := path[0]
		allowed := "ABCDEF"
		if !strings.Contains(allowed, string(drive)) {
			return SkipFunctionStdCall(true, 0)
		}

	}

	return SkipFunctionStdCall(true, 0x1)
}

func FileapiHooks(emu *WinEmulator) {

	emu.AddHook("", "MoveFileExA", &Hook{
		Parameters: []string{"a:lpExistingFileName", "a:lpNewFileName", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "MoveFileExW", &Hook{
		Parameters: []string{"a:lpExistingFileName", "a:lpNewFileName", "dwFlags"},
		Fn:         SkipFunctionStdCall(true, 1),
	})
	emu.AddHook("", "CreateDirectoryA", &Hook{
		Parameters: []string{"a:lpPathName", "lpSecurityAttributes"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return createDirectory(emu, in, false)(emu, in)
		},
	})
	emu.AddHook("", "CreateDirectoryW", &Hook{
		Parameters: []string{"w:lpPathName", "lpSecurityAttributes"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return createDirectory(emu, in, true)(emu, in)
		},
	})
	emu.AddHook("", "DeleteFileA", &Hook{
		Parameters: []string{"a:lpFileName"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "DeleteFileW", &Hook{
		Parameters: []string{"a:lpFileName"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "FindClose", &Hook{
		Parameters: []string{"hFindFile"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "FindFirstFileA", &Hook{
		Parameters: []string{"a:lpFileName", "lpFindFileData"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})

	emu.AddHook("", "FindNextFileA", &Hook{
		Parameters: []string{"hFindFile", "lpFindFileData"},
		Fn:         SkipFunctionStdCall(true, 0x0),
	})
	emu.AddHook("", "GetLogicalDrives", &Hook{
		Parameters: []string{},
		//The return value is bitmask representing the currently available disk drives.
		//We will assume we have A,B,C,D,E,F meaning 0x0000003f
		//Where 63 : 111111
		Fn: SkipFunctionStdCall(true, 0x3f),
	})

	emu.AddHook("", "FlushFileBuffers", &Hook{
		Parameters: []string{"hFile"},
		Fn:         SkipFunctionStdCall(true, 0x1),
	})
	emu.AddHook("", "GetShortPathNameA", &Hook{
		Parameters: []string{"a:lpszLongPath", "a:lpszShortPath", "cchBuffer"},
		Fn:         SkipFunctionStdCall(true, 0x10),
	})
	emu.AddHook("", "GetFileAttributesA", &Hook{
		Parameters: []string{"a:lpFileName"},
		Fn:         SkipFunctionStdCall(true, 0x80),
	})
	emu.AddHook("", "GetFileAttributesW", &Hook{
		Parameters: []string{"w:lpFileName"},
		Fn:         SkipFunctionStdCall(true, 0x80),
	})
	emu.AddHook("", "GetFileSize", &Hook{
		Parameters: []string{"hFile", "lpFileSizeHigh"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Handles[in.Args[0]]
			if handle != nil {
				return SkipFunctionStdCall(true, uint64(handle.Info.Size()))(emu, in)
			}
			return SkipFunctionStdCall(true, 0x0)(emu, in)
		},
	})
	emu.AddHook("", "GetFullPathNameA", &Hook{
		Parameters: []string{"a:lpFileName", "nBufferLength", "lpBuffer", "lpFilePart"},
		Fn:         SkipFunctionStdCall(true, 0x80),
	})
	emu.AddHook("", "GetFullPathNameW", &Hook{
		Parameters: []string{"w:lpFileName", "nBufferLength", "lpBuffer", "lpFilePart"},
		Fn:         SkipFunctionStdCall(true, 0x80),
	})

	emu.AddHook("", "GetTempFileNameA", &Hook{
		Parameters: []string{"a:lpPathName", "a:lpPrefixString", "uUnique", "lpTempFileName"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			s := []byte(util.RandomName(8))
			emu.Uc.MemWrite(in.Args[3], s)
			return SkipFunctionStdCall(true, uint64(len(s)))(emu, in)
		},
	})
	emu.AddHook("", "GetTempPathA", &Hook{
		Parameters: []string{"nBufferLength", "lpBuffer"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			dir := append([]byte("c:\\temp"), 0)
			emu.Uc.MemWrite(in.Args[1], dir)
			return SkipFunctionStdCall(true, uint64(len(dir)))(emu, in)
		},
	})
	emu.AddHook("", "GetTempPathW", &Hook{
		Parameters: []string{"nBufferLength", "lpBuffer"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			dir := append(util.ASCIIToWinWChar("c:\\temp"), 00)
			emu.Uc.MemWrite(in.Args[1], dir)
			return SkipFunctionStdCall(true, uint64(len(dir)))(emu, in)
		},
	})
	emu.AddHook("", "ReadFile", &Hook{
		Parameters: []string{"hFile", "lpBuffer", "nNumberOfBytesToRead", "lpNumberOfBytesRead", "lpOverlapped"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Handles[in.Args[0]]
			if handle != nil {
				buf := make([]byte, in.Args[2])
				num, err := handle.File.Read(buf)
				if err == nil {
					numbuf := make([]byte, 4)
					binary.LittleEndian.PutUint32(numbuf, uint32(num))
					emu.Uc.MemWrite(in.Args[1], buf)
					emu.Uc.MemWrite(in.Args[3], numbuf)
					return SkipFunctionStdCall(true, uint64(handle.Info.Size()))(emu, in)
				}
			}
			return SkipFunctionStdCall(true, 0x0)(emu, in)
		},
	})

	emu.AddHook("", "SetFilePointer", &Hook{
		Parameters: []string{"hFile", "lDistanceToMove", "lpDistanceToMoveHigh", "dwMoveMethod"},
		Fn: func(emu *WinEmulator, in *Instruction) bool {
			handle := emu.Handles[in.Args[0]]
			if handle != nil {
				// if lpDistanceToMoveHigh is NULL, the distance to move is a 32-bit signed value
				var m int64
				if in.Args[2] == 0 {
					move := int32(in.Args[1])
					m = int64(move)
					// if lpDistanceToMoveHigh is not NULL, the distance to move is a 64-bit signed value
				} else {
					move := int64((in.Args[2] << 32) + in.Args[1])
					m = int64(move)
				}

				whence := int(in.Args[3])
				ret, _ := handle.File.Seek(m, whence)
				//if err != nil {
				//    return SkipFunctionStdCall(true,
				return SkipFunctionStdCall(true, uint64(ret))(emu, in)
			}

			return SkipFunctionStdCall(true, 0x0)(emu, in)

		},
	})

	emu.AddHook("", "CopyFileA", &Hook{
		Parameters: []string{"a:lpExistingFileName", "a:lpNewFileName", "b:bFailIfExists"},
		Fn: func(emulator *WinEmulator, in *Instruction) bool {
			return SkipFunctionStdCall(true, 0x1)(emu, in)
		},
	})
}
