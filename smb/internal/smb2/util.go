package smb2

import (
	"encoding/binary"
	"path/filepath"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/sambam/sambam/smb/vfs"
)

var (
	le = binary.LittleEndian
)

func Roundup(x, align int) int {
	return (x + (align - 1)) &^ (align - 1)
}

func Roundup64(x, align int64) int64 {
	return (x + (align - 1)) &^ (align - 1)
}

func UTF16FromString(s string) []uint16 {
	return utf16.Encode([]rune(s))
}

func UTF16ToString(s []uint16) string {
	return string(utf16.Decode(s))
}

// MatchWildcard reports whether the file name s matches an SMB search
// pattern, following MS-FSA 2.1.4.4 (FsRtlIsNameInExpression):
//
//   - '*' matches any sequence of characters (including none)
//   - '?' matches exactly one character
//   - '<' (DOS_STAR) matches any sequence not extending past the last '.'
//     in the name
//   - '>' (DOS_QM) matches any single character except '.', and nothing at
//     a '.' or at the end of the name
//   - '"' (DOS_DOT) matches a '.', or nothing at the end of the name
//
// All other characters match literally and case-insensitively, like
// Windows. Windows clients send the DOS forms (e.g. `dir *.txt` arrives as
// `<.txt`). The match runs in O(len(pattern)*len(name)) time, so hostile
// patterns such as "*a*a*a*b" cannot cause exponential backtracking.
func MatchWildcard(s, pattern string) bool {
	name := []rune(s)
	pat := []rune(pattern)
	lastDot := -1
	for i, r := range name {
		if r == '.' {
			lastDot = i
		}
	}

	// reach[j] reports whether name[:j] can be matched by the pattern prefix
	// processed so far.
	reach := make([]bool, len(name)+1)
	next := make([]bool, len(name)+1)
	reach[0] = true
	for _, pc := range pat {
		for j := range next {
			next[j] = false
		}
		switch pc {
		case '*':
			for j := 0; j <= len(name); j++ {
				next[j] = reach[j] || (j > 0 && next[j-1])
			}
		case '<':
			for j := 0; j <= len(name); j++ {
				// May consume name[j-1] only if it lies before the last dot
				// (or the name has no dot at all).
				canConsume := j > 0 && (lastDot < 0 || j-1 < lastDot)
				next[j] = reach[j] || (canConsume && next[j-1])
			}
		case '>':
			for j := 0; j <= len(name); j++ {
				if !reach[j] {
					continue
				}
				if j < len(name) && name[j] != '.' {
					next[j+1] = true
				} else {
					next[j] = true // zero-width at '.' or end of name
				}
			}
		case '"':
			for j := 0; j <= len(name); j++ {
				if !reach[j] {
					continue
				}
				if j == len(name) {
					next[j] = true
				} else if name[j] == '.' {
					next[j+1] = true
				}
			}
		case '?':
			for j := 0; j < len(name); j++ {
				if reach[j] {
					next[j+1] = true
				}
			}
		default:
			for j := 0; j < len(name); j++ {
				if reach[j] && foldEqual(name[j], pc) {
					next[j+1] = true
				}
			}
		}
		reach, next = next, reach
	}
	return reach[len(name)]
}

func foldEqual(a, b rune) bool {
	return a == b || unicode.ToUpper(a) == unicode.ToUpper(b)
}

func Align(n int, a int) int {
	return (n + a - 1) &^ (a - 1)
}

func (f *FileId) HandleId() uint64 {
	return le.Uint64(f.Volatile[:]) /* & 0xffffffff*/
}

func (f *FileId) SetHandleId(n uint64) {
	v := n //(uint64(rand.Uint32()) << 32) | n
	le.PutUint64(f.Volatile[:], v)
}

func (f *FileId) NodeId() uint64 {
	return le.Uint64(f.Persistent[:])
}

func (f *FileId) SetNodeId(n uint64) {
	le.PutUint64(f.Persistent[:], n)
}

// ContainsWildcard reports whether s is a search pattern rather than a
// plain file name (see MatchWildcard for the wildcard characters).
func ContainsWildcard(s string) bool {
	return strings.ContainsAny(s, `*?<>"`)
}

func BirthTimeFromVfs(a *vfs.Attributes) *Filetime {
	if t, ok := a.GetBirthTime(); ok {
		return NsecToFiletime(t.UnixNano())
	}
	return &Filetime{}
}

func AccessTimeFromVfs(a *vfs.Attributes) *Filetime {
	if t, ok := a.GetAccessTime(); ok {
		return NsecToFiletime(t.UnixNano())
	}
	return &Filetime{}
}

func ModifiedTimeFromVfs(a *vfs.Attributes) *Filetime {
	if t, ok := a.GetLastDataModificationTime(); ok {
		return NsecToFiletime(t.UnixNano())
	}
	return &Filetime{}
}

func ChangeTimeFromVfs(a *vfs.Attributes) *Filetime {
	if t, ok := a.GetLastStatusChangeTime(); ok {
		return NsecToFiletime(t.UnixNano())
	}
	return &Filetime{}
}

func SizeFromVfs(a *vfs.Attributes) uint64 {
	if s, ok := a.GetSizeBytes(); ok {
		return s
	}
	return 0
}

func UnixModeFromVfs(a *vfs.Attributes) uint16 {
	m := uint16(0)
	if s, ok := a.GetUnixMode(); ok {
		m = uint16(s)
	} else {
		m = 0777
	}
	switch a.GetFileType() {
	case vfs.FileTypeDirectory:
		m |= 0x4000
	case vfs.FileTypeRegularFile:
		m |= 0x8000
	case vfs.FileTypeSymlink:
		m |= 0xa000
	}
	return m
}

func DiskSizeFromVfs(a *vfs.Attributes) uint64 {
	if s, ok := a.GetDiskSizeBytes(); ok {
		return s
	}
	return SizeFromVfs(a)
}

const (
	posixFiletypeShift = 12
	posixFiletypeMask  = 0x7000 // 0070000
	posixFiletypeReg   = 0
	posixFiletypeDir   = 1
	posixFiletypeLnk   = 2
	posixFiletypeChr   = 3
	posixFiletypeBlk   = 4
	posixFiletypeFifo  = 5
	posixFiletypeSock  = 6
)

// PosixWireModeFromVfs returns the SMB3 POSIX wire-format mode.
// The wire format encodes file type as a small enum in bits 12-14,
// not the standard S_IF* values.
func PosixWireModeFromVfs(a *vfs.Attributes) uint32 {
	perm := uint32(0777)
	if m, ok := a.GetUnixMode(); ok {
		perm = m & 07777
	}

	ftype := uint32(posixFiletypeReg)
	switch a.GetFileType() {
	case vfs.FileTypeDirectory:
		ftype = posixFiletypeDir
	case vfs.FileTypeSymlink:
		ftype = posixFiletypeLnk
	case vfs.FileTypeRegularFile:
		ftype = posixFiletypeReg
	}

	return perm | (ftype << posixFiletypeShift)
}

func PermissionsFromVfs(a *vfs.Attributes, path string, hideDotfiles bool) uint32 {
	perm := uint32(0)
	if hideDotfiles {
		name := filepath.Base(path)
		if len(name) > 0 && name[0] == '.' {
			perm |= FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE
		}
	}
	if p, ok := a.GetPermissions(); ok {
		if p&vfs.PermissionsWrite == 0 && p&vfs.PermissionsRead == 0 && p&vfs.PermissionsExecute == 0 {
			perm = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_READONLY
		} else if p&vfs.PermissionsWrite == 0 {
			perm = FILE_ATTRIBUTE_READONLY
		}
	}
	if a.GetFileType() == vfs.FileTypeDirectory {
		perm |= FILE_ATTRIBUTE_DIRECTORY
	}
	if a.GetFileType() == vfs.FileTypeSymlink {
		perm |= FILE_ATTRIBUTE_REPARSE_POINT
	}

	if perm == 0 {
		perm = FILE_ATTRIBUTE_NORMAL
	}
	return perm
}

func MaxAccessFromVfs(a *vfs.Attributes) uint32 {
	maximalAccess := uint32(0)
	unixMode, ok := a.GetUnixMode()
	if !ok {
		unixMode = 0777
	}
	maximalAccess = SYNCHRONIZE

	if unixMode&0404 != 0 {
		maximalAccess |= FILE_READ_ATTRIBUTES | FILE_READ_DATA | FILE_READ_EA
		if unixMode&0400 != 0 {
			maximalAccess |= READ_CONTROL
		}
	}
	if unixMode&0202 != 0 {
		maximalAccess |= FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_APPEND_DATA
		if unixMode&0200 != 0 {
			maximalAccess |= WRITE_DAC | WRITE_OWNER
			maximalAccess |= DELETE | FILE_DELETE_CHILD
		}
	}
	if unixMode&0101 != 0 {
		maximalAccess |= FILE_EXECUTE
	}
	// Windows treats execute as a read-capability for regular files on SMB shares.
	// If the file is readable, allow FILE_EXECUTE even if the unix exec bit is unset.
	if unixMode&0444 != 0 {
		maximalAccess |= FILE_EXECUTE
	}
	return maximalAccess
}

func PrepareResponse(rsp *PacketHeader, req []byte, status uint32) {
	p := PacketCodec(req)
	rsp.Command = p.Command()
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = 1 | (p.Flags() & SMB2_FLAGS_PRIORITY_MASK)
	rsp.Status = status
}

func PrepareAsyncResponse(rsp *PacketHeader, req []byte, asyncId uint64, status uint32) {
	p := PacketCodec(req)
	rsp.Command = p.Command()
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = SMB2_FLAGS_SERVER_TO_REDIR
	if asyncId != 0 {
		rsp.Flags |= SMB2_FLAGS_ASYNC_COMMAND
	}
	rsp.Status = status
	rsp.AsyncId = asyncId
}

func IsInvalidFileId(f *FileId) bool {
	inv := [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	return f == nil ||
		(reflect.DeepEqual(f.Persistent, inv) && reflect.DeepEqual(f.Volatile, inv))
}

func IsEA(p string) bool {
	return strings.Contains(p, ":")
}

func SplitEA(p string) (string, string) {
	a := strings.Split(p, ":")
	return a[0], a[1]
}
