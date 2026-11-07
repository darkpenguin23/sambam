package smb2

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/sambam/sambam/smb/internal/erref"
	. "github.com/sambam/sambam/smb/internal/smb2"
)

// Behaviour found with a real Windows 11 client (see the commit message).

func (e *handleEnv) writeFile(name, content string) {
	e.t.Helper()
	if err := os.WriteFile(filepath.Join(e.share, name), []byte(content), 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *handleEnv) readFile(name string) string {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.share, name))
	if err != nil {
		e.t.Fatal(err)
	}
	return string(b)
}

// open opens name for read/write/delete and returns the chain holding it.

func (e *handleEnv) open(name string) *compoundContext {
	e.t.Helper()
	ctx := newChain()
	e.ft.create(ctx, e.createPkt(name, FILE_READ_DATA|FILE_WRITE_DATA|FILE_READ_ATTRIBUTES|DELETE, 0))
	if ctx.fileId == nil {
		e.t.Fatalf("CREATE %s failed: %v", name, statusOf(ctx.rsp[0]))
	}
	return ctx
}

func (e *handleEnv) setInfoOn(ctx *compoundContext, class uint8, input Encoder) NtStatus {
	e.t.Helper()
	e.ft.setInfo(ctx, e.encode(&SetInfoRequest{
		InfoType:      SMB2_0_INFO_FILE,
		FileInfoClass: class,
		FileId:        &relatedFileId,
		Input:         input,
	}, true))
	return statusOf(ctx.rsp[len(ctx.rsp)-1])
}

func (e *handleEnv) closeOn(ctx *compoundContext) {
	e.ft.close(ctx, e.encode(&CloseRequest{FileId: &relatedFileId}, true))
}

func allocation(n uint64) Encoder {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, n)
	return fuzzInput(b)
}

// Windows implements TRUNCATE_EXISTING - FileMode.Truncate, Clear-Content,

// PowerShell 5's Set-Content - as an open plus FileAllocationInformation(0).

// Ignoring it kept the old content: Set-Content 'x' on a file holding

// "one\r\ntwo\r\n" gave "one\r\ntwo\r\nx\r\n".

func TestAllocationInformationTruncates(t *testing.T) {
	e := newHandleEnv(t)
	e.writeFile("f.txt", "0123456789")
	ctx := e.open("f.txt")
	defer e.closeOn(ctx)

	if st := e.setInfoOn(ctx, FileAllocationInformation, allocation(100)); st != 0 {
		t.Fatalf("growing allocation: %v", st)
	}
	if got := e.readFile("f.txt"); got != "0123456789" {
		t.Fatalf("allocation above the size changed the data: %q", got)
	}
	if st := e.setInfoOn(ctx, FileAllocationInformation, allocation(4)); st != 0 {
		t.Fatalf("allocation 4: %v", st)
	}
	if got := e.readFile("f.txt"); got != "0123" {
		t.Fatalf("after allocation 4: %q, want %q", got, "0123")
	}
	if st := e.setInfoOn(ctx, FileAllocationInformation, allocation(0)); st != 0 {
		t.Fatalf("allocation 0: %v", st)
	}
	if got := e.readFile("f.txt"); got != "" {
		t.Fatalf("after allocation 0: %q, want empty", got)
	}
}

func rename(to string, replace bool) Encoder {
	r := &FileRenameInformationType2Encoder{FileName: to}
	if replace {
		r.ReplaceIfExists = 1
	}
	return r
}

// PowerShell's Move-Item -Force, Explorer and .NET decide what to do from the

// status of a failed rename; a collision reported as STATUS_ACCESS_DENIED

// made Move-Item -Force fail instead of replacing the target.

func TestRenameStatus(t *testing.T) {
	e := newHandleEnv(t)
	e.writeFile("src.txt", "src")
	e.writeFile("dst.txt", "dst")
	if err := os.Mkdir(filepath.Join(e.share, "dir"), 0o755); err != nil {
		t.Fatal(err)
	}

	ctx := e.open("src.txt")
	if st := e.setInfoOn(ctx, FileRenameInformation, rename("dst.txt", false)); st != STATUS_OBJECT_NAME_COLLISION {
		t.Errorf("rename onto existing file: %v, want STATUS_OBJECT_NAME_COLLISION", st)
	}
	if st := e.setInfoOn(ctx, FileRenameInformation, rename("dir", true)); st != STATUS_ACCESS_DENIED {
		t.Errorf("replace a directory: %v, want STATUS_ACCESS_DENIED", st)
	}
	if fi, err := os.Stat(filepath.Join(e.share, "dir")); err != nil || !fi.IsDir() {
		t.Fatalf("directory was replaced by a file: %v %v", fi, err)
	}
	if st := e.setInfoOn(ctx, FileRenameInformation, rename(`missing\x.txt`, false)); st != STATUS_OBJECT_PATH_NOT_FOUND {
		t.Errorf("rename into a missing directory: %v, want STATUS_OBJECT_PATH_NOT_FOUND", st)
	}
	if st := e.setInfoOn(ctx, FileRenameInformation, rename("src.txt", false)); st != 0 {
		t.Errorf("rename to its own name: %v, want success", st)
	}
	if st := e.setInfoOn(ctx, FileRenameInformation, rename("dst.txt", true)); st != 0 {
		t.Fatalf("rename with ReplaceIfExists: %v", st)
	}
	e.closeOn(ctx)
	if got := e.readFile("dst.txt"); got != "src" {
		t.Fatalf("dst.txt = %q after replacing rename", got)
	}
	if _, err := os.Stat(filepath.Join(e.share, "src.txt")); !os.IsNotExist(err) {
		t.Fatalf("src.txt still exists: %v", err)
	}
}

// FindFirstStreamW (Get-Item -Stream *, Explorer) asks with a 32-byte buffer

// first and grows it on STATUS_BUFFER_OVERFLOW; STATUS_INFO_LENGTH_MISMATCH

// made it fail with ERROR_BAD_LENGTH.

// Windows computes free space from FileFsFullSizeInformation; the

// ActualAvailableAllocationUnits field was written two bytes too far, so

// Explorer showed a petabyte free and negative used space.

func TestFsFullSizeInformationLayout(t *testing.T) {
	info := &FileFsFullSizeInformationInfo{
		TotalAllocationUnits:           0x1111,
		CallerAvailableAllocationUnits: 0x2222,
		ActualAvailableAllocationUnits: 0x3333,
		SectorsPerAllocationUnit:       8,
		BytesPerSector:                 512,
	}
	b := make([]byte, info.Size())
	info.Encode(b)
	le := binary.LittleEndian
	if le.Uint64(b[0:]) != 0x1111 || le.Uint64(b[8:]) != 0x2222 || le.Uint64(b[16:]) != 0x3333 ||
		le.Uint32(b[24:]) != 8 || le.Uint32(b[28:]) != 512 {
		t.Fatalf("FileFsFullSizeInformation encoding: % x", b)
	}
}

// Named streams follow NTFS: opening a missing one fails instead of creating

// it (every probe used to leave an empty stream behind, and reading a

// missing stream returned empty content), and reading at the end returns

// STATUS_END_OF_FILE instead of success with no data (clients reading until

// EOF looped forever).

func filetime(v int64) *Filetime {
	return &Filetime{LowDateTime: uint32(uint64(v)), HighDateTime: uint32(uint64(v) >> 32)}
}

func TestBasicInfoTime(t *testing.T) {
	for _, v := range []int64{0, -1, -2} {
		if _, set, valid := basicInfoTime(filetime(v)); set || !valid {
			t.Errorf("FILETIME %d: set=%v valid=%v, want unchanged", v, set, valid)
		}
	}
	if _, _, valid := basicInfoTime(filetime(-3)); valid {
		t.Error("FILETIME -3 accepted")
	}
	want := time.Date(2020, 1, 2, 3, 4, 5, 600, time.UTC)
	ft := NsecToFiletime(want.UnixNano())
	if got, set, valid := basicInfoTime(ft); !set || !valid || !got.Equal(want) {
		t.Errorf("FILETIME of %v decodes to %v (set=%v valid=%v)", want, got, set, valid)
	}
	// Far-future values must not overflow into the past.
	if got, set, _ := basicInfoTime(filetime(0x7fffffffffffffff)); !set || got.Year() < 30000 {
		t.Errorf("max FILETIME decodes to %v", got)
	}
}

// CopyFile sets LastAccessTime -1 on the source ("do not update"); that was

// written to disk as a date in 2185. FILE_ATTRIBUTE_READONLY was ignored.
