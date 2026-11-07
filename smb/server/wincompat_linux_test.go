//go:build linux

package smb2

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	. "github.com/sambam/sambam/smb/internal/erref"
	. "github.com/sambam/sambam/smb/internal/smb2"
	"github.com/sambam/sambam/smb/internal/utf16le"
	"golang.org/x/sys/unix"
)

func TestAllocationInformationTruncatesStream(t *testing.T) {
	e := newHandleEnv(t)
	e.writeFile("f.txt", "main")
	if err := unix.Setxattr(filepath.Join(e.share, "f.txt"), "user.s", []byte("streamdata"), 0); err != nil {
		t.Skipf("no user xattrs here: %v", err)
	}
	e.ft.conn.serverCtx.xattrs = true
	ctx := e.open("f.txt:s")
	defer e.closeOn(ctx)
	if st := e.setInfoOn(ctx, FileAllocationInformation, allocation(6)); st != 0 {
		t.Fatalf("allocation 6 on a stream: %v", st)
	}
	buf := make([]byte, 64)
	n, err := unix.Getxattr(filepath.Join(e.share, "f.txt"), "user.s", buf)
	if err != nil || string(buf[:n]) != "stream" {
		t.Fatalf("stream after allocation 6: %q, %v", buf[:n], err)
	}
	if got := e.readFile("f.txt"); got != "main" {
		t.Fatalf("main stream changed: %q", got)
	}
}

func (e *handleEnv) queryFileInfo(ctx *compoundContext, class uint8, outLen uint32) (NtStatus, []byte) {
	e.t.Helper()
	e.ft.queryInfo(ctx, e.encode(&QueryInfoRequest{
		InfoType:           SMB2_0_INFO_FILE,
		FileInfoClass:      class,
		OutputBufferLength: outLen,
		FileId:             &relatedFileId,
	}, true))
	rsp := ctx.rsp[len(ctx.rsp)-1]
	st := statusOf(rsp)
	if st != 0 && st != STATUS_BUFFER_OVERFLOW {
		return st, nil
	}
	return st, QueryInfoResponseDecoder(rsp[64:]).OutputBuffer()
}

func streamNames(buf []byte) []string {
	var names []string
	for len(buf) >= 24 {
		next := binary.LittleEndian.Uint32(buf[0:])
		n := binary.LittleEndian.Uint32(buf[4:])
		names = append(names, utf16le.DecodeToString(buf[24:24+n]))
		if next == 0 {
			break
		}
		buf = buf[next:]
	}
	return names
}

func TestStreamInformationSmallBuffer(t *testing.T) {
	e := newHandleEnv(t)
	e.writeFile("f.txt", "main")
	if err := unix.Setxattr(filepath.Join(e.share, "f.txt"), "user.meta", []byte("abc"), 0); err != nil {
		t.Skipf("no user xattrs here: %v", err)
	}
	e.ft.conn.serverCtx.xattrs = true
	ctx := e.open("f.txt")
	defer e.closeOn(ctx)

	if st, _ := e.queryFileInfo(ctx, FileStreamInformation, 16); st != STATUS_INFO_LENGTH_MISMATCH {
		t.Errorf("16-byte buffer: %v, want STATUS_INFO_LENGTH_MISMATCH", st)
	}
	st, buf := e.queryFileInfo(ctx, FileStreamInformation, 32)
	if st != STATUS_BUFFER_OVERFLOW {
		t.Fatalf("32-byte buffer: %v, want STATUS_BUFFER_OVERFLOW", st)
	}
	if len(buf) > 32 {
		t.Fatalf("32-byte buffer got %d bytes", len(buf))
	}
	st, buf = e.queryFileInfo(ctx, FileStreamInformation, 40)
	if got := streamNames(buf); st != STATUS_BUFFER_OVERFLOW || len(got) != 1 || got[0] != "::$DATA" {
		t.Fatalf("40-byte buffer: %v %q, want STATUS_BUFFER_OVERFLOW [::$DATA]", st, got)
	}
	st, buf = e.queryFileInfo(ctx, FileStreamInformation, 4096)
	if got := streamNames(buf); st != 0 || len(got) != 2 || got[0] != "::$DATA" || got[1] != ":meta:$DATA" {
		t.Fatalf("4096-byte buffer: %v %q", st, got)
	}
}

func (e *handleEnv) createStream(name string, disp uint32) *compoundContext {
	e.t.Helper()
	ctx := newChain()
	e.ft.create(ctx, e.encode(&CreateRequest{
		ImpersonationLevel: 2,
		DesiredAccess:      FILE_READ_DATA | FILE_WRITE_DATA,
		ShareAccess:        FILE_SHARE_READ | FILE_SHARE_WRITE,
		CreateDisposition:  disp,
		Name:               name,
	}, false))
	return ctx
}

func (e *handleEnv) xattrs(name string) []string {
	e.t.Helper()
	buf := make([]byte, 4096)
	n, err := unix.Listxattr(filepath.Join(e.share, name), buf)
	if err != nil {
		e.t.Fatal(err)
	}
	var names []string
	for _, s := range bytes.Split(buf[:n], []byte{0}) {
		if len(s) > 0 {
			names = append(names, string(s))
		}
	}
	return names
}

func TestStreamCreateDispositionsAndEOF(t *testing.T) {
	e := newHandleEnv(t)
	e.writeFile("f.txt", "main")
	if err := unix.Setxattr(filepath.Join(e.share, "f.txt"), "user.have", []byte("abc"), 0); err != nil {
		t.Skipf("no user xattrs here: %v", err)
	}
	e.ft.conn.serverCtx.xattrs = true
	e.ft.ioReadSem = make(chan struct{}, 1)

	for _, c := range []struct {
		disp uint32
		name string
		want NtStatus
	}{
		{FILE_OPEN, "f.txt:missing", STATUS_OBJECT_NAME_NOT_FOUND},
		{FILE_OVERWRITE, "f.txt:missing", STATUS_OBJECT_NAME_NOT_FOUND},
		{FILE_CREATE, "f.txt:have", STATUS_OBJECT_NAME_COLLISION},
	} {
		ctx := e.createStream(c.name, c.disp)
		if st := statusOf(ctx.rsp[0]); st != c.want {
			t.Errorf("disposition %d on %s: %v, want %v", c.disp, c.name, st, c.want)
		}
		if ctx.fileId != nil {
			e.closeOn(ctx)
		}
	}
	if got := e.xattrs("f.txt"); len(got) != 1 || got[0] != "user.have" {
		t.Fatalf("streams after failed opens: %q, want only user.have", got)
	}

	ctx := e.createStream("f.txt:have", FILE_OPEN)
	if ctx.fileId == nil {
		t.Fatalf("open existing stream: %v", statusOf(ctx.rsp[0]))
	}
	defer e.closeOn(ctx)
	read := func(off uint64) (NtStatus, []byte) {
		e.ft.read(ctx, e.encode(&ReadRequest{Length: 100, Offset: off, FileId: &relatedFileId}, true))
		rsp := ctx.rsp[len(ctx.rsp)-1]
		st := statusOf(rsp)
		if st != 0 {
			return st, nil
		}
		return st, ReadResponseDecoder(rsp[64:]).Data()
	}
	if st, data := read(0); st != 0 || string(data) != "abc" {
		t.Fatalf("read stream: %v %q", st, data)
	}
	if st, data := read(3); st != STATUS_END_OF_FILE {
		t.Fatalf("read at end of stream: %v %q, want STATUS_END_OF_FILE", st, data)
	}

	// FILE_OPEN_IF still creates, FILE_OVERWRITE_IF truncates.
	ctx2 := e.createStream("f.txt:new", FILE_OPEN_IF)
	if ctx2.fileId == nil {
		t.Fatalf("FILE_OPEN_IF on a new stream: %v", statusOf(ctx2.rsp[0]))
	}
	e.closeOn(ctx2)
	if got := e.xattrs("f.txt"); len(got) != 2 {
		t.Fatalf("streams after FILE_OPEN_IF: %q", got)
	}
}

func basicInfo(atime, mtime int64, attrs uint32) Encoder {
	b := make([]byte, 40)
	binary.LittleEndian.PutUint64(b[8:], uint64(atime))
	binary.LittleEndian.PutUint64(b[16:], uint64(mtime))
	binary.LittleEndian.PutUint32(b[32:], attrs)
	return fuzzInput(b)
}

func TestSetBasicInformation(t *testing.T) {
	e := newHandleEnv(t)
	e.writeFile("f.txt", "x")
	p := filepath.Join(e.share, "f.txt")
	old := time.Date(2021, 5, 6, 7, 8, 9, 0, time.UTC)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	ctx := e.open("f.txt")
	defer e.closeOn(ctx)

	if st := e.setInfoOn(ctx, FileBasicInformation, basicInfo(-1, 0, 0)); st != 0 {
		t.Fatalf("LastAccessTime -1: %v", st)
	}
	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		t.Fatal(err)
	}
	if atime := time.Unix(st.Atim.Unix()); !atime.Equal(old) {
		t.Fatalf("atime after LastAccessTime=-1: %v, want unchanged %v", atime, old)
	}
	if s := e.setInfoOn(ctx, FileBasicInformation, basicInfo(-5, 0, 0)); s != STATUS_INVALID_PARAMETER {
		t.Errorf("LastAccessTime -5: %v, want STATUS_INVALID_PARAMETER", s)
	}

	if s := e.setInfoOn(ctx, FileBasicInformation, basicInfo(0, 0, FILE_ATTRIBUTE_READONLY)); s != 0 {
		t.Fatalf("set READONLY: %v", s)
	}
	if m := e.mode("f.txt"); m&0o222 != 0 {
		t.Fatalf("mode after READONLY: %v, want no write bits", m)
	}
	if s := e.setInfoOn(ctx, FileBasicInformation, basicInfo(0, 0, FILE_ATTRIBUTE_NORMAL)); s != 0 {
		t.Fatalf("clear READONLY: %v", s)
	}
	if m := e.mode("f.txt"); m&0o200 == 0 {
		t.Fatalf("mode after clearing READONLY: %v, want owner write", m)
	}
}
