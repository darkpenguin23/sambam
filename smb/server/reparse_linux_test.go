//go:build linux

package smb2

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	. "github.com/sambam/sambam/smb/internal/smb2"
	"github.com/sambam/sambam/smb/osfs"
	"golang.org/x/sys/unix"
)

// --- FSCTL_SET/DELETE_REPARSE_POINT access checks ---------------------------

type reparseEnv struct {
	t     *testing.T
	share string
	fs    *osfs.PassthroughFS
	srv   *Server
	ft    *fileTree
}

func newReparseEnv(t *testing.T, user string) *reparseEnv {
	t.Helper()
	share := t.TempDir()
	for _, name := range []string{"victim.txt", "other.txt"} {
		if err := os.WriteFile(filepath.Join(share, name), []byte("keep"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fs := osfs.NewPassthroughFS(share, false)
	srv := &Server{opens: map[uint64]*Open{}, userRO: map[string]bool{"bob": true}}

	ft := fuzzFileTreeIoctlHarness()
	ft.fs = fs
	ft.session.username = user
	ft.session.conn.serverCtx = srv
	return &reparseEnv{t: t, share: share, fs: fs, srv: srv, ft: ft}
}

// open opens name in the VFS and registers it like CREATE does.
func (e *reparseEnv) open(name string, flags int, access uint32) FileId {
	e.t.Helper()
	h, err := e.fs.Open(name, flags, 0o644)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { e.fs.Close(h) })
	e.srv.addOpen(&Open{fileId: uint64(h), grantedAccess: access, pathName: name})
	var fid FileId
	binary.LittleEndian.PutUint64(fid.Volatile[:], uint64(h))
	if fid.HandleId() != uint64(h) {
		e.t.Fatalf("FileId encoding: HandleId()=%x want %x", fid.HandleId(), uint64(h))
	}
	return fid
}

func (e *reparseEnv) ioctl(code uint32, fid FileId, input []byte) {
	e.t.Helper()
	mustNotPanicServer(e.t, func() { _ = e.ft.ioctl(nil, makeIoctlPacket(code, fid, input)) })
}

func (e *reparseEnv) isSymlink(name string) bool {
	fi, err := os.Lstat(filepath.Join(e.share, name))
	return err == nil && fi.Mode()&os.ModeSymlink != 0
}

func (e *reparseEnv) exists(name string) bool {
	_, err := os.Lstat(filepath.Join(e.share, name))
	return err == nil
}

func symlinkReparseBuffer(target string) []byte {
	name := []byte{}
	for _, r := range target { // ASCII targets only in these tests
		name = append(name, byte(r), 0)
	}
	data := make([]byte, 12, 12+2*len(name))
	binary.LittleEndian.PutUint16(data[0:], 0)                     // SubstituteNameOffset
	binary.LittleEndian.PutUint16(data[2:], uint16(len(name)))     // SubstituteNameLength
	binary.LittleEndian.PutUint16(data[4:], uint16(len(name)))     // PrintNameOffset
	binary.LittleEndian.PutUint16(data[6:], uint16(len(name)))     // PrintNameLength
	binary.LittleEndian.PutUint32(data[8:], SYMLINK_FLAG_RELATIVE) // Flags
	data = append(data, name...)
	data = append(data, name...)
	hdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(hdr[0:], IO_REPARSE_TAG_SYMLINK)
	binary.LittleEndian.PutUint16(hdr[4:], uint16(len(data)))
	return append(hdr, data...)
}

var deleteReparseBuffer = func() []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b, IO_REPARSE_TAG_SYMLINK)
	return b
}()

func TestReparseSetRequiresWritableUserAndHandle(t *testing.T) {
	// Positive control: a writable user with a write handle may create a symlink.
	e := newReparseEnv(t, "alice")
	fid := e.open("victim.txt", os.O_RDWR, FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES)
	e.ioctl(FSCTL_SET_REPARSE_POINT, fid, symlinkReparseBuffer("other.txt"))
	if !e.isSymlink("victim.txt") {
		t.Fatal("control: writable user could not create a symlink (harness does not reach the handler?)")
	}

	// Read-only user, even with a handle that claims write access.
	e = newReparseEnv(t, "bob")
	fid = e.open("victim.txt", os.O_RDONLY, FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES)
	e.ioctl(FSCTL_SET_REPARSE_POINT, fid, symlinkReparseBuffer("other.txt"))
	if e.isSymlink("victim.txt") {
		t.Fatal("read-only user replaced a file with a symlink")
	}

	// Writable user, but the handle was opened for reading only.
	e = newReparseEnv(t, "alice")
	fid = e.open("victim.txt", os.O_RDONLY, FILE_READ_DATA|FILE_READ_ATTRIBUTES)
	e.ioctl(FSCTL_SET_REPARSE_POINT, fid, symlinkReparseBuffer("other.txt"))
	if e.isSymlink("victim.txt") {
		t.Fatal("read-only handle replaced a file with a symlink")
	}
}

func TestReparseDeleteOnlyRemovesSymlinks(t *testing.T) {
	// Read-only user must not delete anything.
	e := newReparseEnv(t, "bob")
	fid := e.open("victim.txt", os.O_RDONLY, FILE_READ_DATA)
	e.ioctl(FSCTL_DELETE_REPARSE_POINT, fid, deleteReparseBuffer)
	if !e.exists("victim.txt") {
		t.Fatal("read-only user deleted a file via FSCTL_DELETE_REPARSE_POINT")
	}

	// Writable user with write access, but on a regular file: not a reparse point.
	e = newReparseEnv(t, "alice")
	fid = e.open("victim.txt", os.O_RDWR, FILE_WRITE_DATA|FILE_WRITE_ATTRIBUTES)
	e.ioctl(FSCTL_DELETE_REPARSE_POINT, fid, deleteReparseBuffer)
	if !e.exists("victim.txt") {
		t.Fatal("FSCTL_DELETE_REPARSE_POINT deleted a regular file")
	}

	// Positive control: on an actual symlink the reparse point is removed.
	e = newReparseEnv(t, "alice")
	if err := os.Symlink("other.txt", filepath.Join(e.share, "lnk")); err != nil {
		t.Fatal(err)
	}
	fid = e.open("lnk", unix.O_PATH|unix.O_NOFOLLOW, FILE_WRITE_ATTRIBUTES)
	e.ioctl(FSCTL_DELETE_REPARSE_POINT, fid, deleteReparseBuffer)
	if e.exists("lnk") {
		t.Fatal("control: symlink was not removed")
	}
	if !e.exists("other.txt") {
		t.Fatal("symlink target was removed instead of the link")
	}
}
