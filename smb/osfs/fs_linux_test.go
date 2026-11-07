//go:build linux

package osfs

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/sambam/sambam/smb/vfs"
	"golang.org/x/sys/unix"
)

// The SMB layer opens symlinks themselves with O_PATH|O_NOFOLLOW so that
// clients can resolve them. That must keep working for links that point
// outside the share (the link is listed, never followed).
func TestOpenSymlinkItselfWithOPath(t *testing.T) {
	fs, share, outside := newTestFS(t, false)
	if err := os.Symlink(outside, filepath.Join(share, "esc")); err != nil {
		t.Fatal(err)
	}
	attrs, err := fs.Lookup(0, "esc")
	if err != nil || attrs.GetFileType() != vfs.FileTypeSymlink {
		t.Fatalf("Lookup(esc) = %v, %v; want symlink", attrs, err)
	}
	h, err := fs.Open("esc", unix.O_PATH|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		t.Fatalf("open symlink with O_PATH|O_NOFOLLOW: %v", err)
	}
	defer fs.Close(h)
	attrs, err = fs.GetAttr(h)
	if err != nil || attrs.GetFileType() != vfs.FileTypeSymlink {
		t.Fatalf("GetAttr = %v, %v; want symlink", attrs, err)
	}
	if target, err := fs.Readlink(h); err != nil || target != outside {
		t.Fatalf("Readlink = %q, %v", target, err)
	}
}

// Same on a read-only share: the write flags are stripped, O_PATH|O_NOFOLLOW
// must survive, otherwise the open would follow (and fail on) the link.
func TestOpenSymlinkItselfOnReadOnlyShare(t *testing.T) {
	fs, share, outside := newTestFS(t, true)
	if err := os.Symlink(outside, filepath.Join(share, "esc")); err != nil {
		t.Fatal(err)
	}
	h, err := fs.Open("esc", unix.O_PATH|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		t.Fatalf("open symlink on read-only share: %v", err)
	}
	fs.Close(h)
}

func TestXattrRoundTripAndNoFollow(t *testing.T) {
	fs, share, outside := newTestFS(t, false)
	writeFile(t, filepath.Join(share, "f.txt"), "x")
	h, err := fs.Open("f.txt", os.O_RDONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(h)

	if err := fs.Setxattr(h, "stream", []byte("value")); err != nil {
		if errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP) {
			t.Skip("filesystem of TMPDIR does not support user xattrs")
		}
		t.Fatalf("Setxattr: %v", err)
	}
	if n, err := fs.Getxattr(h, "stream", nil); err != nil || n != 5 {
		t.Fatalf("Getxattr size = %d, %v", n, err)
	}
	buf := make([]byte, 5)
	if n, err := fs.Getxattr(h, "stream", buf); err != nil || string(buf[:n]) != "value" {
		t.Fatalf("Getxattr = %q, %v", buf[:n], err)
	}
	if names, err := fs.Listxattr(h); err != nil || len(names) != 1 || names[0] != "stream" {
		t.Fatalf("Listxattr = %q, %v", names, err)
	}
	if err := fs.Removexattr(h, "stream"); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Getxattr(h, "stream", nil); !errors.Is(err, unix.ENODATA) {
		t.Fatalf("Getxattr after remove: %v, want ENODATA", err)
	}

	// A handle on a symlink pointing outside must not touch the target's xattrs.
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(share, "lnk")); err != nil {
		t.Fatal(err)
	}
	lh, err := fs.Open("lnk", unix.O_PATH|unix.O_NOFOLLOW, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(lh)
	_ = fs.Setxattr(lh, "planted", []byte("x"))
	if sz, err := unix.Getxattr(filepath.Join(outside, "secret.txt"), "user.planted", nil); err == nil {
		t.Fatalf("xattr was written through the symlink to the outside file (size %d)", sz)
	}
}

func TestStatFSReportsRealDisk(t *testing.T) {
	fs, share, _ := newTestFS(t, false)
	var st unix.Statfs_t
	if err := unix.Statfs(share, &st); err != nil {
		t.Fatal(err)
	}
	a, err := fs.StatFS(0)
	if err != nil {
		t.Fatal(err)
	}
	blocks, _ := a.GetBlocks()
	bs, _ := a.GetBlockSize()
	if blocks != st.Blocks || bs != uint64(st.Frsize) {
		t.Fatalf("StatFS = %d blocks of %d, statfs = %d blocks of %d", blocks, bs, st.Blocks, st.Frsize)
	}
	avail, _ := a.GetAvailableBlocks()
	// Free space moves while tests run; it must be in the right ballpark.
	if diff := int64(avail) - int64(st.Bavail); diff > 1<<16 || diff < -(1<<16) {
		t.Fatalf("available blocks %d vs statfs %d", avail, st.Bavail)
	}
}
