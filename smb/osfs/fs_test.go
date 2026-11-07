package osfs

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"

	"github.com/sambam/sambam/smb/vfs"
)

const secret = "outside-the-share"

// newTestFS creates <tmp>/share (the share root) and <tmp>/outside/secret.txt
// next to it, which no client path must ever reach.
func newTestFS(t *testing.T, readOnly bool) (*PassthroughFS, string, string) {
	t.Helper()
	base := t.TempDir()
	share := filepath.Join(base, "share")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{share, filepath.Join(share, "sub"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(outside, "secret.txt"), secret)
	writeFile(t, filepath.Join(share, "sub", "doc.txt"), "doc")
	return NewPassthroughFS(share, readOnly), share, outside
}

func writeFile(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readAll(t *testing.T, fs *PassthroughFS, h vfs.VfsHandle) string {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := fs.Read(h, buf, 0, 0)
	if err != nil && err != io.EOF {
		t.Fatalf("read: %v", err)
	}
	return string(buf[:n])
}

func TestEscapingPathsAreRejected(t *testing.T) {
	fs, share, outside := newTestFS(t, false)
	// A symlink planted inside the share that points outside of it.
	if err := os.Symlink(outside, filepath.Join(share, "esc")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../outside", filepath.Join(share, "esc-rel")); err != nil {
		t.Fatal(err)
	}

	escaping := []string{
		"../outside/secret.txt",
		"/../outside/secret.txt",
		"sub/../../outside/secret.txt",
		"esc/secret.txt",
		"esc-rel/secret.txt",
	}
	for _, p := range escaping {
		t.Run(p, func(t *testing.T) {
			if _, err := fs.Lookup(0, p); err == nil {
				t.Errorf("Lookup(%q) succeeded", p)
			}
			if h, err := fs.Open(p, os.O_RDONLY, 0o644); err == nil {
				t.Errorf("Open(%q) succeeded and returned %q", p, readAll(t, fs, h))
				fs.Close(h)
			}
		})
	}
	for _, d := range []string{"..", "../outside", "sub/../..", "esc", "esc-rel"} {
		if h, err := fs.OpenDir(d); err == nil {
			fs.Close(h)
			t.Errorf("OpenDir(%q) succeeded", d)
		}
	}

	// Creating, making directories and renaming must not reach outside.
	if h, err := fs.Open("../outside/created.txt", os.O_RDWR|os.O_CREATE, 0o644); err == nil {
		fs.Close(h)
	}
	if _, err := fs.Mkdir("../outside/newdir", 0o755); err == nil {
		t.Error("Mkdir outside the share succeeded")
	}
	if _, err := fs.Mkdir("esc/newdir", 0o755); err == nil {
		t.Error("Mkdir through an escaping symlink succeeded")
	}
	writeFile(t, filepath.Join(share, "move-me.txt"), "x")
	h, err := fs.Open("move-me.txt", os.O_RDONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.Rename(h, "../outside/moved.txt", 1); err == nil {
		t.Error("Rename to a target outside the share succeeded")
	}
	if err := fs.Rename(h, "esc/moved.txt", 1); err == nil {
		t.Error("Rename through an escaping symlink succeeded")
	}
	fs.Close(h)

	for _, name := range []string{"created.txt", "newdir", "moved.txt"} {
		if _, err := os.Lstat(filepath.Join(outside, name)); err == nil {
			t.Errorf("%s was created outside the share", name)
		}
	}
}

func TestSymlinkInsideShareStillWorks(t *testing.T) {
	fs, share, _ := newTestFS(t, false)
	if err := os.Symlink("sub", filepath.Join(share, "alias")); err != nil {
		t.Fatal(err)
	}
	h, err := fs.Open("alias/doc.txt", os.O_RDONLY, 0o644)
	if err != nil {
		t.Fatalf("open through in-share symlink: %v", err)
	}
	defer fs.Close(h)
	if got := readAll(t, fs, h); got != "doc" {
		t.Fatalf("read %q, want %q", got, "doc")
	}
}

func TestShareRootMayBeSymlink(t *testing.T) {
	_, share, _ := newTestFS(t, false)
	link := filepath.Join(t.TempDir(), "share-link")
	if err := os.Symlink(share, link); err != nil {
		t.Fatal(err)
	}
	fs := NewPassthroughFS(link, false)
	attrs, err := fs.Lookup(0, "/")
	if err != nil {
		t.Fatal(err)
	}
	if attrs.GetFileType() != vfs.FileTypeDirectory {
		t.Fatalf("share root type = %v, want directory", attrs.GetFileType())
	}
	if _, err := fs.Lookup(0, "sub/doc.txt"); err != nil {
		t.Fatalf("lookup below symlinked root: %v", err)
	}
}

func TestClientSymlinkIsStoredButNotFollowed(t *testing.T) {
	fs, share, outside := newTestFS(t, false)
	h, err := fs.Open("lnk", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Symlink(h, outside, 0); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if target, err := fs.Readlink(h); err != nil || target != outside {
		t.Fatalf("Readlink = %q, %v; want %q", target, err, outside)
	}
	fs.Close(h)

	if fi, err := os.Lstat(filepath.Join(share, "lnk")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("lnk on disk is not a symlink: %v", err)
	}
	if h, err := fs.Open("lnk/secret.txt", os.O_RDONLY, 0o644); err == nil {
		t.Errorf("read through client-created symlink: %q", readAll(t, fs, h))
		fs.Close(h)
	}
}

func TestFileLifecycle(t *testing.T) {
	fs, share, _ := newTestFS(t, false)

	var mu sync.Mutex
	var created, deleted, opened []string
	fs.OnCreate = func(p string, isDir bool) { mu.Lock(); created = append(created, p); mu.Unlock() }
	fs.OnDelete = func(p string) { mu.Lock(); deleted = append(deleted, p); mu.Unlock() }
	fs.OnOpen = func(p, mode string) { mu.Lock(); opened = append(opened, p); mu.Unlock() }

	if _, err := fs.Mkdir("dir", 0o755); err != nil {
		t.Fatal(err)
	}
	h, err := fs.Open("dir/a.txt", os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := fs.Write(h, []byte("hello world"), 0, 0); err != nil || n != 11 {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if n, err := fs.Write(h, []byte("WORLD"), 6, 0); err != nil || n != 5 {
		t.Fatalf("Write at offset = %d, %v", n, err)
	}
	if err := fs.Truncate(h, 9); err != nil {
		t.Fatal(err)
	}
	if got := readAll(t, fs, h); got != "hello WOR" {
		t.Fatalf("content = %q", got)
	}
	attrs, err := fs.GetAttr(h)
	if err != nil {
		t.Fatal(err)
	}
	if size, _ := attrs.GetSizeBytes(); size != 9 {
		t.Fatalf("size after truncate = %d, want 9", size)
	}
	if err := fs.Rename(h, "dir/b.txt", 0); err != nil {
		t.Fatal(err)
	}
	if err := fs.Unlink(h); err != nil {
		t.Fatal(err)
	}
	fs.Close(h)

	if _, err := os.Stat(filepath.Join(share, "dir", "b.txt")); !os.IsNotExist(err) {
		t.Fatalf("b.txt still exists: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(created) != 2 || created[0] != "dir" || created[1] != "dir/a.txt" {
		t.Errorf("OnCreate paths = %q", created)
	}
	if len(deleted) != 1 || deleted[0] != "dir/b.txt" {
		t.Errorf("OnDelete paths = %q (want share-relative path after rename)", deleted)
	}
	if len(opened) != 1 || opened[0] != "dir/a.txt" {
		t.Errorf("OnOpen paths = %q", opened)
	}
}

func TestRenameWithoutReplaceKeepsExistingTarget(t *testing.T) {
	fs, share, _ := newTestFS(t, false)
	writeFile(t, filepath.Join(share, "src.txt"), "src")
	writeFile(t, filepath.Join(share, "dst.txt"), "dst")
	h, err := fs.Open("src.txt", os.O_RDONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(h)
	if err := fs.Rename(h, "dst.txt", 0); err == nil {
		t.Fatal("rename onto existing file without replace succeeded")
	}
	if b, _ := os.ReadFile(filepath.Join(share, "dst.txt")); string(b) != "dst" {
		t.Fatalf("dst.txt was overwritten: %q", b)
	}
	if err := fs.Rename(h, "dst.txt", 1); err != nil {
		t.Fatalf("rename with replace: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(share, "dst.txt")); string(b) != "src" {
		t.Fatalf("dst.txt = %q after replace", b)
	}
}

func TestReadDirReturnsEveryEntryOnce(t *testing.T) {
	fs, share, _ := newTestFS(t, false)
	dir := filepath.Join(share, "many")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const n = 1234
	want := []string{".", ".."}
	for i := 0; i < n; i++ {
		name := "file-" + string(rune('a'+i%26)) + "-" + itoa(i) + ".txt"
		writeFile(t, filepath.Join(dir, name), "")
		want = append(want, name)
	}
	h, err := fs.OpenDir("many")
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close(h)

	// Read in small batches and push part of each batch back, the way the
	// QUERY_DIRECTORY handler does when the response buffer is full.
	// pos != 0 means RESTART_SCANS, so continuation reads pass 0.
	var got []string
	for calls := 0; ; calls++ {
		if calls > 10*n {
			t.Fatal("ReadDir did not reach the end of the directory")
		}
		entries, err := fs.ReadDir(h, 0, 50)
		if err == io.EOF || (err == nil && len(entries) == 0) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		keep := len(entries)
		if keep > 7 {
			keep = len(entries) - 7
			fs.PutBackDirEntries(h, entries[keep:])
		}
		for _, e := range entries[:keep] {
			got = append(got, e.Name)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestReadOnlyShare(t *testing.T) {
	fs, share, _ := newTestFS(t, true)
	writeFile(t, filepath.Join(share, "keep.txt"), "keep")

	if h, err := fs.Open("new.txt", os.O_RDWR|os.O_CREATE, 0o644); err == nil {
		fs.Close(h)
	}
	if _, err := os.Stat(filepath.Join(share, "new.txt")); !os.IsNotExist(err) {
		t.Error("read-only share created a file")
	}
	h, err := fs.Open("keep.txt", os.O_RDWR|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatalf("open existing file on read-only share: %v", err)
	}
	defer fs.Close(h)
	if _, err := fs.Write(h, []byte("X"), 0, 0); err == nil {
		t.Error("write on read-only share succeeded")
	}
	if err := fs.Unlink(h); err == nil {
		t.Error("unlink on read-only share succeeded")
	}
	if _, err := fs.Mkdir("d", 0o755); err == nil {
		t.Error("mkdir on read-only share succeeded")
	}
	if b, _ := os.ReadFile(filepath.Join(share, "keep.txt")); !bytes.Equal(b, []byte("keep")) {
		t.Errorf("keep.txt changed to %q", b)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}
