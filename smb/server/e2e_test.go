package smb2_test

// End-to-end tests: a real sambam server on 127.0.0.1 serving an osfs share,
// driven by an independent SMB2/3 client (github.com/hirochachacha/go-smb2).

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	client "github.com/hirochachacha/go-smb2"
	log "github.com/sirupsen/logrus"

	"github.com/sambam/sambam/smb/osfs"
	server "github.com/sambam/sambam/smb/server"
	"github.com/sambam/sambam/smb/vfs"
)

const outsideSecret = "outside-the-share"

type e2eServer struct {
	addr    string
	share   string
	outside string
}

func startServer(t *testing.T) *e2eServer {
	t.Helper()
	if !testing.Verbose() {
		log.SetOutput(io.Discard)
		t.Cleanup(func() { log.SetOutput(os.Stderr) })
	}

	base := t.TempDir()
	e := &e2eServer{share: filepath.Join(base, "share"), outside: filepath.Join(base, "outside")}
	for _, d := range []string{e.share, e.outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(e.outside, "secret.txt"), []byte(outsideSecret), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.share, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := server.NewServer(&server.ServerConfig{
		EnableSMB3Encryption: true,
		AuthUsers:            []string{"alice", "bob"},
		ShareAllowUsers:      map[string][]string{"docs": {"alice", "bob"}},
		UserReadonly:         map[string]bool{"bob": true},
	}, &server.NTLMAuthenticator{
		UserPassword: map[string]string{"alice": "alicepw", "bob": "bobpw"},
		NbDomain:     "E2E",
		NbName:       "E2E",
		DnsName:      "e2e.local",
		DnsDomain:    ".local",
	}, map[string]vfs.VFSFileSystem{"docs": osfs.NewPassthroughFS(e.share, false)})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	e.addr = ln.Addr().String()
	ln.Close()

	done := make(chan error, 1)
	go func() { done <- srv.Serve(e.addr) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", e.addr)
		if err == nil {
			c.Close()
			break
		}
		select {
		case err := <-done:
			t.Fatalf("server exited: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Cleanup(func() {
		srv.Shutdown()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not stop after Shutdown")
		}
	})
	return e
}

// mount logs in and mounts the "docs" share.
func (e *e2eServer) mount(t *testing.T, user, pw string) (*client.Share, error) {
	t.Helper()
	conn, err := net.Dial("tcp", e.addr)
	if err != nil {
		return nil, err
	}
	d := &client.Dialer{Initiator: &client.NTLMInitiator{User: user, Password: pw}}
	sess, err := d.Dial(conn)
	if err != nil {
		conn.Close()
		return nil, err
	}
	share, err := sess.Mount("docs")
	if err != nil {
		sess.Logoff()
		conn.Close()
		return nil, err
	}
	t.Cleanup(func() {
		share.Umount()
		sess.Logoff()
		conn.Close()
	})
	return share, nil
}

func (e *e2eServer) mustMount(t *testing.T, user, pw string) *client.Share {
	t.Helper()
	s, err := e.mount(t, user, pw)
	if err != nil {
		t.Fatalf("mount as %s: %v", user, err)
	}
	return s
}

func (e *e2eServer) onDisk(name string) (string, bool) {
	b, err := os.ReadFile(filepath.Join(e.share, filepath.FromSlash(name)))
	return string(b), err == nil
}

func TestE2EFileLifecycle(t *testing.T) {
	e := startServer(t)
	fs := e.mustMount(t, "alice", "alicepw")

	data := make([]byte, 3<<20+123) // > 1 MiB to cross several READ/WRITE requests
	rand.Read(data)
	if err := fs.WriteFile("big.bin", data, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := fs.ReadFile("big.bin")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("read back %d bytes, differs from the %d written", len(got), len(data))
	}
	if disk, _ := e.onDisk("big.bin"); disk != string(data) {
		t.Fatal("on-disk content differs")
	}
	fi, err := fs.Stat("big.bin")
	if err != nil || fi.Size() != int64(len(data)) {
		t.Fatalf("stat: %v size=%d", err, fi.Size())
	}

	// Partial write and truncate through an open handle.
	f, err := fs.OpenFile("big.bin", os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteAt([]byte("HEADER"), 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(10); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if disk, _ := e.onDisk("big.bin"); disk != "HEADER"+string(data[6:10]) {
		t.Fatalf("after WriteAt+Truncate: %q", disk)
	}

	// Directories, rename, delete.
	if err := fs.MkdirAll(`dir\sub`, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := fs.Rename("big.bin", `dir\sub\moved.bin`); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, ok := e.onDisk("dir/sub/moved.bin"); !ok {
		t.Fatal("renamed file missing on disk")
	}
	if _, ok := e.onDisk("big.bin"); ok {
		t.Fatal("old name still present after rename")
	}
	if err := fs.Remove("dir"); err == nil {
		t.Fatal("removing a non-empty directory succeeded")
	}
	if err := fs.RemoveAll("dir"); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	if _, err := os.Stat(filepath.Join(e.share, "dir")); !os.IsNotExist(err) {
		t.Fatalf("dir still exists: %v", err)
	}
}

func TestE2ERenameDoesNotOverwrite(t *testing.T) {
	e := startServer(t)
	fs := e.mustMount(t, "alice", "alicepw")
	if err := fs.WriteFile("a.txt", []byte("A"), 0o644); err != nil {
		t.Fatal(err)
	}
	// go-smb2's Rename does not set ReplaceIfExists; the existing target must survive.
	if err := fs.Rename("a.txt", "keep.txt"); err == nil {
		t.Fatal("rename onto an existing file succeeded without ReplaceIfExists")
	}
	if disk, _ := e.onDisk("keep.txt"); disk != "keep" {
		t.Fatalf("keep.txt = %q", disk)
	}
}

func TestE2ELargeDirectoryListing(t *testing.T) {
	e := startServer(t)
	dir := filepath.Join(e.share, "many")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	const n = 3000 // several QUERY_DIRECTORY round trips
	want := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("entry-%05d-%s.txt", i, strings.Repeat("x", i%40))
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
		want = append(want, name)
	}
	fs := e.mustMount(t, "alice", "alicepw")
	infos, err := fs.ReadDir("many")
	if err != nil {
		t.Fatal(err)
	}
	got := make([]string, 0, len(infos))
	for _, fi := range infos {
		got = append(got, fi.Name())
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("listed %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entry %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestE2EReadOnlyUser(t *testing.T) {
	e := startServer(t)
	fs := e.mustMount(t, "bob", "bobpw")

	if b, err := fs.ReadFile("keep.txt"); err != nil || string(b) != "keep" {
		t.Fatalf("read-only user cannot read: %q, %v", b, err)
	}
	if err := fs.WriteFile("new.txt", []byte("x"), 0o644); err == nil {
		t.Error("read-only user created a file")
	}
	if f, err := fs.OpenFile("keep.txt", os.O_RDWR, 0); err == nil {
		f.Close()
		t.Error("read-only user opened a file for writing")
	}
	if err := fs.Remove("keep.txt"); err == nil {
		t.Error("read-only user deleted a file")
	}
	if err := fs.Rename("keep.txt", "renamed.txt"); err == nil {
		t.Error("read-only user renamed a file")
	}
	if err := fs.Mkdir("d", 0o755); err == nil {
		t.Error("read-only user created a directory")
	}
	if err := fs.Symlink("keep.txt", "lnk"); err == nil {
		t.Error("read-only user created a symlink")
	}
	if disk, ok := e.onDisk("keep.txt"); !ok || disk != "keep" {
		t.Fatalf("keep.txt changed: %q exists=%v", disk, ok)
	}
	entries, _ := os.ReadDir(e.share)
	if len(entries) != 1 {
		t.Fatalf("share content changed: %d entries", len(entries))
	}
}

func TestE2EPathsCannotLeaveShare(t *testing.T) {
	e := startServer(t)
	fs := e.mustMount(t, "alice", "alicepw")

	for _, p := range []string{`..\outside\secret.txt`, `keep.txt\..\..\outside\secret.txt`} {
		if b, err := fs.ReadFile(p); err == nil {
			t.Errorf("ReadFile(%q) = %q", p, b)
		}
	}
	if err := fs.WriteFile(`..\outside\created.txt`, []byte("x"), 0o644); err == nil {
		t.Error("created a file outside the share")
	}
	if err := fs.Rename("keep.txt", `..\outside\moved.txt`); err == nil {
		t.Error("renamed a file to outside the share")
	}
	if err := fs.Mkdir(`..\outside\newdir`, 0o755); err == nil {
		t.Error("created a directory outside the share")
	}
	for _, name := range []string{"created.txt", "moved.txt", "newdir"} {
		if _, err := os.Lstat(filepath.Join(e.outside, name)); err == nil {
			t.Errorf("%s appeared outside the share", name)
		}
	}
	if _, ok := e.onDisk("keep.txt"); !ok {
		t.Error("keep.txt disappeared")
	}
}

func TestE2ESymlinks(t *testing.T) {
	e := startServer(t)
	fs := e.mustMount(t, "alice", "alicepw")

	// A client may store a symlink with any target (clients resolve links
	// themselves), but the server must never follow it out of the share.
	if err := fs.Symlink(e.outside, "esc"); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if target, err := fs.Readlink("esc"); err != nil || target != strings.ReplaceAll(e.outside, "/", `\`) {
		t.Fatalf("Readlink = %q, %v", target, err)
	}
	if b, err := fs.ReadFile(`esc\secret.txt`); err == nil {
		t.Fatalf("read through client-created symlink: %q", b)
	}

	// The same for a link planted locally on the server.
	if err := os.Symlink("../outside", filepath.Join(e.share, "esc-rel")); err != nil {
		t.Fatal(err)
	}
	if b, err := fs.ReadFile(`esc-rel\secret.txt`); err == nil {
		t.Fatalf("read through local escaping symlink: %q", b)
	}

	// Links that stay inside the share keep working.
	if err := os.Mkdir(filepath.Join(e.share, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.share, "sub", "doc.txt"), []byte("doc"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("sub", filepath.Join(e.share, "alias")); err != nil {
		t.Fatal(err)
	}
	if b, err := fs.ReadFile(`alias\doc.txt`); err != nil || string(b) != "doc" {
		t.Fatalf("read through in-share symlink: %q, %v", b, err)
	}
}

func TestE2EAuthentication(t *testing.T) {
	e := startServer(t)
	if _, err := e.mount(t, "alice", "wrong"); err == nil {
		t.Error("login with wrong password succeeded")
	}
	if _, err := e.mount(t, "mallory", "x"); err == nil {
		t.Error("login as unknown user succeeded (guest is disabled)")
	}
	e.mustMount(t, "alice", "alicepw")
}

// Many simultaneous logins of different users used to share one NTLM
// handshake state and crashed the server with a nil pointer dereference.
func TestE2EConcurrentLogins(t *testing.T) {
	e := startServer(t)
	const n = 40
	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			user, pw := "alice", "alicepw"
			if i%2 == 1 {
				user, pw = "bob", "bobpw"
			}
			fs, err := e.mount(t, user, pw)
			if err != nil {
				errs <- fmt.Errorf("%s #%d: mount: %w", user, i, err)
				return
			}
			b, err := fs.ReadFile("keep.txt")
			if err != nil || string(b) != "keep" {
				errs <- fmt.Errorf("%s #%d: read: %q %v", user, i, b, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	failed := 0
	for err := range errs {
		failed++
		t.Error(err)
	}
	if failed > 0 {
		t.Fatalf("%d of %d concurrent sessions failed", failed, n)
	}
	// The server must still serve new clients afterwards.
	e.mustMount(t, "alice", "alicepw")
}
