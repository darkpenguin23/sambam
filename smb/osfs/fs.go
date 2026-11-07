package osfs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sambam/sambam/smb/vfs"
)

type OpenFile struct {
	path        string
	isDir       bool
	f           *os.File
	h           vfs.VfsHandle
	dirPos      int
	dirBuffer   []vfs.DirInfo
	readOnce    sync.Once
	dirReadOnce sync.Once
	mode        string
	statsMu     sync.Mutex
	readBytes   uint64
	writeBytes  uint64
	hadRead     bool
	hadWrite    bool
	closing     uint32
	ioWG        sync.WaitGroup
}

// PassthroughFS exposes a host directory as a VFS. Every filesystem access
// goes through an os.Root, so client-supplied names can never resolve to a
// location outside rootPath — neither via ".." nor via symlinks (including
// symlinks created by clients). OpenFile.path is always relative to the root.
type PassthroughFS struct {
	rootPath  string
	readOnly  bool
	openFiles sync.Map

	rootMu sync.Mutex
	root   atomic.Pointer[os.Root]

	// Debug callbacks
	OnCreate    func(path string, isDir bool)
	OnOverwrite func(path string)
	OnDelete    func(path string)
	OnRead      func(path string)
	OnOpen      func(path string, mode string)
	OnClose     func(path string, mode string, readBytes uint64, writeBytes uint64)
	OnSlowOp    func(op string, path string, duration time.Duration, size int)
	OnDirOpen   func(path string)
	OnDirRead   func(path string)
}

func (fs *PassthroughFS) BasePath() string {
	return fs.rootPath
}

func (fs *PassthroughFS) IsReadOnly() bool {
	return fs.readOnly
}

// openRoot returns the share root, opening it on first use. Opening lazily
// keeps NewPassthroughFS infallible and lets a share directory that does not
// exist yet at startup become usable once it is created.
func (fs *PassthroughFS) openRoot() (*os.Root, error) {
	if r := fs.root.Load(); r != nil {
		return r, nil
	}
	fs.rootMu.Lock()
	defer fs.rootMu.Unlock()
	if r := fs.root.Load(); r != nil {
		return r, nil
	}
	r, err := os.OpenRoot(fs.rootPath)
	if err != nil {
		return nil, err
	}
	fs.root.Store(r)
	return r, nil
}

// relName converts a VFS path ("/", "dir/file", "/dir/file/") into a name
// relative to the share root as expected by os.Root ("." for the root).
// ".." is cleaned lexically; anything that still escapes is rejected by
// os.Root.
func relName(p string) string {
	return path.Join(".", p)
}

// displayPath is the share-relative path handed to the debug callbacks;
// the share root is reported as "" as before.
func displayPath(rel string) string {
	if rel == "." {
		return ""
	}
	return rel
}

func (fs *PassthroughFS) loadOpen(handle vfs.VfsHandle) (*OpenFile, error) {
	if handle == 0 {
		return nil, fmt.Errorf("bad handle")
	}
	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return nil, fmt.Errorf("bad handle")
	}
	return v.(*OpenFile), nil
}

func openMode(flags int) string {
	if flags&os.O_RDWR != 0 {
		return "read-write"
	}
	if flags&os.O_WRONLY != 0 {
		return "write"
	}
	return "read"
}

func NewPassthroughFS(rootPath string, readOnly bool) *PassthroughFS {
	return &PassthroughFS{
		rootPath:  rootPath,
		readOnly:  readOnly,
		openFiles: sync.Map{},
	}
}

func (fs *PassthroughFS) GetAttr(handle vfs.VfsHandle) (*vfs.Attributes, error) {
	r, err := fs.openRoot()
	if err != nil {
		return nil, err
	}
	p := "."
	if handle != 0 {
		v, ok := fs.openFiles.Load(handle)
		if !ok {
			return nil, fmt.Errorf("bad handle")
		}
		open := v.(*OpenFile)
		if open.f != nil {
			if info, err := open.f.Stat(); err == nil {
				return fileInfoToAttr(info)
			}
		}
		p = open.path
	}

	info, err := r.Lstat(p)
	if err != nil {
		return nil, err
	}

	return fileInfoToAttr(info)
}

func (fs *PassthroughFS) SetAttr(handle vfs.VfsHandle, a *vfs.Attributes) (*vfs.Attributes, error) {
	if fs.readOnly {
		return nil, fmt.Errorf("read-only share")
	}

	if handle == 0 {
		return nil, fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return nil, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	r, err := fs.openRoot()
	if err != nil {
		return nil, err
	}

	oldAttrs, err := fs.GetAttr(handle)
	if err != nil {
		return nil, fmt.Errorf("failed to read attributes")
	}

	atime, atimeSet := a.GetAccessTime()
	if !atimeSet {
		atime, _ = oldAttrs.GetAccessTime()
	}
	mtime, mtimeSet := a.GetLastDataModificationTime()
	if !mtimeSet {
		mtime, _ = oldAttrs.GetLastDataModificationTime()
	}

	if atimeSet || mtimeSet {
		r.Chtimes(open.path, atime, mtime)
	}

	if mode, mSet := a.GetUnixMode(); mSet {
		// Lstat to check if symlink — can't chmod symlinks on Linux
		if info, err := r.Lstat(open.path); err == nil && info.Mode()&os.ModeSymlink == 0 {
			r.Chmod(open.path, os.FileMode(mode&0777))
		}
	}

	uid, uidSet := a.GetUID()
	gid, gidSet := a.GetGID()
	if uidSet || gidSet {
		chownUid := -1
		chownGid := -1
		if uidSet {
			chownUid = int(uid)
		}
		if gidSet {
			chownGid = int(gid)
		}
		r.Lchown(open.path, chownUid, chownGid)
	}

	return nil, nil
}

// diskUsage is the size of the filesystem holding a share, in blockSize units.
type diskUsage struct {
	blockSize, blocks, free, avail, files, freeFiles uint64
}

// StatFS reports the real size and free space of the filesystem holding the
// share (it used to report fixed values: about 40 GB total and 4 GB free,
// so clients refused larger copies or showed wrong free space).
func (fs *PassthroughFS) StatFS(handle vfs.VfsHandle) (*vfs.FSAttributes, error) {
	u, err := diskStats(fs.rootPath)
	if err != nil || u.blockSize == 0 {
		// Fall back to the former fixed values.
		u = diskUsage{blockSize: 4096, blocks: 10000000, free: 1000000, avail: 1000000, files: 1000000, freeFiles: 1000000}
	}
	a := vfs.FSAttributes{}
	a.SetAvailableBlocks(u.avail)
	a.SetBlockSize(u.blockSize)
	a.SetBlocks(u.blocks)
	a.SetFiles(u.files)
	a.SetFreeBlocks(u.free)
	a.SetFreeFiles(u.freeFiles)
	a.SetIOSize(4096)
	return &a, nil
}

func (fs *PassthroughFS) FSync(handle vfs.VfsHandle) error {
	if handle == 0 {
		return fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	return open.f.Sync()
}

func (fs *PassthroughFS) Flush(handle vfs.VfsHandle) error {
	return nil
}

func randHandle() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return binary.LittleEndian.Uint64(b[:])
}

func (fs *PassthroughFS) Open(p string, flags int, mode int) (vfs.VfsHandle, error) {
	r, err := fs.openRoot()
	if err != nil {
		return 0, err
	}
	name := relName(p)
	fileMode := openMode(flags)

	// Check if file exists before opening (to detect creation)
	isCreate := flags&os.O_CREATE != 0
	_, existedBefore := r.Stat(name)

	// If read-only, strip every write/create flag. Other bits (e.g. the
	// O_PATH|O_NOFOLLOW used to open a symlink itself) are kept.
	if fs.readOnly {
		flags &^= os.O_WRONLY | os.O_RDWR | os.O_CREATE | os.O_TRUNC | os.O_APPEND | os.O_EXCL
		fileMode = "read"
	}

	f, err := r.OpenFile(name, flags, os.FileMode(mode))
	if err != nil {
		return 0, err
	}

	// Call OnCreate if file was newly created, OnOverwrite if replaced
	if isCreate && existedBefore != nil && fs.OnCreate != nil {
		fs.OnCreate(p, false)
	} else if isCreate && existedBefore == nil && flags&os.O_TRUNC != 0 && fs.OnOverwrite != nil {
		fs.OnOverwrite(p)
	}

	h := vfs.VfsHandle(randHandle())
	fs.openFiles.Store(h, &OpenFile{f: f, h: h, path: name, mode: fileMode})

	if fs.OnOpen != nil {
		fs.OnOpen(displayPath(name), fileMode)
	}

	return h, nil
}

func (fs *PassthroughFS) Close(handle vfs.VfsHandle) error {
	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	atomic.StoreUint32(&open.closing, 1)
	open.ioWG.Wait()

	if open.f != nil {
		open.f.Close()
	}

	open.statsMu.Lock()
	readBytes := open.readBytes
	writeBytes := open.writeBytes
	hadRead := open.hadRead
	hadWrite := open.hadWrite
	mode := open.mode
	open.statsMu.Unlock()

	if fs.OnClose != nil && (hadRead || hadWrite) {
		fs.OnClose(displayPath(open.path), mode, readBytes, writeBytes)
	}

	fs.openFiles.Delete(handle)

	return nil
}

func (fs *PassthroughFS) Lookup(handle vfs.VfsHandle, name string) (*vfs.Attributes, error) {
	r, err := fs.openRoot()
	if err != nil {
		return nil, err
	}
	p := "."
	if handle != 0 {
		v, ok := fs.openFiles.Load(handle)
		if !ok {
			return nil, fmt.Errorf("bad handle")
		}
		open := v.(*OpenFile)
		p = open.path
	}

	target := relName(path.Join(p, name))
	// For share root lookups, follow symlinks so roots like /bin -> /usr/bin
	// are treated as directories by SMB clients.
	lookup := r.Lstat
	if target == "." {
		lookup = r.Stat
	}
	info, err := lookup(target)
	if err != nil {
		return nil, err
	}

	return fileInfoToAttr(info)
}

func (fs *PassthroughFS) Mkdir(p string, mode int) (*vfs.Attributes, error) {
	if fs.readOnly {
		return nil, fmt.Errorf("read-only share")
	}

	r, err := fs.openRoot()
	if err != nil {
		return nil, err
	}
	name := relName(p)
	if err := r.Mkdir(name, os.FileMode(mode)); err != nil {
		return nil, err
	}

	if fs.OnCreate != nil {
		fs.OnCreate(p, true)
	}

	info, err := r.Stat(name)
	if err != nil {
		return nil, err
	}

	return fileInfoToAttr(info)
}

func (fs *PassthroughFS) Read(handle vfs.VfsHandle, buf []byte, offset uint64, flags int) (int, error) {
	if handle == 0 {
		return 0, io.EOF
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return 0, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	if atomic.LoadUint32(&open.closing) != 0 {
		return 0, fmt.Errorf("bad handle")
	}
	open.ioWG.Add(1)
	if atomic.LoadUint32(&open.closing) != 0 {
		open.ioWG.Done()
		return 0, fmt.Errorf("bad handle")
	}
	defer open.ioWG.Done()

	start := time.Now()
	n, err := open.f.ReadAt(buf, int64(offset))
	duration := time.Since(start)
	if n > 0 && fs.OnRead != nil {
		relPath := displayPath(open.path)
		open.readOnce.Do(func() {
			fs.OnRead(relPath)
		})
	}
	if n > 0 {
		open.statsMu.Lock()
		open.readBytes += uint64(n)
		open.hadRead = true
		open.statsMu.Unlock()
	}
	if fs.OnSlowOp != nil && duration > 200*time.Millisecond {
		fs.OnSlowOp("read", displayPath(open.path), duration, n)
	}
	// If file was closed during read (race with Close), return EOF
	if err != nil && (os.IsNotExist(err) || isClosedError(err)) {
		return n, io.EOF
	}
	return n, err
}

// isClosedError checks if the error is due to a closed file descriptor
func isClosedError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "bad file descriptor") ||
		strings.Contains(errStr, "file already closed")
}

func (fs *PassthroughFS) Write(handle vfs.VfsHandle, buf []byte, offset uint64, flags int) (int, error) {
	if fs.readOnly {
		return 0, fmt.Errorf("read-only share")
	}

	if handle == 0 {
		return 0, fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return 0, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	if atomic.LoadUint32(&open.closing) != 0 {
		return 0, fmt.Errorf("bad handle")
	}
	open.ioWG.Add(1)
	if atomic.LoadUint32(&open.closing) != 0 {
		open.ioWG.Done()
		return 0, fmt.Errorf("bad handle")
	}
	defer open.ioWG.Done()

	start := time.Now()
	n, err := open.f.WriteAt(buf, int64(offset))
	duration := time.Since(start)
	if n > 0 {
		open.statsMu.Lock()
		open.writeBytes += uint64(n)
		open.hadWrite = true
		open.statsMu.Unlock()
	}
	if fs.OnSlowOp != nil && duration > 200*time.Millisecond {
		fs.OnSlowOp("write", displayPath(open.path), duration, n)
	}
	return n, err
}

func (fs *PassthroughFS) OpenDir(p string) (vfs.VfsHandle, error) {
	r, err := fs.openRoot()
	if err != nil {
		return 0, err
	}
	name := relName(p)
	f, err := r.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return 0, err
	}

	h := vfs.VfsHandle(randHandle())
	fs.openFiles.Store(h, &OpenFile{f: f, h: h, path: name, isDir: true, mode: "dir"})

	if fs.OnDirOpen != nil {
		fs.OnDirOpen(displayPath(name))
	}

	return h, nil
}

func (fs *PassthroughFS) ReadDir(handle vfs.VfsHandle, pos int, maxEntries int) ([]vfs.DirInfo, error) {
	if handle == 0 {
		return nil, nil
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return nil, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	if open.isDir && fs.OnDirRead != nil {
		open.dirReadOnce.Do(func() {
			fs.OnDirRead(displayPath(open.path))
		})
	}

	var results []vfs.DirInfo
	if pos != 0 {
		open.f.Seek(0, 0)
		open.dirPos = 0
		open.dirBuffer = nil
	}

	if open.dirPos == 0 {
		attrs, err := fs.GetAttr(open.h)
		if err != nil {
			return nil, err
		}

		results = append(results,
			vfs.DirInfo{Name: ".", Attributes: *attrs},
			vfs.DirInfo{Name: "..", Attributes: *attrs})
	}

	// First drain any buffered entries from a previous read
	if len(open.dirBuffer) > 0 {
		if len(open.dirBuffer) <= maxEntries {
			results = append(results, open.dirBuffer...)
			open.dirBuffer = nil
		} else {
			results = append(results, open.dirBuffer[:maxEntries]...)
			open.dirBuffer = open.dirBuffer[maxEntries:]
			open.dirPos = 1
			return results, nil
		}
		maxEntries -= len(results)
		if maxEntries <= 0 {
			open.dirPos = 1
			return results, nil
		}
	}

	start := time.Now()
	entries, err := open.f.ReadDir(maxEntries)
	duration := time.Since(start)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if fs.OnSlowOp != nil && duration > 200*time.Millisecond {
		fs.OnSlowOp("query-dir", displayPath(open.path), duration, len(entries))
	}

	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		attrs, attrErr := fileInfoToAttr(info)
		if attrErr != nil {
			continue
		}
		results = append(results, vfs.DirInfo{Name: entry.Name(), Attributes: *attrs})
	}
	open.dirPos = 1

	if err == io.EOF && len(results) == 0 {
		return nil, io.EOF
	}

	return results, nil
}

// PutBackDirEntries stores unconsumed directory entries for the next ReadDir call.
func (fs *PassthroughFS) PutBackDirEntries(handle vfs.VfsHandle, entries []vfs.DirInfo) {
	if handle == 0 || len(entries) == 0 {
		return
	}
	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return
	}
	open := v.(*OpenFile)
	open.dirBuffer = append(entries, open.dirBuffer...)
}

func (fs *PassthroughFS) Readlink(handle vfs.VfsHandle) (string, error) {
	if handle == 0 {
		return "", fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return "", fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	r, err := fs.openRoot()
	if err != nil {
		return "", err
	}
	return r.Readlink(open.path)
}

func (fs *PassthroughFS) Unlink(handle vfs.VfsHandle) error {
	if fs.readOnly {
		return fmt.Errorf("read-only share")
	}

	if handle == 0 {
		return fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)

	r, err := fs.openRoot()
	if err != nil {
		return err
	}

	err = r.Remove(open.path)
	if err == nil && fs.OnDelete != nil {
		fs.OnDelete(displayPath(open.path))
	}
	return err
}

func (fs *PassthroughFS) Truncate(handle vfs.VfsHandle, length uint64) error {
	if fs.readOnly {
		return fmt.Errorf("read-only share")
	}

	v, ok := fs.openFiles.Load(handle)
	if !ok {
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	if open.f != nil {
		return open.f.Truncate(int64(length))
	}
	r, err := fs.openRoot()
	if err != nil {
		return err
	}
	f, err := r.OpenFile(open.path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(int64(length))
}

func (fs *PassthroughFS) Rename(from vfs.VfsHandle, to string, flags int) error {
	if fs.readOnly {
		return fmt.Errorf("read-only share")
	}

	if from == 0 {
		return fmt.Errorf("bad handle")
	}

	v, ok := fs.openFiles.Load(from)
	if !ok {
		return fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	r, err := fs.openRoot()
	if err != nil {
		return err
	}

	newPath := relName(to)
	if flags == 0 {
		if _, err := r.Lstat(newPath); err == nil {
			return fmt.Errorf("already exists")
		}
	}

	if err := r.Rename(open.path, newPath); err != nil {
		return err
	}
	open.path = newPath
	return nil
}

func (fs *PassthroughFS) Symlink(targetHandle vfs.VfsHandle, target string, flag int) (*vfs.Attributes, error) {
	if fs.readOnly {
		return nil, fmt.Errorf("read-only share")
	}
	if targetHandle == 0 {
		return nil, fmt.Errorf("bad handle")
	}
	v, ok := fs.openFiles.Load(targetHandle)
	if !ok {
		return nil, fmt.Errorf("bad handle")
	}
	open := v.(*OpenFile)
	linkPath := open.path
	r, err := fs.openRoot()
	if err != nil {
		return nil, err
	}

	// Close and remove the placeholder file created by the CREATE request
	if open.f != nil {
		open.f.Close()
		open.f = nil
	}
	r.Remove(linkPath)

	// Create the actual symlink. The target is stored verbatim (clients
	// resolve symlinks themselves); os.Root guarantees the server never
	// follows it outside the share.
	if err := r.Symlink(target, linkPath); err != nil {
		return nil, err
	}

	info, err := r.Lstat(linkPath)
	if err != nil {
		return nil, err
	}
	return fileInfoToAttr(info)
}

func (fs *PassthroughFS) Link(vfs.VfsNode, vfs.VfsNode, string) (*vfs.Attributes, error) {
	return nil, fmt.Errorf("hard links not supported")
}

func fileInfoToAttr(stat os.FileInfo) (*vfs.Attributes, error) {
	sysStat, ok := vfs.CompatStat(stat)
	if !ok {
		return nil, fmt.Errorf("failed to convert stat")
	}

	a := vfs.Attributes{}
	a.SetInodeNumber(sysStat.Ino)
	a.SetSizeBytes(uint64(stat.Size()))
	a.SetDiskSizeBytes(uint64(sysStat.Blocks * 512))
	a.SetUnixMode(uint32(stat.Mode()))
	a.SetPermissions(vfs.NewPermissionsFromMode(uint32(stat.Mode().Perm())))
	a.SetUID(sysStat.Uid)
	a.SetGID(sysStat.Gid)
	a.SetLinkCount(sysStat.Nlink)
	a.SetAccessTime(sysStat.Atime)
	a.SetLastDataModificationTime(stat.ModTime())
	a.SetBirthTime(sysStat.Btime)
	a.SetLastStatusChangeTime(sysStat.Ctime)

	if stat.IsDir() {
		a.SetFileType(vfs.FileTypeDirectory)
	} else if stat.Mode()&os.ModeSymlink != 0 {
		a.SetFileType(vfs.FileTypeSymlink)
	} else {
		a.SetFileType(vfs.FileTypeRegularFile)
	}

	return &a, nil
}
