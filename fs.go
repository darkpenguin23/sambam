package main

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

type PassthroughFS struct {
	rootPath  string
	readOnly  bool
	openFiles sync.Map

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

func (fs *PassthroughFS) relativePath(fullPath string) string {
	rel := strings.TrimPrefix(fullPath, fs.rootPath)
	rel = strings.TrimPrefix(rel, "/")
	return rel
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
	p := fs.rootPath
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

	info, err := os.Lstat(p)
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
		os.Chtimes(open.path, atime, mtime)
	}

	if mode, mSet := a.GetUnixMode(); mSet {
		// Lstat to check if symlink — can't chmod symlinks on Linux
		if info, err := os.Lstat(open.path); err == nil && info.Mode()&os.ModeSymlink == 0 {
			os.Chmod(open.path, os.FileMode(mode&0777))
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
		os.Lchown(open.path, chownUid, chownGid)
	}

	return nil, nil
}

func (fs *PassthroughFS) StatFS(handle vfs.VfsHandle) (*vfs.FSAttributes, error) {
	a := vfs.FSAttributes{}
	// Return some reasonable defaults
	a.SetAvailableBlocks(1000000)
	a.SetBlockSize(4096)
	a.SetBlocks(10000000)
	a.SetFiles(1000000)
	a.SetFreeBlocks(1000000)
	a.SetFreeFiles(1000000)
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
	fullPath := path.Join(fs.rootPath, p)
	fileMode := openMode(flags)

	// Check if file exists before opening (to detect creation)
	isCreate := flags&os.O_CREATE != 0
	_, existedBefore := os.Stat(fullPath)

	// If read-only, force read-only flags
	if fs.readOnly {
		flags = os.O_RDONLY
		fileMode = "read"
	}

	f, err := os.OpenFile(fullPath, flags, os.FileMode(mode))
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
	fs.openFiles.Store(h, &OpenFile{f: f, h: h, path: fullPath, mode: fileMode})

	if fs.OnOpen != nil {
		fs.OnOpen(fs.relativePath(fullPath), fileMode)
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
		fs.OnClose(fs.relativePath(open.path), mode, readBytes, writeBytes)
	}

	fs.openFiles.Delete(handle)

	return nil
}

func (fs *PassthroughFS) Lookup(handle vfs.VfsHandle, name string) (*vfs.Attributes, error) {
	p := fs.rootPath
	if handle != 0 {
		v, ok := fs.openFiles.Load(handle)
		if !ok {
			return nil, fmt.Errorf("bad handle")
		}
		open := v.(*OpenFile)
		p = open.path
	}

	fullPath := path.Join(p, name)
	// For share root lookups, follow symlinks so roots like /bin -> /usr/bin
	// are treated as directories by SMB clients.
	lookup := os.Lstat
	if handle == 0 && path.Clean(fullPath) == path.Clean(fs.rootPath) {
		lookup = os.Stat
	}
	info, err := lookup(fullPath)
	if err != nil {
		return nil, err
	}

	return fileInfoToAttr(info)
}

func (fs *PassthroughFS) Mkdir(p string, mode int) (*vfs.Attributes, error) {
	if fs.readOnly {
		return nil, fmt.Errorf("read-only share")
	}

	fullPath := path.Join(fs.rootPath, p)
	if err := os.Mkdir(fullPath, os.FileMode(mode)); err != nil {
		return nil, err
	}

	if fs.OnCreate != nil {
		fs.OnCreate(p, true)
	}

	info, err := os.Stat(fullPath)
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
		relPath := fs.relativePath(open.path)
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
		fs.OnSlowOp("read", fs.relativePath(open.path), duration, n)
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
		fs.OnSlowOp("write", fs.relativePath(open.path), duration, n)
	}
	return n, err
}

func (fs *PassthroughFS) OpenDir(p string) (vfs.VfsHandle, error) {
	fullPath := path.Join(fs.rootPath, p)
	f, err := os.OpenFile(fullPath, os.O_RDONLY, 0)
	if err != nil {
		return 0, err
	}

	h := vfs.VfsHandle(randHandle())
	fs.openFiles.Store(h, &OpenFile{f: f, h: h, path: fullPath, isDir: true, mode: "dir"})

	if fs.OnDirOpen != nil {
		fs.OnDirOpen(fs.relativePath(fullPath))
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
			fs.OnDirRead(fs.relativePath(open.path))
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
		fs.OnSlowOp("query-dir", fs.relativePath(open.path), duration, len(entries))
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
	return os.Readlink(open.path)
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

	// Get relative path for callback
	relPath := strings.TrimPrefix(open.path, fs.rootPath)
	relPath = strings.TrimPrefix(relPath, "/")

	err := os.Remove(open.path)
	if err == nil && fs.OnDelete != nil {
		fs.OnDelete(relPath)
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
	return os.Truncate(open.path, int64(length))
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

	if flags == 0 {
		if _, err := os.Lstat(path.Join(fs.rootPath, to)); err == nil {
			return fmt.Errorf("already exists")
		}
	}

	newPath := path.Join(fs.rootPath, to)
	if err := os.Rename(open.path, newPath); err != nil {
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

	// Close and remove the placeholder file created by the CREATE request
	if open.f != nil {
		open.f.Close()
		open.f = nil
	}
	os.Remove(linkPath)

	// Create the actual symlink
	if err := os.Symlink(target, linkPath); err != nil {
		return nil, err
	}

	info, err := os.Lstat(linkPath)
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
