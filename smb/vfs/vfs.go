package vfs

type VfsNode uint64
type VfsHandle uint64

const VFS_ROOT_NODE = VfsNode(1)

type EntryReply struct {
	Node       VfsNode
	Generation uint64
	Attrs      Attributes
}

type DirInfo struct {
	Name string
	Attributes
}

type VFSFileSystem interface {
	BasePath() string

	GetAttr(VfsHandle) (*Attributes, error)
	SetAttr(VfsHandle, *Attributes) (*Attributes, error)

	StatFS(VfsHandle) (*FSAttributes, error)

	FSync(VfsHandle) error

	Flush(VfsHandle) error

	//Mknod(VfsNode, string, int, int) (*EntryReply, error)

	//Create(VfsNode, string, int, int) (*EntryReply, VfsHandle, error)
	Open(string, int, int) (VfsHandle, error)
	Close(VfsHandle) error

	Lookup(VfsHandle, string) (*Attributes, error)

	Mkdir(string, int) (*Attributes, error)

	Read(VfsHandle, []byte, uint64, int) (int, error)
	Write(VfsHandle, []byte, uint64, int) (int, error)

	OpenDir(string) (VfsHandle, error)
	ReadDir(VfsHandle, int, int) ([]DirInfo, error)
	PutBackDirEntries(VfsHandle, []DirInfo)

	Readlink(VfsHandle) (string, error)

	Unlink(VfsHandle) error

	//Rmdir(VfsNode, string) error

	Truncate(VfsHandle, uint64) error

	Rename(VfsHandle, string, int) error

	Symlink(VfsHandle, string, int) (*Attributes, error)
	Link(VfsNode, VfsNode, string) (*Attributes, error)

	Listxattr(VfsHandle) ([]string, error)
	Getxattr(VfsHandle, string, []byte) (int, error)
	Setxattr(VfsHandle, string, []byte) error
	Removexattr(VfsHandle, string) error

	//RegisterNotify(VfsHandle, chan *NotifyEvent) error
	//RemoveNotify(VfsHandle) error
}

// CaseResolver is implemented by filesystems whose names are case-sensitive
// on disk (Linux) but have to be looked up case-insensitively, as Windows
// clients expect. ResolveCase returns p with every component that exists
// under a different spelling replaced by the name stored on disk; components
// that do not exist are kept as given, so a new file is created with the
// client's spelling. A path that exists as given is returned unchanged.
type CaseResolver interface {
	ResolveCase(p string) string
}

// ShareMask is a bitmask of operations that are permitted
type ShareMask uint32

const (
	// ShareMaskRead permits calls to VirtualRead().
	ShareMaskRead ShareMask = 1 << iota
	// ShareMaskWrite permits calls to VirtualWrite().
	ShareMaskWrite
)

type NotifyEvent struct {
	EvType uint8
	Handle VfsHandle
	Name   string
}
