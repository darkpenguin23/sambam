package smb2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	. "github.com/sambam/sambam/smb/internal/erref"
	. "github.com/sambam/sambam/smb/internal/smb2"
	"github.com/sambam/sambam/smb/internal/utf16le"
	"github.com/sambam/sambam/smb/vfs"
	log "github.com/sirupsen/logrus"
)

var (
	dirQueryLogMu       sync.Mutex
	dirQueryLast        = map[string]time.Time{}
	dirQueryDedupWindow = 300 * time.Millisecond
)

func shouldLogDirQueryDebug(key string) bool {
	now := time.Now()

	dirQueryLogMu.Lock()
	defer dirQueryLogMu.Unlock()

	last, ok := dirQueryLast[key]
	if ok && now.Sub(last) < dirQueryDedupWindow {
		return false
	}
	dirQueryLast[key] = now
	return true
}

func (t *fileTree) isUserReadOnly() bool {
	if t.session == nil || t.session.conn == nil || t.session.conn.serverCtx == nil {
		return false
	}
	return t.session.conn.serverCtx.isUserReadOnly(t.session.username)
}

func (t *fileTree) isShareReadOnly() bool {
	type rofs interface {
		IsReadOnly() bool
	}
	if fs, ok := t.fs.(rofs); ok {
		return fs.IsReadOnly()
	}
	return false
}

type fileTree struct {
	treeConn
	fs vfs.VFSFileSystem

	openFiles      map[uint64]bool
	aaplExtensions bool

	ioReadSem  chan struct{}
	ioWriteSem chan struct{}
}

func (t *fileTree) getTree() *treeConn {
	return &t.treeConn
}

func (t *fileTree) create(ctx *compoundContext, pkt []byte) error {
	log.Tracef("fileTreeCreate")

	c := t.session.conn

	res, err := accept(SMB2_CREATE, pkt)
	if err != nil {
		return err
	}

	r := CreateRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken create format"}
	}
	log.Tracef(
		"create req: name=%q access=0x%x share=0x%x opts=0x%x disp=%d attrs=0x%x oplock=%d imp=%d",
		r.Name(),
		r.DesiredAccess(),
		r.ShareAccess(),
		r.CreateOptions(),
		r.CreateDisposition(),
		r.FileAttributes(),
		r.RequestedOplockLevel(),
		r.ImpersonationLevel(),
	)

	log.Tracef("create name: %s, options %d, disp %d", r.Name(), r.CreateOptions(), r.CreateDisposition())

	rsp := new(CreateResponse)
	rsp.FileId = &FileId{}
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	name := r.Name()
	if name == "" {
		name = "/"
	} else {
		var ok bool
		if name, ok = shareRelativePath(name); !ok {
			log.Warnf("deny create with '..' path component user=%s path=%q", t.session.username, r.Name())
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_OBJECT_PATH_SYNTAX_BAD))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
	}

	isEA := IsEA(name)
	eaKey := ""
	if isEA {
		name, eaKey = SplitEA(name)
	}
	shareReadOnly := t.isShareReadOnly()

	if r.SmbCreateFlags() != 0 {
		log.Errorf("Create flags: %d", r.SmbCreateFlags())
	}

	attrs, err := t.fs.Lookup(0, name)
	fileExists := err == nil
	isDir := fileExists && attrs.GetFileType() == vfs.FileTypeDirectory
	flags := 0
	createDir := r.CreateOptions()&FILE_DIRECTORY_FILE != 0
	err = nil
	isSymlink := fileExists && (attrs.GetFileType() == vfs.FileTypeSymlink) && (r.CreateOptions()&FILE_OPEN_REPARSE_POINT == 0)
	d := r.CreateDisposition()
	deleteOnClose := r.CreateOptions()&FILE_DELETE_ON_CLOSE != 0
	if (t.isUserReadOnly() || shareReadOnly) && deleteOnClose {
		log.Warnf("deny create delete-on-close on read-only context user=%s path=%s", t.session.username, name)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}
	if t.isUserReadOnly() || shareReadOnly {
		access := r.DesiredAccess()
		wantsWrite := access&(FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_ATTRIBUTES|FILE_WRITE_EA|DELETE|WRITE_DAC|WRITE_OWNER|GENERIC_WRITE) != 0
		createsOrMutates := d != FILE_OPEN || createDir
		if wantsWrite || createsOrMutates {
			log.Warnf("deny write create on read-only context user=%s path=%s", t.session.username, name)
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
	}

	if fileExists && !isDir && createDir {
		status := STATUS_OBJECT_NAME_COLLISION
		if d != FILE_CREATE {
			status = STATUS_NOT_A_DIRECTORY
		}
		log.Tracef("create dir probe on non-directory path: %s", name)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(status))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if isEA && !fileExists {
		log.Tracef("attempt to read ea from non-exsiting file: %s", name)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NO_SUCH_FILE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	action := FILE_OPENED
	switch d {
	case FILE_OPEN_IF:
		flags = os.O_CREATE
		if !fileExists && createDir {
			_, err = t.fs.Mkdir(name, 0777)
			isDir = true
		}

		if !fileExists {
			action = FILE_CREATED
		}
	case FILE_OPEN:
		if !fileExists {
			log.Tracef("Open: doesn't exist: %s", r.Name())
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NO_SUCH_FILE))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
	case FILE_CREATE:
		if fileExists {
			log.Tracef("Open: already exists: %s", r.Name())
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_OBJECT_NAME_COLLISION))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}

		if createDir {
			_, err = t.fs.Mkdir(name, 0777)
			isDir = true
		}
		action = FILE_CREATED
		flags = os.O_CREATE | os.O_EXCL
	case FILE_OVERWRITE:
		if !fileExists {
			log.Errorf("Open: doesn't exists: overwrite: %s", r.Name())
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NO_SUCH_FILE))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
		action = FILE_OVERWRITTEN
		flags = os.O_CREATE | os.O_TRUNC
	case FILE_OVERWRITE_IF:
		action = FILE_CREATED
		if fileExists {
			action = FILE_OVERWRITTEN
		}
		flags = os.O_CREATE | os.O_TRUNC
	case FILE_SUPERSEDE:
		action = FILE_CREATED
		if fileExists {
			action = FILE_SUPERSEDED
		}
		flags = os.O_CREATE | os.O_TRUNC
	}

	if err != nil {
		log.Errorf("mkdir() failed")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	// Never grant exclusive oplocks — we have no infrastructure to send
	// oplock break notifications.  Without breaks, an exclusive oplock
	// causes "invalid handle" errors on Windows 11 UAC elevation because
	// the elevated process cannot open the file while the non-elevated
	// explorer still holds the oplock.
	lockLevel := uint8(SMB2_OPLOCK_LEVEL_NONE)
	lockState := LOCKSTATE_NONE

	access := r.DesiredAccess()
	var h vfs.VfsHandle
	if !isDir {
		if access&(FILE_WRITE_DATA|GENERIC_WRITE) != 0 {
			flags |= os.O_RDWR
		} else {
			flags |= os.O_RDONLY
		}

		if isEA {
			flags = 0
		}

		if isSymlink {
			// Always open symlinks with O_PATH|O_NOFOLLOW — let client resolve
			flags = 0x200000 | 0x20000 // O_PATH | O_NOFOLLOW
		} else if r.CreateOptions()&FILE_OPEN_REPARSE_POINT != 0 && fileExists && attrs.GetFileType() == vfs.FileTypeSymlink {
			// FILE_OPEN_REPARSE_POINT should only force path-open for actual reparse points.
			// Applying O_PATH to regular files breaks data reads (all reads return EOF).
			flags |= 0x200000 | 0x20000 // O_PATH | O_NOFOLLOW — open symlink itself
		}

		h, err = t.fs.Open(name, flags, 0644)
		log.Tracef("open file: %d, err %v", flags, err)
	} else {
		h, err = t.fs.OpenDir(name)
		log.Tracef("open dir, err %v", err)
	}

	if err == nil {
		attrs, err = t.fs.GetAttr(h)
	}
	if err != nil {
		log.Errorf("open failed: %s, %v, co %x", name, err, r.CreateOptions())
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if isEA {
		if status, err := t.handleCreateEA(d, h, eaKey); err != nil {
			log.Tracef("handleCreateEA failed, disp %d, key %s", d, eaKey)
			t.fs.Close(h)
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, status)
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
	}

	node := attrs.GetInodeNumber()
	rsp.FileId.SetHandleId(uint64(h))
	rsp.FileId.SetNodeId(node)

	rsp.CreateAction = uint32(action)
	rsp.FileAttributes = PermissionsFromVfs(attrs, name, t.conn.serverCtx.hideDotfiles)
	rsp.CreationTime = BirthTimeFromVfs(attrs)
	rsp.LastAccessTime = AccessTimeFromVfs(attrs)
	rsp.LastWriteTime = ModifiedTimeFromVfs(attrs)
	rsp.ChangeTime = ChangeTimeFromVfs(attrs)
	if !isEA {
		rsp.EndofFile = int64(SizeFromVfs(attrs))
		rsp.AllocationSize = int64(DiskSizeFromVfs(attrs))
	} else {
		len, _ := t.fs.Getxattr(h, eaKey, nil)
		rsp.EndofFile = int64(len)
		rsp.AllocationSize = int64(len)
	}

	open := &Open{
		fs:                t.fs,
		fileId:            rsp.FileId.HandleId(),
		durableFileId:     rsp.FileId.NodeId(),
		session:           t.session,
		tree:              &t.treeConn,
		oplockLevel:       lockLevel,
		grantedAccess:     access,
		oplockState:       lockState,
		pathName:          name,
		createOptions:     r.CreateOptions(),
		createDisposition: r.CreateDisposition(),
		fileAttributes:    rsp.FileAttributes,
		isEa:              isEA,
		eaKey:             eaKey,
		isSymlink:         isSymlink,
		deleteAfterClose:  (r.CreateOptions()&FILE_DELETE_ON_CLOSE != 0),
	}

	cc := r.CreateContexts()
	for len(cc) > 0 {
		res := CreateContextDecoder(cc)
		ccName := res.Name()
		log.Tracef("create context: name=%q len=%d", ccName, len(ccName))
		switch ccName {
		case "MxAc":
			if enc, err := t.handleMaxAccessCC(attrs); err == nil && enc != nil {
				rsp.Contexts = append(rsp.Contexts, enc)
			}
		case "AAPL":
			t.aaplExtensions = true
			t.session.conn.setClientOS("macOS", "AAPL create context", clientOSPrioAAPL)
			if enc, err := t.handleAAPLCC(res.Buffer()); err == nil {
				rsp.Contexts = append(rsp.Contexts, enc)
			}
		case "DH2Q":
			if enc, err := t.handleDH2Q(res.Buffer(), open); err == nil && enc != nil {
				rsp.Contexts = append(rsp.Contexts, enc)
			}
		case "RqLs":
			if enc, err := t.handleRqLs(res.Buffer(), open); err == nil && enc != nil {
				rsp.Contexts = append(rsp.Contexts, enc)
				// If we reply with a lease, mark oplock as LEASE.
				if r.RequestedOplockLevel() == SMB2_OPLOCK_LEVEL_LEASE {
					lockLevel = SMB2_OPLOCK_LEVEL_LEASE
				}
			}
		case "QFid":
			if enc, err := t.handleQFid(res.Buffer(), open); err == nil {
				rsp.Contexts = append(rsp.Contexts, enc)
			}
		default:
			// Check for POSIX create context (16-byte GUID tag)
			if t.session.conn.posixExtensions && len(ccName) == 16 && ccName == string(SMB2_CREATE_TAG_POSIX) {
				log.Tracef("POSIX create context matched")
				t.session.conn.setClientOS("linux", "POSIX create context", clientOSPrioPOSIX)
				if enc, err := t.handlePosixCC(attrs); err == nil {
					rsp.Contexts = append(rsp.Contexts, enc)
				}
			}
		}

		cc = cc[res.Next():]
		if res.Next() == 0 {
			break
		}
	}

	// Ensure the response reflects the final oplock decision.
	rsp.OplockLevel = lockLevel

	if ctx != nil {
		ctx.fileId = rsp.FileId
	}

	t.conn.serverCtx.addOpen(open)

	if log.IsLevelEnabled(log.TraceLevel) {
		if len(rsp.Contexts) == 0 {
			log.Tracef("create rsp: oplock=%d ctxs=0 ctxLen=0", rsp.OplockLevel)
		} else {
			ctxLen := 0
			off := 88
			names := make([]string, 0, len(rsp.Contexts))
			for _, cc := range rsp.Contexts {
				off = Roundup(off, 8)
				ctxLen = off - 88 + cc.Size()
				off += cc.Size()
				if cctx, ok := cc.(*CreateContext); ok {
					names = append(names, cctx.Name)
				}
			}
			log.Tracef("create rsp: oplock=%d ctxs=%d ctxLen=%d names=%v", rsp.OplockLevel, len(rsp.Contexts), ctxLen, names)
		}
	}

	err = c.sendPacket(rsp, &t.treeConn, ctx)
	if err == nil && !isEA && name != "" {
		switch action {
		case FILE_CREATED:
			typeStr := "file"
			if isDir {
				typeStr = "dir"
			}
			c.infof("create: %s %s", typeStr, name)
		case FILE_OVERWRITTEN, FILE_SUPERSEDED:
			c.infof("replace: %s", name)
		}
	}

	// Notify directory watchers of file changes (after response is sent)
	if !isEA && name != "" {
		switch action {
		case FILE_CREATED:
			t.conn.serverCtx.notifyChange(name, FILE_ACTION_ADDED)
		case FILE_OVERWRITTEN, FILE_SUPERSEDED:
			t.conn.serverCtx.notifyChange(name, FILE_ACTION_MODIFIED)
		}
	}

	return err
}

func (t *fileTree) handleQFid(pkt []byte, open *Open) (Encoder, error) {
	attrRoot, _ := t.fs.GetAttr(0)

	return &CreateContext{
		Name: "QFid",
		Data: &DiskIdResponse{
			DiskFileId: open.durableFileId,
			VolumeId:   attrRoot.GetInodeNumber(),
		},
	}, nil
}

func (t *fileTree) handleDH2Q(pkt []byte, open *Open) (Encoder, error) {
	// Durable handles are disabled: durable reconnect semantics are not
	// implemented, so no DH2Q response context is returned. (The previous
	// response-building code was unreachable after this return.)
	return nil, nil
}

func (t *fileTree) handleRqLs(pkt []byte, open *Open) (Encoder, error) {
	// Disable leases: do not return RqLs response context.
	// Some Windows clients behave poorly if the server doesn't fully
	// implement lease semantics.
	return nil, nil
}

func (t *fileTree) handleCreateEA(disp uint32, h vfs.VfsHandle, eaKey string) (uint32, error) {
	var err error = nil
	status := uint32(0)

	// special cases for Apple
	if eaKey == "AFP_AfpInfo" {
		return 0, nil
	}

	switch disp {
	case FILE_OPEN_IF:
		// open or create
		if _, err = t.fs.Getxattr(h, eaKey, nil); err != nil {
			if err = t.fs.Setxattr(h, eaKey, nil); err != nil {
				status = uint32(STATUS_OPEN_FAILED)
			}
		}
	case FILE_OPEN:
		// open existing; if missing, create empty ADS to satisfy Windows probes
		if _, err = t.fs.Getxattr(h, eaKey, nil); err != nil {
			if err = t.fs.Setxattr(h, eaKey, nil); err != nil {
				status = uint32(STATUS_OBJECT_NAME_NOT_FOUND)
			} else {
				err = nil
			}
		}
	case FILE_CREATE:
		// if exists fail, otherwise create
		if _, err = t.fs.Getxattr(h, eaKey, nil); err == nil {
			status = uint32(STATUS_OBJECT_NAME_EXISTS)
			err = fmt.Errorf("already exists")
			break
		}
		if err = t.fs.Setxattr(h, eaKey, nil); err != nil {
			status = uint32(STATUS_OPEN_FAILED)
		}
	case FILE_OVERWRITE:
		// error if doesn't exists
		if _, err = t.fs.Getxattr(h, eaKey, nil); err != nil {
			status = uint32(STATUS_OBJECT_NAME_NOT_FOUND)
		}
		if err = t.fs.Setxattr(h, eaKey, nil); err != nil {
			status = uint32(STATUS_OPEN_FAILED)
		}
	case FILE_SUPERSEDE, FILE_OVERWRITE_IF:
		err = t.fs.Setxattr(h, eaKey, nil)
	}

	if err != nil && status == 0 {
		status = uint32(STATUS_OPEN_FAILED)
	}
	return status, err
}

// https://github.com/openzfs/openzfs/blob/master/usr/src/uts/common/smbsrv/smb2_aapl.h
func (t *fileTree) handleAAPLCC(pkt []byte) (Encoder, error) {
	r := AAPLServerQueryRequestDecoder(pkt)
	switch r.CommandCode() {
	case AAPL_SERVER_QUERY:
		rsp := CreateContext{
			Name: "AAPL",
			Data: &AAPLServerQueryResponse{
				CommandCode: AAPL_SERVER_QUERY,
				ReplyBitmap: AAPL_SERVER_CAPS | AAPL_VOLUME_CAPS | AAPL_MODEL_INFO,
				ServerCaps:  AAPL_SUPPORTS_READDIR_ATTR | /*AAPL_SUPPORTS_OSX_COPYFILE |*/ AAPL_UNIX_BASED | AAPL_SUPPORTS_NFS_ACE,
				VolumeCaps:/*AAPL_SUPPORT_RESOLVE_ID |AAPL_CASE_SENSITIVE |*/ AAPL_SUPPORTS_FULL_SYNC,
				ModelString: "CloudMachine",
			},
		}
		return rsp, nil
	case AAPL_RESOLVE_ID:
	}

	return nil, fmt.Errorf("not supported command")
}

func (t *fileTree) handlePosixCC(attrs *vfs.Attributes) (Encoder, error) {
	uid, _ := attrs.GetUID()
	gid, _ := attrs.GetGID()
	mode := PosixWireModeFromVfs(attrs)
	nlinks := attrs.GetLinkCount()

	ownerSid := PosixSIDFromUid(uid)
	groupSid := PosixSIDFromGid(gid)

	ownerBuf := make([]byte, ownerSid.Size())
	ownerSid.Encode(ownerBuf)
	groupBuf := make([]byte, groupSid.Size())
	groupSid.Encode(groupBuf)

	reparseTag := uint32(0)
	if attrs.GetFileType() == vfs.FileTypeSymlink {
		reparseTag = IO_REPARSE_TAG_SYMLINK
	}

	log.Tracef("POSIX CC: mode=0x%x, type=%d, nlinks=%d, reparse=0x%x, uid=%d, gid=%d", mode, attrs.GetFileType(), nlinks, reparseTag, uid, gid)

	return &CreateContext{
		Name: string(SMB2_CREATE_TAG_POSIX),
		Data: &PosixCreateResponse{
			Nlinks:     nlinks,
			ReparseTag: reparseTag,
			Mode:       mode,
			OwnerSid:   ownerBuf,
			GroupSid:   groupBuf,
		},
	}, nil
}

func (t *fileTree) handleMaxAccessCC(attrs *vfs.Attributes) (Encoder, error) {
	ccMaxAccess := CreateContext{
		Name: "MxAc",
		Data: CreateContextMaximalAccessResponse{
			QueryStatus:   0,
			MaximalAccess: MaxAccessFromVfs(attrs),
		},
	}
	return ccMaxAccess, nil
}

func (t *fileTree) close(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, err := accept(SMB2_CLOSE, pkt)
	if err != nil {
		return err
	}

	r := CloseRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken close request"}
	}

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("Close: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(CloseResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if r.Flags()&SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB != 0 {
		a, err := t.fs.GetAttr(vfs.VfsHandle(fileId.HandleId()))
		if err != nil {
			log.Errorf("Close: GetAttr() failed")
			goto send
		}

		if open == nil {
			log.Errorf("close: no open")
			goto send
		}
		rsp.CloseFlags = SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
		rsp.CreationTime = BirthTimeFromVfs(a)
		rsp.LastAccessTime = AccessTimeFromVfs(a)
		rsp.LastWriteTime = ModifiedTimeFromVfs(a)
		rsp.ChangeTime = ChangeTimeFromVfs(a)
		rsp.EndofFile = int64(SizeFromVfs(a))
		rsp.AllocationSize = int64(DiskSizeFromVfs(a))
		rsp.FileAttributes = PermissionsFromVfs(a, open.pathName, t.conn.serverCtx.hideDotfiles)
	}
send:
	if err := t.conn.serverCtx.releaseOpen(fileId.HandleId(), open, t.fs); err != nil {
		log.Errorf("Delete failed: %v", err)
		rsp.Status = uint32(STATUS_ACCESS_DENIED)
	} else if open != nil && open.deleteAfterClose && open.pathName != "" {
		c.infof("delete: %s", open.pathName)
	}

	c.sendPacket(rsp, &t.treeConn, ctx)
	return nil
}

func (t *fileTree) flush(ctx *compoundContext, pkt []byte) error {
	log.Tracef("flush")

	c := t.session.conn

	res, _ := accept(SMB2_FLUSH, pkt)
	r := FlushRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("flush: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	t.fs.Flush(vfs.VfsHandle(fileId.HandleId()))

	rsp := new(FlushResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) readEA(ctx *compoundContext, fileId *FileId, open *Open, pkt []byte, off uint64, length uint32) error {
	c := t.session.conn
	log.Tracef("readEA req: file=%s stream=%s off=%d len=%d", open.pathName, open.eaKey, off, length)

	// macOS TextEdit has been observed crashing while consuming
	// com.apple.TextEncoding over SMB in some OS builds.
	// Returning "not found" makes the client fall back to content sniffing.
	if strings.EqualFold(c.clientOS, "macOS") && strings.EqualFold(open.eaKey, "com.apple.TextEncoding") {
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_OBJECT_NAME_NOT_FOUND))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	status := uint32(0) //STATUS_END_OF_FILE
	total, err := t.fs.Getxattr(vfs.VfsHandle(fileId.HandleId()), open.eaKey, nil)
	n := 0

	if err != nil {
		// Missing stream/xattr is normal for Windows metadata probes.
		// Returning ACCESS_DENIED causes aggressive client retries.
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENODATA) {
			status = uint32(STATUS_OBJECT_NAME_NOT_FOUND)
		} else {
			status = uint32(STATUS_ACCESS_DENIED)
		}
	} else if total == 0 || int64(off) >= int64(total) {
		// For ADS/xattr stream reads, return success with zero-length payload
		// at/end-of-stream. Explorer probes Zone.Identifier repeatedly and is
		// sensitive to EOF-style error statuses here.
		rsp := new(ReadResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, 0)
		rsp.DataRemaining = 0
		rsp.Data = nil
		log.Tracef("readEA rsp: file=%s stream=%s n=0 eof=true", open.pathName, open.eaKey)
		return c.sendPacket(rsp, &t.treeConn, ctx)
	} else {
		full := make([]byte, total)
		nfull, err := t.fs.Getxattr(vfs.VfsHandle(fileId.HandleId()), open.eaKey, full)
		if err != nil {
			status = uint32(STATUS_ACCESS_DENIED)
		} else {
			start := int(off)
			end := start + int(length)
			if end > nfull {
				end = nfull
			}
			if start < 0 || start > nfull || end < start {
				status = uint32(STATUS_END_OF_FILE)
			} else {
				data := full[start:end]
				n = len(data)
				rsp := new(ReadResponse)
				PrepareResponse(&rsp.PacketHeader, pkt, 0)
				rsp.DataRemaining = 0
				rsp.Data = data
				log.Tracef("readEA rsp: file=%s stream=%s n=%d", open.pathName, open.eaKey, n)
				return c.sendPacket(rsp, &t.treeConn, ctx)
			}
		}
	}

	if status != 0 {
		// special cases for Apple
		if open.eaKey == "AFP_AfpInfo" && length == 60 {
			info := AfpInfo{
				Signature: [4]byte{'A', 'F', 'P', '_'},
				//Version:   [4]byte{0x00, 0x01, 0x00, 0x00},
			}
			buf := make([]byte, 60)
			info.Encode(buf)
			n = 60
			//t.fs.Setxattr(h, open.eaKey, buf)
			rsp := new(ReadResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, 0)
			rsp.DataRemaining = 0
			rsp.Data = buf[:n]
			log.Tracef("readEA rsp: file=%s stream=%s n=%d", open.pathName, open.eaKey, n)
			return c.sendPacket(rsp, &t.treeConn, ctx)
		} else {
			log.Tracef("readEA err: file=%s stream=%s status=0x%x err=%v", open.pathName, open.eaKey, status, err)
			rsp := new(ErrorResponse)
			PrepareResponse(rsp.Header(), pkt, status)
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
	}
	return nil

}

func (t *fileTree) read(ctx *compoundContext, pkt []byte) error {
	log.Tracef("read")
	c := t.session.conn

	res, _ := accept(SMB2_READ, pkt)
	r := ReadRequestDecoder(res)
	if r.Channel() != 0 || r.ReadChannelInfoLength() != 0 {
		log.Tracef("read: unsupported channel=%d chanInfoLen=%d", r.Channel(), r.ReadChannelInfoLength())
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("read: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if open == nil {
		log.Errorf("read: no open: %d", fileId.HandleId())
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	// Serve reads synchronously to avoid client-visible corruption/regressions.
	t.ioReadSem <- struct{}{}
	defer func() { <-t.ioReadSem }()
	return t.readImpl(ctx, pkt, fileId, open, 0)
}

func (t *fileTree) readImpl(ctx *compoundContext, pkt []byte, fileId *FileId, open *Open, asyncId uint64) error {
	c := t.session.conn

	res, _ := accept(SMB2_READ, pkt)
	r := ReadRequestDecoder(res)
	if r.Channel() != 0 || r.ReadChannelInfoLength() != 0 {
		log.Tracef("readImpl: unsupported channel=%d chanInfoLen=%d", r.Channel(), r.ReadChannelInfoLength())
		rsp := new(ErrorResponse)
		PrepareAsyncResponse(rsp.Header(), pkt, asyncId, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}
	log.Tracef("read req: file=%s off=%d len=%d min=%d flags=0x%x", open.pathName, r.Offset(), r.Length(), r.MinimumCount(), r.Flags())

	buf := make([]byte, r.Length())
	var n int
	var err error

	if open.isEa {
		return t.readEA(ctx, fileId, open, pkt, r.Offset(), r.Length())
	}

	n, err = t.fs.Read(vfs.VfsHandle(fileId.HandleId()), buf, r.Offset(), 0)
	if n > 0 {
		head := n
		if head > 16 {
			head = 16
		}
		log.Tracef("read rsp: file=%s off=%d n=%d err=%v head=%x", open.pathName, r.Offset(), n, err, buf[:head])
	} else {
		log.Tracef("read rsp: file=%s off=%d n=%d err=%v", open.pathName, r.Offset(), n, err)
	}
	if err != nil && n == 0 {
		status := STATUS_ACCESS_DENIED
		if err == io.EOF {
			if !open.isEa {
				status = STATUS_END_OF_FILE
			} else {
				status = STATUS_OBJECT_NAME_NOT_FOUND
			}
		} else {
			log.Errorf("Read: %v", err)
		}
		rsp := new(ErrorResponse)
		if asyncId == 0 {
			PrepareResponse(rsp.Header(), pkt, uint32(status))
		} else {
			PrepareAsyncResponse(rsp.Header(), pkt, asyncId, uint32(status))
		}
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(ReadResponse)
	if asyncId == 0 {
		PrepareResponse(&rsp.PacketHeader, pkt, 0)
	} else {
		PrepareAsyncResponse(&rsp.PacketHeader, pkt, asyncId, 0)
	}
	rsp.DataRemaining = 0
	rsp.Data = buf[:n]

	log.Tracef("read async %d finished", asyncId)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) write(ctx *compoundContext, pkt []byte) error {
	log.Tracef("write")

	c := t.session.conn
	if t.isUserReadOnly() {
		log.Warnf("deny write for read-only user=%s", t.session.username)
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	res, _ := accept(SMB2_WRITE, pkt)
	r := WriteRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("write: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if open == nil {
		log.Errorf("write: no open")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	// Semi-synchronous write: send PENDING, wait for write slot, do write, respond
	// This ensures writes complete before we return, preventing race with SetInfo
	asyncId := randint64()
	if ctx != nil || open.isEa {
		return t.writeImpl(ctx, pkt, fileId, open, 0)
	}

	// Send PENDING response immediately
	pendingRsp := new(ErrorResponse)
	PrepareAsyncResponse(pendingRsp.Header(), pkt, asyncId, uint32(STATUS_PENDING))
	c.sendPacket(pendingRsp, &t.treeConn, ctx)

	// Wait for write slot and complete the write synchronously
	t.ioWriteSem <- struct{}{}
	defer func() { <-t.ioWriteSem }()

	return t.writeImpl(ctx, pkt, fileId, open, asyncId)
}

func (t *fileTree) writeImpl(ctx *compoundContext, pkt []byte, fileId *FileId, open *Open, asyncId uint64) error {

	var n int
	var err error

	c := t.session.conn

	res, _ := accept(SMB2_WRITE, pkt)
	r := WriteRequestDecoder(res)

	if open.isEa {
		open.ioMu.Lock()
		log.Tracef("write ea: key %s, off %d, len %d", open.eaKey, r.Offset(), len(r.Data()))
		err = t.writeStream(vfs.VfsHandle(fileId.HandleId()), open.eaKey, r.Offset(), r.Data())
		open.ioMu.Unlock()
		n = len(r.Data())
	} else {
		log.Tracef("Write: %d offset %d", r.Length(), r.Offset())
		open.ioMu.Lock()
		n, err = t.fs.Write(vfs.VfsHandle(fileId.HandleId()), r.Data(), r.Offset(), int(r.Flags()))
		open.ioMu.Unlock()
	}

	if err != nil {
		log.Errorf("Write failed: %v", err)
		status := uint32(STATUS_IO_DEVICE_ERROR)
		if open.isEa {
			status = streamWriteStatus(err)
		}
		rsp := new(ErrorResponse)
		PrepareAsyncResponse(rsp.Header(), pkt, asyncId, status)
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(WriteResponse)
	PrepareAsyncResponse(&rsp.PacketHeader, pkt, asyncId, 0)
	rsp.Count = uint32(n)

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) lock(ctx *compoundContext, pkt []byte) error {
	log.Tracef("Lock")
	c := t.session.conn

	//rsp := new(ErrorResponse)
	//PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
	rsp := new(LockResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) handleReparsePointReq(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_IOCTL, pkt)
	r := IoctlRequestDecoder(res)

	rd := SymbolicLinkReparseDataBufferDecoder(r.Data())
	if rd.IsInvalid() {
		log.Errorf("handleReparsePointReq: reparse tag not supported: 0x%x", rd.ReparseTag())
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		log.Errorf("handleReparsePointReq: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	log.Tracef("handleReparsePointReq: subst name %s", rd.SubstituteName())
	source := strings.ReplaceAll(rd.SubstituteName(), "\\", "/")
	_, err := t.fs.Symlink(vfs.VfsHandle(fileId.HandleId()), source, int(rd.Flags()))
	if err != nil {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(IoctlResponse)
	rsp.CtlCode = FSCTL_SET_REPARSE_POINT
	rsp.FileId = fileId
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) handleGetReparsePointReq(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_IOCTL, pkt)
	r := IoctlRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		log.Errorf("handleReparsePointReq: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	l, err := t.fs.Readlink(vfs.VfsHandle(fileId.HandleId()))
	if err != nil {
		log.Errorf("handleGetReparsePointReq: Readlink() failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	l = strings.ReplaceAll(l, "/", "\\")
	out := &SymbolicLinkReparseDataBuffer{
		SubstituteName: l,
		PrintName:      l,
	}
	if !path.IsAbs(l) {
		out.Flags = SYMLINK_FLAG_RELATIVE
	}

	rsp := new(IoctlResponse)
	rsp.CtlCode = FSCTL_GET_REPARSE_POINT
	rsp.FileId = fileId
	rsp.Output = out

	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) handleDeleteReparsePointReq(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_IOCTL, pkt)
	r := IoctlRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		log.Errorf("handleDeleteReparsePointReq: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	// Only a symlink carries a reparse point here. Without this check the
	// FSCTL would delete any regular file the handle points to.
	attrs, err := t.fs.GetAttr(vfs.VfsHandle(fileId.HandleId()))
	if err != nil || attrs.GetFileType() != vfs.FileTypeSymlink {
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_NOT_A_REPARSE_POINT))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	err = t.fs.Unlink(vfs.VfsHandle(fileId.HandleId()))
	if err != nil {
		log.Errorf("handleDeleteReparsePointReq: Unlink() failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(IoctlResponse)
	rsp.CtlCode = FSCTL_DELETE_REPARSE_POINT
	rsp.FileId = fileId

	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) handleCreateOrGetObjectId(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_IOCTL, pkt)
	r := IoctlRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		log.Errorf("handleCreateOrGetObjectId: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	attrRoot, _ := t.fs.GetAttr(0)

	id := &FileObjectId1{
		ObjectId:      FileId{Persistent: fileId.Persistent},
		BirthObjectId: FileId{Persistent: fileId.Persistent},
	}
	le.PutUint64(id.BirthVolumeId.Persistent[:], attrRoot.GetInodeNumber())

	rsp := new(IoctlResponse)
	rsp.CtlCode = FSCTL_CREATE_OR_GET_OBJECT_ID
	rsp.FileId = fileId
	rsp.Output = id

	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

// reparseWriteAllowed decides whether FSCTL_SET/DELETE_REPARSE_POINT may
// modify the file behind the request's handle. Both FSCTLs replace or remove
// directory entries, so they are refused for read-only users and shares, and
// (as in MS-FSA 2.1.5.10.36/37) the handle must have been opened with write
// access. An invalid file id is let through so the handler can answer with
// STATUS_INVALID_HANDLE.
func (t *fileTree) reparseWriteAllowed(ctx *compoundContext, r IoctlRequestDecoder) bool {
	if t.isUserReadOnly() || t.isShareReadOnly() {
		return false
	}
	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		return true
	}
	if t.conn == nil || t.conn.serverCtx == nil {
		return false
	}
	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if open == nil {
		return false
	}
	const writeAccess = FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES | GENERIC_WRITE | GENERIC_ALL | MAXIMUM_ALLOWED
	return open.grantedAccess&writeAccess != 0
}

func (t *fileTree) ioctl(ctx *compoundContext, pkt []byte) error {
	log.Tracef("Ioctl")

	c := t.session.conn

	res, err := accept(SMB2_IOCTL, pkt)
	if err != nil {
		return err
	}
	r := IoctlRequestDecoder(res)
	if r.IsInvalid() {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_PARAMETER))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}
	fileID := uint64(0)
	if fid := r.FileId(); fid != nil {
		fileID = fid.Decode().HandleId()
	}
	log.Tracef("ioctl req: code=0x%x fileId=%d inLen=%d outLen=%d maxOut=%d flags=0x%x",
		r.CtlCode(),
		fileID,
		r.InputCount(),
		r.OutputCount(),
		r.MaxOutputResponse(),
		r.Flags(),
	)

	switch r.CtlCode() {
	case FSCTL_SET_REPARSE_POINT, FSCTL_DELETE_REPARSE_POINT:
		if !t.reparseWriteAllowed(ctx, r) {
			log.Warnf("deny reparse point change user=%s code=0x%x", t.session.username, r.CtlCode())
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
		if r.CtlCode() == FSCTL_SET_REPARSE_POINT {
			return t.handleReparsePointReq(ctx, pkt)
		}
		return t.handleDeleteReparsePointReq(ctx, pkt)
	case FSCTL_GET_REPARSE_POINT:
		return t.handleGetReparsePointReq(ctx, pkt)
	case FSCTL_CREATE_OR_GET_OBJECT_ID:
		return t.handleCreateOrGetObjectId(ctx, pkt)
	}

	log.Tracef("ioctl: unsupported code %d", r.CtlCode())
	/*rsp := new(IoctlResponse)
	rsp.CtlCode = r.CtlCode()
	rsp.FileId = r.FileId().Decode()
	*/
	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) cancel(ctx *compoundContext, pkt []byte) error {
	log.Tracef("Cancel request received")

	p := PacketCodec(pkt)
	asyncId := p.AsyncId()

	// Cancel ALL pending ChangeNotify on this connection, not just the one
	// matching asyncId. Explorer registers two watchers but only cancels one
	// by asyncId — the other would block until timeout. Cancelling both
	// ensures copy/replace/delete operations start immediately.
	if asyncId != 0 {
		t.conn.serverCtx.lock.Lock()
		for _, open := range t.conn.serverCtx.opens {
			if open.session != nil && open.session.conn == t.session.conn && open.notifyCancel != nil {
				select {
				case open.notifyCancel <- struct{}{}:
				default:
				}
			}
		}
		t.conn.serverCtx.lock.Unlock()
	}

	return nil
}

func newFileDirectoryInformationInfo(d vfs.DirInfo, hideDotfiles bool) FileDirectoryInformationInfo {
	info := FileDirectoryInformationInfo{
		FileIndex: 0,
		FileName:  d.Name,
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name, hideDotfiles)
	return info
}

func newFileFullDirectoryInformationInfo(d vfs.DirInfo, hideDotfiles bool) FileFullDirectoryInformationInfo {
	info := FileFullDirectoryInformationInfo{
		FileIndex: 0,
		FileName:  d.Name,
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name, hideDotfiles)
	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.EaSize = IO_REPARSE_TAG_SYMLINK
	}
	return info
}

func newFileIdFullDirectoryInformationInfo(d vfs.DirInfo, hideDotfiles bool) FileIdFullDirectoryInformationInfo {
	info := FileIdFullDirectoryInformationInfo{
		FileIndex: 0,
		FileName:  d.Name,
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name, hideDotfiles)
	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.EaSize = IO_REPARSE_TAG_SYMLINK
	}
	return info
}

func newFileIdBothDirectoryInformationInfo(d vfs.DirInfo, hideDotfiles bool) FileIdBothDirectoryInformationInfo {
	info := FileIdBothDirectoryInformationInfo{
		FileIndex: 0,
		FileName:  d.Name,
		FileId:    d.GetInodeNumber(),
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name, hideDotfiles)

	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.EaSize = IO_REPARSE_TAG_SYMLINK
	}

	return info
}

func newFileBothDirectoryInformationInfo(d vfs.DirInfo, hideDotfiles bool) FileBothDirectoryInformationInfo {
	info := FileBothDirectoryInformationInfo{
		FileIndex: 0,
		FileName:  d.Name,
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name, hideDotfiles)

	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.EaSize = IO_REPARSE_TAG_SYMLINK
	}

	return info
}

func newFileIdAllExtdBothDirectoryInformationInfo(d vfs.DirInfo, hideDotfiles bool) FileIdAllExtdBothDirectoryInformationInfo {
	info := FileIdAllExtdBothDirectoryInformationInfo{
		FileIndex: 0,
		FileName:  d.Name,
		FileId:    d.GetInodeNumber(),
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name, hideDotfiles)

	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.EaSize = IO_REPARSE_TAG_SYMLINK
	}

	return info
}

func newFileIdBothDirectoryInformationInfo2(d vfs.DirInfo, hideDotfiles bool) FileIdBothDirectoryInformationInfo2 {
	info := FileIdBothDirectoryInformationInfo2{
		FileIndex: 0,
		MaxAccess: MaxAccessFromVfs(&d.Attributes),
		FileName:  d.Name,
		FileId:    d.GetInodeNumber(),
		UnixMode:  UnixModeFromVfs(&d.Attributes),
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.FileAttributes = PermissionsFromVfs(&d.Attributes, d.Name, hideDotfiles)

	if info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		info.MaxAccess = IO_REPARSE_TAG_SYMLINK
	}

	return info
}

func newFileNamesInformationInfo(d vfs.DirInfo) FileNamesInformationInfo {
	info := FileNamesInformationInfo{
		FileName: d.Name,
	}
	return info
}

func newFilePosixDirectoryInformationInfo(d vfs.DirInfo, hideDotfiles bool) *FilePosixDirectoryInformationInfo {
	uid, _ := d.Attributes.GetUID()
	gid, _ := d.Attributes.GetGID()
	mode := PosixWireModeFromVfs(&d.Attributes)
	nlinks := d.Attributes.GetLinkCount()

	ownerSid := PosixSIDFromUid(uid)
	groupSid := PosixSIDFromGid(gid)
	ownerBuf := make([]byte, ownerSid.Size())
	ownerSid.Encode(ownerBuf)
	groupBuf := make([]byte, groupSid.Size())
	groupSid.Encode(groupBuf)

	reparseTag := uint32(0)
	if d.Attributes.GetFileType() == vfs.FileTypeSymlink {
		reparseTag = IO_REPARSE_TAG_SYMLINK
	}

	info := &FilePosixDirectoryInformationInfo{
		FileName:   d.Name,
		Inode:      d.GetInodeNumber(),
		Mode:       mode,
		HardLinks:  nlinks,
		ReparseTag: reparseTag,
		OwnerSid:   ownerBuf,
		GroupSid:   groupBuf,
	}

	info.CreationTime = *BirthTimeFromVfs(&d.Attributes)
	info.LastAccessTime = *AccessTimeFromVfs(&d.Attributes)
	info.LastWriteTime = *ModifiedTimeFromVfs(&d.Attributes)
	info.ChangeTime = *ChangeTimeFromVfs(&d.Attributes)
	info.EndOfFile = SizeFromVfs(&d.Attributes)
	info.AllocationSize = DiskSizeFromVfs(&d.Attributes)
	info.DosAttributes = PermissionsFromVfs(&d.Attributes, d.Name, hideDotfiles)

	nameLen := utf16le.EncodedStringLen(info.FileName)
	log.Tracef("POSIX direntry: name=%s, nameLen=%d, ownerSid=%d, groupSid=%d, size=%d, mode=0x%x, dosAttrs=0x%x, type=%d, nlinks=%d",
		d.Name, nameLen, len(info.OwnerSid), len(info.GroupSid), info.Size(), mode, info.DosAttributes, d.Attributes.GetFileType(), nlinks)

	return info
}

func (t *fileTree) makeItem(class uint8, d vfs.DirInfo) Encoder {
	hideDotfiles := t.conn.serverCtx.hideDotfiles
	switch class {
	case FileBothDirectoryInformation:
		return newFileBothDirectoryInformationInfo(d, hideDotfiles)
	case FileNamesInformation:
		return newFileNamesInformationInfo(d)
	case FileIdBothDirectoryInformation:
		if t.aaplExtensions {
			return newFileIdBothDirectoryInformationInfo2(d, hideDotfiles)
		}
		return newFileIdBothDirectoryInformationInfo(d, hideDotfiles)
	case FileDirectoryInformation:
		return newFileDirectoryInformationInfo(d, hideDotfiles)
	case FileFullDirectoryInformation:
		return newFileFullDirectoryInformationInfo(d, hideDotfiles)
	case FileIdFullDirectoryInformation:
		return newFileIdFullDirectoryInformationInfo(d, hideDotfiles)
	case FileIdAllExtdBothDirectoryInformation:
		return newFileIdAllExtdBothDirectoryInformationInfo(d, hideDotfiles)
	case FilePosixInformation:
		return newFilePosixDirectoryInformationInfo(d, hideDotfiles)
	default:
		log.Warningf("bad info class %d", class)
	}
	return nil
}

func (t *fileTree) queryDirectory(ctx *compoundContext, pkt []byte) error {
	log.Tracef("QueryDirectory")

	c := t.session.conn

	res, err := accept(SMB2_QUERY_DIRECTORY, pkt)
	if err != nil {
		log.Errorf("queryDirectory: invalid request: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_PARAMETER))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}
	r := QueryDirectoryRequestDecoder(res)
	if r.IsInvalid() {
		log.Errorf("queryDirectory: malformed request payload")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_PARAMETER))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	switch r.FileInfoClass() {
	case FileIdBothDirectoryInformation, FileFullDirectoryInformation, FileNamesInformation,
		FileDirectoryInformation, FileIdFullDirectoryInformation, FileBothDirectoryInformation,
		FileIdAllExtdBothDirectoryInformation, FilePosixInformation:
		break
	default:
		log.Errorf("wrong info class %d", r.FileInfoClass())
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_PARAMETER))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	log.Tracef("queryDirectory: class=%d, pattern=%s", r.FileInfoClass(), r.FileName())
	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("queryDirectory: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	dirTarget := fmt.Sprintf("handle=%d", fileId.HandleId())
	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if open != nil && open.pathName != "" {
		dirTarget = open.pathName
	}

	out := &FileInformationInfoResponse{}
	Status := uint32(0)

	// RESTART_SCANS and REOPEN both start a new scan of the directory.
	restart := r.Flags()&(RESTART_SCANS|REOPEN) != 0
	pos := 0
	if restart {
		pos = 1
		if open != nil {
			open.enumStarted = false
			open.enumSingleDone = false
		}
	}

	// An empty search pattern means "*" (as on Windows).
	name := r.FileName()
	if name == "" {
		name = "*"
	}
	maxOutBytes := int(r.OutputBufferLength())
	if maxOutBytes == 0 {
		maxOutBytes = 65536
	}

	if Status == 0 {
		// Nothing to return: STATUS_NO_SUCH_FILE on the first query of a
		// scan, STATUS_NO_MORE_FILES once the scan is under way.
		Status = uint32(STATUS_NO_SUCH_FILE)
		if open != nil && open.enumStarted {
			Status = uint32(STATUS_NO_MORE_FILES)
		}

		if !ContainsWildcard(name) {
			// A plain name yields at most one entry per scan; returning it
			// on every call made clients that loop until NO_MORE_FILES
			// (e.g. smbclient `ls file`) spin forever.
			if open == nil || !open.enumSingleDone {
				if attrs, err := t.fs.Lookup(vfs.VfsHandle(fileId.HandleId()), name); err == nil {
					log.Tracef("lookup %s success", name)
					d := vfs.DirInfo{Name: name, Attributes: *attrs}
					info := t.makeItem(r.FileInfoClass(), d)
					out.Items = append(out.Items, info)
					Status = 0
					if open != nil {
						open.enumSingleDone = true
					}
				}
			}
		} else {
			h := vfs.VfsHandle(fileId.HandleId())
			accSize := 0
			// Read batch after batch until something matched, the output
			// buffer is full or the directory is exhausted. Stopping after
			// one batch without a match ended the listing early in large
			// directories.
			for len(out.Items) == 0 {
				dir, err := t.fs.ReadDir(h, pos, 1000)
				pos = 0
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Errorf("queryDirectory: err %v", err)
					Status = uint32(STATUS_ACCESS_DENIED)
					break
				}

				var unconsumed []vfs.DirInfo
				for i, d := range dir {
					// Hide macOS AppleDouble and .DS_Store files when AAPL extensions are active
					if t.aaplExtensions && (strings.HasPrefix(d.Name, "._") || d.Name == ".DS_Store") {
						continue
					}
					if !MatchWildcard(d.Name, name) {
						continue
					}
					info := t.makeItem(r.FileInfoClass(), d)
					entrySize := info.Size()

					// Check if adding this entry would exceed OutputBufferLength
					if accSize > 0 && accSize+entrySize > maxOutBytes {
						// Buffer remaining entries for next call
						unconsumed = dir[i:]
						break
					}

					out.Items = append(out.Items, info)
					accSize += entrySize
					Status = 0

					if r.Flags()&RETURN_SINGLE_ENTRY != 0 {
						if i+1 < len(dir) {
							unconsumed = dir[i+1:]
						}
						break
					}
				}
				// Put back unconsumed entries so the next QueryDirectory gets them
				if len(unconsumed) > 0 {
					t.fs.PutBackDirEntries(h, unconsumed)
					break
				}
			}

			if r.FileInfoClass() == FilePosixInformation && len(out.Items) > 0 {
				total := 0
				for i, it := range out.Items {
					sz := it.Size()
					total += sz
					log.Tracef("POSIX readdir entry[%d]: size=%d", i, sz)
				}
				log.Tracef("POSIX readdir: entries=%d totalBytes=%d maxOut=%d", len(out.Items), total, maxOutBytes)
			}
		}
		if open != nil {
			open.enumStarted = true
		}
	} else {
		out = nil
	}

	var rsp Packet
	if Status != 0 {
		rsp = new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, Status)
	} else {
		rsp = &QueryDirectoryResponse{Output: out}
		PrepareResponse(rsp.Header(), pkt, Status)
	}

	// Many clients (including POSIX mounts) issue a trailing QUERY_DIRECTORY that
	// only asks "are there more entries?". Skip that terminal call in debug logs.
	if Status != uint32(STATUS_NO_MORE_FILES) {
		c.infof("dir read: %s", dirTarget)
		event := "dir list"
		if r.Flags()&RESTART_SCANS != 0 {
			event = "dir refresh"
		}
		key := fmt.Sprintf("%s|%s", event, dirTarget)
		if shouldLogDirQueryDebug(key) {
			c.debugf("%s: %s", event, dirTarget)
		}
	}

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) changeNotify(ctx *compoundContext, pkt []byte) error {
	log.Tracef("ChangeNotify")

	c := t.session.conn

	res, _ := accept(SMB2_CHANGE_NOTIFY, pkt)
	r := ChangeNotifyRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		log.Tracef("ChangeNotify: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if open == nil {
		log.Errorf("ChangeNotify: open not found")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	log.Tracef("ChangeNotify: file %s, h: %d", open.pathName, fileId.HandleId())

	/*ch := make(chan *vfs.NotifyEvent)
	t.fs.RegisterNotify(vfs.VfsHandle(fileId.HandleId()), ch)
	go func(ctx *compoundContext, ch chan *vfs.NotifyEvent, isDir bool, pkt []byte) {
		defer c.recoverConn("change notify")
		ev := <-ch
		if ev != nil {
			log.Errorf("notification received: %v, %v", isDir, ev)
			if isDir {
				rsp := new(ChangeNotifyResponse)
				rsp.Output = &FileNotifyInformationInfo{
					Action:   FILE_ACTION_ADDED,
					FileName: strings.ReplaceAll(ev.Name, "/", "\\"),
				}
				log.Errorf("Sending notification: %s", strings.ReplaceAll(ev.Name, "/", "\\"))
				PrepareResponse(&rsp.PacketHeader, pkt, 0)
				rsp.Flags |= SMB2_FLAGS_ASYNC_COMMAND
				c.sendPacket(rsp, &t.treeConn, ctx)
			}
		}
		t.fs.RemoveNotify(vfs.VfsHandle(fileId.HandleId()))
		close(ch)
	}(ctx, ch, open.fileAttributes&FILE_ATTRIBUTE_DIRECTORY != 0, open.notifyReq)*/

	/*rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
	return c.sendPacket(rsp, &t.treeConn, ctx)*/
	// Send PENDING now, and complete after 3s if still open
	asyncId := randint64()
	pending := new(ErrorResponse)
	PrepareAsyncResponse(pending.Header(), pkt, asyncId, uint32(STATUS_PENDING))
	if err := c.sendPacket(pending, &t.treeConn, ctx); err != nil {
		return err
	}
	open.notifyReqAsyncId = asyncId
	open.notifyReq = pkt
	open.notifyCancel = make(chan struct{}, 1)
	if open.notifyCh == nil {
		open.notifyCh = make(chan notifyEvent, 64)
	}
	open.notifyWatchTree = (r.Flags() & 0x0001) != 0

	// Set up filesystem watch (persistent for directory handle lifetime)
	if open.fsWatchPath == "" {
		realPath := filepath.Join(t.fs.BasePath(), open.pathName)
		shareRoot := t.fs.BasePath()
		t.conn.serverCtx.addFsWatch(realPath, shareRoot)
		open.fsWatchPath = realPath
	}

	handleId := fileId.HandleId()
	cancelCh := open.notifyCancel
	eventCh := open.notifyCh

	// Copy the request packet — the receiver may reuse the buffer
	savedPkt := make([]byte, len(pkt))
	copy(savedPkt, pkt)

	go func(ctx *compoundContext, reqPkt []byte, h uint64) {
		defer c.recoverConn("change notify")
		var events []notifyEvent
		// Wait indefinitely for real events or cancel — like real Samba.
		// Never send STATUS_CANCELLED on timeout (Explorer gives up after
		// 2 consecutive STATUS_CANCELLED). Use periodic liveness checks
		// as a safety net against goroutine leaks on unexpected disconnects.
		for {
			select {
			case ev := <-eventCh:
				events = append(events, ev)
				// Adaptive coalesce: wait for a quiet period (no events for 150ms),
				// capped at 3s max.
				deadline := time.After(3 * time.Second)
				quiet := time.NewTimer(150 * time.Millisecond)
			coalesceLoop:
				for {
					select {
					case ev = <-eventCh:
						events = append(events, ev)
						quiet.Reset(150 * time.Millisecond)
					case <-quiet.C:
						break coalesceLoop
					case <-deadline:
						break coalesceLoop
					case <-cancelCh:
						events = nil
						break coalesceLoop
					}
				}
				quiet.Stop()
			case <-cancelCh:
				log.Tracef("ChangeNotify: cancelled h=%d", h)
			case <-time.After(60 * time.Second):
				// Liveness check: if the open handle is gone (connection dropped),
				// exit the goroutine to prevent leaks.
				if t.conn.serverCtx.getOpen(h) == nil {
					log.Tracef("ChangeNotify: open gone h=%d", h)
					return
				}
				continue // keep waiting
			}
			break
		}
		if t.conn.serverCtx.getOpen(h) == nil {
			return
		}
		open.notifyReq = nil
		open.notifyCancel = nil
		// Keep notifyCh alive to buffer events between ChangeNotify cycles

		if len(events) > 0 {
			log.Tracef("notify: %d change(s) h=%d", len(events), h)
			rsp := new(ChangeNotifyResponse)
			list := make(FileNotifyInformationList, len(events))
			for i, ev := range events {
				list[i] = FileNotifyInformationInfo{
					Action:   ev.Action,
					FileName: strings.ReplaceAll(ev.FileName, "/", "\\"),
				}
			}
			rsp.Output = list
			PrepareAsyncResponse(&rsp.PacketHeader, reqPkt, asyncId, 0)
			c.sendPacket(rsp, &t.treeConn, ctx)
		} else {
			log.Tracef("ChangeNotify: sending STATUS_CANCELLED h=%d", h)
			final := new(ErrorResponse)
			PrepareAsyncResponse(&final.PacketHeader, reqPkt, asyncId, uint32(STATUS_CANCELLED))
			c.sendPacket(final, &t.treeConn, ctx)
		}
	}(ctx, savedPkt, handleId)

	return nil
}

func (t *fileTree) queryInfoFileSystem(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_QUERY_INFO, pkt)
	r := QueryInfoRequestDecoder(res)

	log.Tracef("queryInfoFileSystem: class %d", r.FileInfoClass())

	s, _ := t.fs.StatFS(0)
	bs := uint32(512)
	if b, ok := s.GetBlockSize(); ok {
		bs = uint32(b)
	}
	au := int64(-1)
	if val, ok := s.GetAvailableBlocks(); ok {
		au = int64(val)
	}
	ta := int64(-1)
	if val, ok := s.GetBlocks(); ok {
		ta = int64(val)
	}

	var info Encoder
	switch r.FileInfoClass() {
	case FileFsVolumeInformation:
		info = &FileFsVolumeInformationInfo{
			VolumeLabel: t.path,
		}
	case FileFsSizeInformation:
		info = &FileFsSizeInformationInfo{
			TotalAllocationUnits:     ta,
			AvailableAllocationUnits: au,
			SectorsPerAllocationUnit: bs / 512,
			BytesPerSector:           512,
		}
	case FileFsDeviceInformation:
		info = &FileFsDeviceInformationInfo{
			DeviceType: FILE_DEVICE_DISK,
		}
	case FileFsAttributeInformation:
		attrs := FILE_SUPPORTS_OPEN_BY_FILE_ID |
			FILE_SUPPORTS_OBJECT_IDS |
			//FILE_CASE_SENSITIVE_SEARCH |
			FILE_CASE_PRESERVED_NAMES |
			FILE_PERSISTENT_ACLS |
			FILE_SUPPORTS_SPARSE_FILES |
			FILE_UNICODE_ON_DISK |
			FILE_SUPPORTS_HARD_LINKS |
			FILE_SUPPORTS_REPARSE_POINTS
		if t.conn.serverCtx.xattrs {
			attrs |= FILE_SUPPORTS_EXTENDED_ATTRIBUTES | FILE_NAMED_STREAMS
		}
		info = &FileFsAttributeInformationInfo{
			FileSystemAttributes:       uint32(attrs),
			MaximumComponentNameLength: 255,
			FileSystemName:             "APFS",
		}
	case FileFsFullSizeInformation:
		info = &FileFsFullSizeInformationInfo{
			TotalAllocationUnits:           ta,
			CallerAvailableAllocationUnits: au,
			ActualAvailableAllocationUnits: au,
			SectorsPerAllocationUnit:       bs / 512,
			BytesPerSector:                 512,
		}
	case FileFsSectorSizeInformation:
		info = &FileFsSectorSizeInformationInfo{
			LogicalBytesPerSector:                                 512,
			PhysicalBytesPerSectorForAtomicity:                    bs,
			PhysicalBytesPerSectorForPerformance:                  bs,
			FileSystemEffectivePhysicalBytesPerSectorForAtomicity: bs,
			Flags:                           0,
			ByteOffsetForSectorAlignment:    0,
			ByteOffsetForPartitionAlignment: 0,
		}
	case FileFsObjectIdInformation:
		fileId := r.FileId().Decode()
		if ctx != nil && ctx.fileId != nil {
			fileId = ctx.fileId
		}
		attrRoot, _ := t.fs.GetAttr(0)
		id := &FileObjectId1{
			ObjectId:      FileId{Persistent: fileId.Persistent},
			BirthObjectId: FileId{Persistent: fileId.Persistent},
		}
		le.PutUint64(id.BirthVolumeId.Persistent[:], attrRoot.GetInodeNumber())
		info = id
	case FilePosixInformation:
		info = &FileFsPosixInformationInfo{
			OptimalTransferSize: bs,
			BlockSize:           bs,
			TotalBlocks:         uint64(ta),
			BlocksAvail:         uint64(au),
			UserBlocksAvail:     uint64(au),
			TotalFileNodes:      1000000,
			FreeFileNodes:       1000000,
			FileSysIdentifier:   0,
		}
	default:
		log.Errorf("queryInfoFileSystem: unsupported type %d", r.FileInfoClass())
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if info != nil {
		need := info.Size()
		if need > int(r.OutputBufferLength()) {
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INFO_LENGTH_MISMATCH))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
	}

	rsp := new(QueryInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	rsp.Output = info

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) queryInfoFile(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_QUERY_INFO, pkt)
	r := QueryInfoRequestDecoder(res)

	log.Tracef("queryInfoFile: class %d outLen=%d", r.FileInfoClass(), r.OutputBufferLength())

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("queryInfoFile: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if open == nil {
		log.Errorf("queryInfoFile: open not found: %d", fileId.HandleId())
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	name := open.pathName
	a, err := t.fs.GetAttr(vfs.VfsHandle(fileId.HandleId()))
	if err != nil {
		log.Errorf("queryInfoFile: GetAttr() failed")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	isDir := uint8(0)
	if a.GetFileType() == vfs.FileTypeDirectory {
		isDir = 1
	}

	var info Encoder
	switch r.FileInfoClass() {
	case FileAllInformation:
		endOfFile, allocSize := int64(SizeFromVfs(a)), int64(DiskSizeFromVfs(a))
		if open.isEa {
			// On a stream handle the sizes are the stream's, not the file's
			// (as for FileNetworkOpenInformation below).
			l, _ := t.fs.Getxattr(vfs.VfsHandle(fileId.HandleId()), open.eaKey, nil)
			endOfFile, allocSize = int64(l), int64(l)
		}
		info = &FileAllInformationInfo{
			BasicInformation: FileBasicInformationInfo{
				CreationTime:   *BirthTimeFromVfs(a),
				LastAccessTime: *AccessTimeFromVfs(a),
				LastWriteTime:  *ModifiedTimeFromVfs(a),
				ChangeTime:     *ChangeTimeFromVfs(a),
				FileAttributes: PermissionsFromVfs(a, open.pathName, t.conn.serverCtx.hideDotfiles),
			},
			StandardInformation: FileStandardInformationInfo{
				EndOfFile:      endOfFile,
				AllocationSize: allocSize,
				NumberOfLinks:  a.GetLinkCount(),
				Directory:      isDir,
			},
			Internal: FileInternalInformationInfo{
				IndexNumber: int64(a.GetInodeNumber()),
			},
			EaInformation: FileEaInformationInfo{},
			AccessInformation: FileAccessInformationInfo{
				AccessFlags: MaxAccessFromVfs(a),
			},
			PositionInformation: FilePositionInformationInfo{},
			ModeInformation: FileModeInformationInfo{
				Mode: FILE_SYNCHRONOUS_IO_ALERT,
			},
			AlignmentInformation: FileAlignmentInformationInfo{},
			NameInformation: FileAlternateNameInformationInfo{
				FileName: strings.ReplaceAll(name, "/", "\\"),
			},
		}
	case FileEaInformation:
		info = &FileEaInformationInfo{}
	case FileStreamInformation:
		if isDir == 1 {
			break
		}

		xattrs, err := t.fs.Listxattr(vfs.VfsHandle(fileId.HandleId()))
		items := FileStreamInformationInfoItems{
			FileStreamInformationInfo{
				NextEntryOffset:      0,
				StreamSize:           SizeFromVfs(a),
				StreamAllocationSize: DiskSizeFromVfs(a),
				StreamName:           "::$DATA",
			},
		}

		log.Tracef("queryInfoFile: xattrs ret %v, err %v", xattrs, err)
		if err == nil && t.conn.serverCtx.xattrs {
			for _, ea := range xattrs {
				l, err := t.fs.Getxattr(vfs.VfsHandle(fileId.HandleId()), ea, nil)
				if err == nil {
					item := FileStreamInformationInfo{
						StreamSize:           uint64(l),
						StreamAllocationSize: uint64(l),
						StreamName:           fmt.Sprintf(":%s:$DATA", ea),
					}
					items = append(items, item)
				}
			}
		}
		info = items
	case FileNetworkOpenInformation:
		if !open.isEa {
			info = &FileNetworkOpenInformationInfo{
				CreationTime:   *BirthTimeFromVfs(a),
				LastAccessTime: *AccessTimeFromVfs(a),
				LastWriteTime:  *ModifiedTimeFromVfs(a),
				ChangeTime:     *ChangeTimeFromVfs(a),
				AllocationSize: int64(DiskSizeFromVfs(a)),
				EndOfFile:      int64(SizeFromVfs(a)),
				FileAttributes: PermissionsFromVfs(a, open.pathName, t.conn.serverCtx.hideDotfiles),
			}
		} else {
			len, _ := t.fs.Getxattr(vfs.VfsHandle(fileId.HandleId()), open.eaKey, nil)
			info = &FileNetworkOpenInformationInfo{
				CreationTime:   *BirthTimeFromVfs(a),
				LastAccessTime: *AccessTimeFromVfs(a),
				LastWriteTime:  *ModifiedTimeFromVfs(a),
				ChangeTime:     *ChangeTimeFromVfs(a),
				AllocationSize: int64(len),
				EndOfFile:      int64(len),
				FileAttributes: 0,
			}
		}
	case FileNormalizedNameInformation:
		norm := strings.ReplaceAll(name, "/", "\\")
		if !strings.HasPrefix(norm, "\\") {
			norm = "\\" + norm
		}
		info = &FileNormalizedNameInformationInfo{
			FileName: norm,
		}
	case FileInternalInformation:
		info = &FileInternalInformationInfo{
			int64(a.GetInodeNumber()),
		}
	case FileFullEaInformation:
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NO_EAS_ON_FILE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	case FilePosixInformation:
		if !t.session.conn.posixExtensions {
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
		uid, _ := a.GetUID()
		gid, _ := a.GetGID()
		mode := PosixWireModeFromVfs(a)
		nlinks := a.GetLinkCount()
		ownerSid := PosixSIDFromUid(uid)
		groupSid := PosixSIDFromGid(gid)
		ownerBuf := make([]byte, ownerSid.Size())
		ownerSid.Encode(ownerBuf)
		groupBuf := make([]byte, groupSid.Size())
		groupSid.Encode(groupBuf)
		reparseTag := uint32(0)
		if a.GetFileType() == vfs.FileTypeSymlink {
			reparseTag = IO_REPARSE_TAG_SYMLINK
		}
		dosAttrs := PermissionsFromVfs(a, open.pathName, t.conn.serverCtx.hideDotfiles)
		log.Tracef("POSIX info: mode=0x%x, type=%d, dosAttrs=0x%x, inode=%d", mode, a.GetFileType(), dosAttrs, a.GetInodeNumber())
		info = &PosixFileInfo{
			CreationTime:   *BirthTimeFromVfs(a),
			LastAccessTime: *AccessTimeFromVfs(a),
			LastWriteTime:  *ModifiedTimeFromVfs(a),
			ChangeTime:     *ChangeTimeFromVfs(a),
			EndOfFile:      int64(SizeFromVfs(a)),
			AllocationSize: int64(DiskSizeFromVfs(a)),
			DosAttributes:  dosAttrs,
			Inode:          a.GetInodeNumber(),
			HardLinks:      nlinks,
			ReparseTag:     reparseTag,
			Mode:           mode,
			OwnerSid:       ownerBuf,
			GroupSid:       groupBuf,
		}
	default:
		log.Errorf("queryInfoFile: unsupported class %d", r.FileInfoClass())
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if info != nil {
		need := info.Size()
		if need > int(r.OutputBufferLength()) {
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INFO_LENGTH_MISMATCH))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
	}

	rsp := new(QueryInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	rsp.Output = info

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) queryInfoSec(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_QUERY_INFO, pkt)
	r := QueryInfoRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}
	if IsInvalidFileId(fileId) {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}
	if t.conn.serverCtx.getOpen(fileId.HandleId()) == nil {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	log.Tracef("queryInfoSec: addInfo=0x%x outLen=%d", r.AdditionalInformation(), r.OutputBufferLength())
	// Build a minimal valid self-relative descriptor for requested fields.
	ai := r.AdditionalInformation()
	sd := SecurityDescriptor{}
	if ai&OWNER_SECURITY_INFORMATION != 0 {
		sd.OwnerSid = &SID{IdentifierAuthority: SECURITY_NT_AUTHORITY, SubAuthority: []uint32{18}} // LOCAL_SYSTEM
	}
	if ai&GROUP_SECUIRTY_INFORMATION != 0 {
		sd.GroupSid = &SID{IdentifierAuthority: SECURITY_NT_AUTHORITY, SubAuthority: []uint32{18}} // LOCAL_SYSTEM
	}
	if ai&(SACL_SECUIRTY_INFORMATION|LABEL_SECUIRTY_INFORMATION) != 0 {
		// Return a medium-integrity mandatory label (S-1-16-8192).
		// Windows 11 UAC checks this when elevating executables from a share.
		sd.Sacl = &ACL{
			ACE{
				Sid:  &SID{IdentifierAuthority: MANDATORY_LABEL_AUTHORITY, SubAuthority: []uint32{8192}},
				Type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
				Mask: 0, // no mandatory policy (NW=0, NR=0, NX=0)
			},
		}
	}
	if ai&DACL_SECUIRTY_INFORMATION != 0 {
		sd.Dacl = &ACL{
			ACE{
				Sid:  &SID{IdentifierAuthority: WORLD_SID_AUTHORITY, SubAuthority: []uint32{0}}, // Everyone
				Type: ACCESS_ALLOWED_ACE_TYPE,
				Mask: GENERIC_ALL,
			},
		}
	}

	if need := sd.Size(); need > int(r.OutputBufferLength()) {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_BUFFER_TOO_SMALL))
		rsp.ErrorData = &SmallBufferErrorResponse{RequiredBufferLength: uint32(need)}
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(QueryInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	rsp.Output = &sd
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) queryInfo(ctx *compoundContext, pkt []byte) error {
	log.Tracef("QueryInfo")

	c := t.session.conn

	res, err := accept(SMB2_QUERY_INFO, pkt)
	if err != nil {
		return err
	}

	r := QueryInfoRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken quety info format"}
	}

	log.Tracef("query info type: %d", r.InfoType())
	switch r.InfoType() {
	case SMB2_0_INFO_FILE:
		return t.queryInfoFile(ctx, pkt)
	case SMB2_0_INFO_FILESYSTEM:
		return t.queryInfoFileSystem(ctx, pkt)
	case SMB2_0_INFO_SECURITY:
		return t.queryInfoSec(ctx, pkt)
	case SMB2_0_INFO_QUOTA:
		log.Errorf("SMB2_0_INFO_QUOTA unsupported")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}
	log.Errorf("queryInfo: unsupported info type %d", r.InfoType())
	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setBasicInfo(ctx *compoundContext, fileId *FileId, open *Open, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)
	info := FileBasicInformationInfoDecoder(r.Buffer())

	a := new(vfs.Attributes)

	ns := info.LastAccessTime().Nanoseconds()
	if ns != 0 {
		seconds := ns / 1e9
		nanoseconds := ns % 1e9
		a.SetAccessTime(time.Unix(seconds, nanoseconds))
	}
	ns = info.LastWriteTime().Nanoseconds()
	if ns != 0 {
		seconds := ns / 1e9
		nanoseconds := ns % 1e9
		a.SetLastDataModificationTime(time.Unix(seconds, nanoseconds))
	}
	ns = info.ChangeTime().Nanoseconds()
	if ns != 0 {
		seconds := ns / 1e9
		nanoseconds := ns % 1e9
		a.SetLastStatusChangeTime(time.Unix(seconds, nanoseconds))
	}
	ns = info.CreationTime().Nanoseconds()
	if ns != 0 {
		seconds := ns / 1e9
		nanoseconds := ns % 1e9
		a.SetBirthTime(time.Unix(seconds, nanoseconds))
	}

	if !open.isEa {
		if _, err := t.fs.SetAttr(vfs.VfsHandle(fileId.HandleId()), a); err != nil && !c.serverCtx.ignoreSetAttrErr {
			log.Errorf("SetAttr failed: %v", err)
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
	}

	rsp := new(SetInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setEndOfFileInfo(ctx *compoundContext, fileId *FileId, open *Open, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)
	info := FileEndOfFileInformationDecoder(r.Buffer())
	open.ioMu.Lock()
	err := t.fs.Truncate(vfs.VfsHandle(fileId.HandleId()), uint64(info.EndOfFile()))
	open.ioMu.Unlock()
	if err != nil {
		log.Errorf("setEndOfFileInfo: truncate failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(SetInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setEndOfFileInfoEa(ctx *compoundContext, fileId *FileId, open *Open, eaKey string, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)
	info := FileEndOfFileInformationDecoder(r.Buffer())

	open.ioMu.Lock()
	err := t.resizeStream(vfs.VfsHandle(fileId.HandleId()), eaKey, info.EndOfFile())
	open.ioMu.Unlock()
	if err != nil {
		log.Errorf("set stream size %d failed: %v", info.EndOfFile(), err)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, streamWriteStatus(err))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(SetInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setDispositionInfo(ctx *compoundContext, fileId *FileId, open *Open, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)
	info := FileDispositionInformationInfoDecoder(r.Buffer())

	// Check if Windows wants to delete the file or clear the delete flag
	deleteRequested := info.DeletePending() != 0
	log.Tracef("setDispositionInfo: DeletePending=%d", info.DeletePending())

	if !deleteRequested {
		// Windows is clearing the delete flag
		open.deleteAfterClose = false
		rsp := new(SetInfoResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, 0)
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	attrs, err := t.fs.GetAttr(vfs.VfsHandle(fileId.HandleId()))
	if err != nil {
		log.Errorf("Delete failed to get attrs: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if attrs.GetFileType() == vfs.FileTypeDirectory {
		if dir, err := t.fs.ReadDir(vfs.VfsHandle(fileId.HandleId()), 0, 1000); err == nil {
			isEmpty := true
			for _, d := range dir {
				if d.Name != "." && d.Name != ".." {
					isEmpty = false
					break
				}
			}
			if !isEmpty {
				log.Tracef("Delete failed: directory not empty: %v", err)
				rsp := new(ErrorResponse)
				PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_DIRECTORY_NOT_EMPTY))
				return c.sendPacket(rsp, &t.treeConn, ctx)
			}
		}
	}
	open.deleteAfterClose = true

	rsp := new(SetInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setDispositionInfoEa(ctx *compoundContext, fileId *FileId, eaKey string, pkt []byte) error {
	c := t.session.conn

	if err := t.fs.Removexattr(vfs.VfsHandle(fileId.HandleId()), eaKey); err != nil && err != syscall.ENODATA {
		log.Errorf("removexattr failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_FOUND))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(SetInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setRename(ctx *compoundContext, fileId *FileId, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)
	info := FileRenameInformationInfoDecoder(r.Buffer())

	log.Tracef("setRename %s, root %d", info.FileName(), info.RootDirectory())
	to, ok := shareRelativePath(info.FileName())
	if !ok {
		log.Warnf("deny rename to '..' path user=%s target=%q", t.session.username, info.FileName())
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_OBJECT_PATH_SYNTAX_BAD))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}
	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if err := t.fs.Rename(vfs.VfsHandle(fileId.HandleId()), to, int(info.ReplaceIfExists())); err != nil {
		log.Errorf("rename failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if open != nil {
		c.infof("rename: %s -> %s", open.pathName, to)
		if t.conn.serverCtx.onRename != nil {
			t.conn.serverCtx.onRename(open.pathName, to)
		}
	}

	rsp := new(SetInfoResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	sendErr := c.sendPacket(rsp, &t.treeConn, ctx)

	// Notify directory watchers (after response is sent)
	if open != nil && open.pathName != "" {
		t.conn.serverCtx.notifyChange(open.pathName, FILE_ACTION_RENAMED_OLD_NAME)
	}
	if to != "" {
		t.conn.serverCtx.notifyChange(to, FILE_ACTION_RENAMED_NEW_NAME)
	}

	return sendErr
}

func (t *fileTree) setSecInfo(ctx *compoundContext, fileId *FileId, pkt []byte) error {
	log.Tracef("setSecInfo")
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)
	sd := SecurityDescriptorDecoder(r.Buffer())

	a := &vfs.Attributes{}
	changed := false

	// Check Owner SID for POSIX uid (S-1-22-1-<uid>) or NFS uid (S-1-5-88-1-<uid>)
	if ownerBuf := sd.OwnerSid(); ownerBuf != nil {
		sid := SidDecoder(ownerBuf)
		if !sid.IsInvalid() {
			subs := sid.SubAuthority()
			log.Tracef("setSecInfo: owner SID auth=%d subs=%v", sid.IdentifierAuthority(), subs)
			if sid.IdentifierAuthority() == 22 && sid.SubAuthorityCount() == 2 && subs[0] == 1 {
				a.SetUID(subs[1])
				changed = true
			} else if sid.IdentifierAuthority() == 5 && sid.SubAuthorityCount() == 3 && subs[0] == 88 && subs[1] == 1 {
				a.SetUID(subs[2])
				changed = true
			}
		}
	} else {
		log.Tracef("setSecInfo: no owner SID")
	}

	// Check Group SID for POSIX gid (S-1-22-2-<gid>) or NFS gid (S-1-5-88-2-<gid>)
	if groupBuf := sd.GroupSid(); groupBuf != nil {
		sid := SidDecoder(groupBuf)
		if !sid.IsInvalid() {
			subs := sid.SubAuthority()
			log.Tracef("setSecInfo: group SID auth=%d subs=%v", sid.IdentifierAuthority(), subs)
			if sid.IdentifierAuthority() == 22 && sid.SubAuthorityCount() == 2 && subs[0] == 2 {
				a.SetGID(subs[1])
				changed = true
			} else if sid.IdentifierAuthority() == 5 && sid.SubAuthorityCount() == 3 && subs[0] == 88 && subs[1] == 2 {
				a.SetGID(subs[2])
				changed = true
			}
		}
	} else {
		log.Tracef("setSecInfo: no group SID")
	}

	// Try to extract NFS mode SID from DACL or convert standard ACLs to mode
	if daclBuf := sd.Dacl(); daclBuf != nil {
		dacl := AclDecoder(daclBuf)
		log.Tracef("setSecInfo: DACL with %d ACEs", dacl.AceCount())
		aceBuf := dacl.Aces()
		foundNfsMode := false
		for i := 0; i < int(dacl.AceCount()); i++ {
			ace := AceDecoder(aceBuf)
			sidBuf := ace.Sid()
			sid := SidDecoder(sidBuf)
			subs := sid.SubAuthority()
			log.Tracef("setSecInfo: ACE[%d] type=%d mask=0x%x auth=%d subs=%v", i, ace.Type(), ace.Mask(), sid.IdentifierAuthority(), subs)
			if sid.SubAuthorityCount() == 3 && subs[0] == 88 && subs[1] == 3 {
				// NFS Mode Sid - apply Unix permissions
				mode := subs[2]
				log.Tracef("setSecInfo: NFS mode SID found, mode=0%o", mode)
				a.SetUnixMode(mode)
				changed = true
				foundNfsMode = true
				break
			}
			aceBuf = aceBuf[ace.Size():]
		}
		if !foundNfsMode {
			current := uint32(0)
			if cur, err := t.fs.GetAttr(vfs.VfsHandle(fileId.HandleId())); err == nil {
				current, _ = cur.GetUnixMode()
			}
			if mode, ok := modeFromDacl(dacl, current); ok {
				log.Tracef("setSecInfo: derived mode=0%o from DACL (was 0%o)", mode, current&0o777)
				a.SetUnixMode(mode)
				changed = true
			} else {
				log.Tracef("setSecInfo: DACL names no Unix owner/group, mode unchanged")
			}
		}
	} else {
		log.Tracef("setSecInfo: no DACL")
	}

	log.Tracef("setSecInfo: changed=%v", changed)
	if changed {
		t.fs.SetAttr(vfs.VfsHandle(fileId.HandleId()), a)
	}

	// Accept security descriptor even if we can't fully preserve NTFS ACLs
	// This is necessary for Windows copy operations to succeed
	rsp := &SetInfoResponse{}
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setPosixInfo(ctx *compoundContext, fileId *FileId, pkt []byte) error {
	log.Tracef("setPosixInfo")
	c := t.session.conn

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)
	buf := r.Buffer()

	a := &vfs.Attributes{}
	changed := false

	// POSIX info layout: 80 bytes fixed + variable SIDs
	// Offset 76: Mode (uint32)
	if len(buf) >= 80 {
		mode := le.Uint32(buf[76:80])
		if mode != 0 {
			a.SetUnixMode(mode)
			changed = true
		}
	}

	// Offset 80+: OwnerSid then GroupSid (variable length)
	if len(buf) > 80 {
		sidBuf := buf[80:]
		// Parse owner SID
		if len(sidBuf) >= 8 {
			subCount := int(sidBuf[1])
			sidSize := 8 + subCount*4
			if len(sidBuf) >= sidSize {
				sid := SidDecoder(sidBuf[:sidSize])
				if !sid.IsInvalid() {
					subs := sid.SubAuthority()
					if sid.IdentifierAuthority() == 22 && subCount == 2 && subs[0] == 1 {
						a.SetUID(subs[1])
						changed = true
					}
				}
				sidBuf = sidBuf[sidSize:]
			}
		}
		// Parse group SID
		if len(sidBuf) >= 8 {
			subCount := int(sidBuf[1])
			sidSize := 8 + subCount*4
			if len(sidBuf) >= sidSize {
				sid := SidDecoder(sidBuf[:sidSize])
				if !sid.IsInvalid() {
					subs := sid.SubAuthority()
					if sid.IdentifierAuthority() == 22 && subCount == 2 && subs[0] == 2 {
						a.SetGID(subs[1])
						changed = true
					}
				}
			}
		}
	}

	if changed {
		if _, err := t.fs.SetAttr(vfs.VfsHandle(fileId.HandleId()), a); err != nil {
			log.Errorf("setPosixInfo: SetAttr failed: %v", err)
		}
	}

	rsp := &SetInfoResponse{}
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) setInfo(ctx *compoundContext, pkt []byte) error {
	log.Tracef("SetInfo")
	c := t.session.conn
	if t.isUserReadOnly() {
		log.Warnf("deny setinfo for read-only user=%s", t.session.username)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}
	if t.isShareReadOnly() {
		log.Warnf("deny setinfo on read-only share")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	res, _ := accept(SMB2_SET_INFO, pkt)
	r := SetInfoRequestDecoder(res)

	fileId := r.FileId().Decode()
	if ctx != nil && ctx.fileId != nil {
		fileId = ctx.fileId
	}

	if IsInvalidFileId(fileId) {
		log.Errorf("SetInfo: invalid fileid")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	open := t.conn.serverCtx.getOpen(fileId.HandleId())
	if open == nil {
		log.Errorf("delete: no open")
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	log.Tracef("SetInfo: %d class", r.FileInfoClass())

	// Flush any pending writes to ensure data is on disk before SetInfo
	t.fs.Flush(vfs.VfsHandle(fileId.HandleId()))

	switch r.InfoType() {
	case SMB2_0_INFO_SECURITY:
		return t.setSecInfo(ctx, fileId, pkt)
	}

	status := uint32(0)
	switch r.FileInfoClass() {
	case FileBasicInformation:
		return t.setBasicInfo(ctx, fileId, open, pkt)
	case FileEndOfFileInformation:
		if open.isEa {
			return t.setEndOfFileInfoEa(ctx, fileId, open, open.eaKey, pkt)
		}
		return t.setEndOfFileInfo(ctx, fileId, open, pkt)
	case FileDispositionInformation:
		if open.isEa {
			return t.setDispositionInfoEa(ctx, fileId, open.eaKey, pkt)
		}
		return t.setDispositionInfo(ctx, fileId, open, pkt)
	case FileRenameInformation:
		if !open.isEa {
			return t.setRename(ctx, fileId, pkt)
		}
		status = uint32(STATUS_NOT_SUPPORTED)
	case FilePosixInformation:
		return t.setPosixInfo(ctx, fileId, pkt)
	case FileAllocationInformation:
		rsp := &SetInfoResponse{}
		PrepareResponse(&rsp.PacketHeader, pkt, 0)
		return c.sendPacket(rsp, &t.treeConn, ctx)
	default:
		status = uint32(STATUS_NOT_SUPPORTED)
		log.Errorf("unsupported class %d in SetInfo", r.FileInfoClass())
	}

	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, status)

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *fileTree) oplockBreak(ctx *compoundContext, pkt []byte) error {
	log.Tracef("OplockBreak")
	c := t.session.conn

	res, err := accept(SMB2_OPLOCK_BREAK, pkt)
	if err != nil {
		return err
	}
	if len(res) < 2 {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_PARAMETER))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	structSize := binary.LittleEndian.Uint16(res[:2])
	var body []byte
	switch structSize {
	case 24:
		if len(res) < 24 {
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_PARAMETER))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
		body = append([]byte(nil), res[:24]...)
	case 36:
		if len(res) < 36 {
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_PARAMETER))
			return c.sendPacket(rsp, &t.treeConn, ctx)
		}
		body = append([]byte(nil), res[:36]...)
	default:
		log.Tracef("OplockBreak: unsupported structure size=%d", structSize)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_PARAMETER))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := &OplockBreakResponse{Body: body}
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	log.Tracef("OplockBreak: ack structure size=%d", structSize)

	return c.sendPacket(rsp, &t.treeConn, ctx)
}
