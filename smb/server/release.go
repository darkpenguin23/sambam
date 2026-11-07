package smb2

import (
	"github.com/sambam/sambam/smb/vfs"
)

// releaseOpen frees everything a file handle holds: a pending
// delete-on-close, its entry in the open table, the VFS handle, a pending
// CHANGE_NOTIFY and that notify's fsnotify watch. It serves CLOSE as well as
// the cleanup when a tree, session or connection goes away while handles are
// still open. It returns the delete-on-close error, if any.
func (d *Server) releaseOpen(fileId uint64, open *Open, fs vfs.VFSFileSystem) error {
	var deleteErr error
	if open != nil && open.deleteAfterClose && fs != nil {
		deleteErr = fs.Unlink(vfs.VfsHandle(fileId))
		if deleteErr == nil && open.pathName != "" {
			d.notifyChange(open.pathName, FILE_ACTION_REMOVED)
		}
	}

	d.deleteOpen(fileId)
	if fs != nil {
		fs.Close(vfs.VfsHandle(fileId))
	}

	if open != nil && open.notifyCancel != nil {
		select {
		case open.notifyCancel <- struct{}{}:
		default:
		}
	}
	if open != nil && open.fsWatchPath != "" {
		d.removeFsWatch(open.fsWatchPath)
	}
	return deleteErr
}

// releaseOpens releases the handles of this connection that match. It is
// called on LOGOFF, TREE_DISCONNECT and when the connection ends; before,
// such handles (and their file descriptors) stayed open forever.
func (c *conn) releaseOpens(reason string, match func(*Open) bool) {
	d := c.serverCtx
	if d == nil {
		return
	}
	d.lock.Lock()
	var victims []*Open
	for _, o := range d.opens {
		if o.session != nil && o.session.conn == c && match(o) {
			victims = append(victims, o)
		}
	}
	d.lock.Unlock()

	for _, o := range victims {
		if err := d.releaseOpen(o.fileId, o, o.fs); err != nil {
			c.warnf("%s: delete-on-close of %s failed: %v", reason, o.pathName, err)
		}
	}
	if len(victims) > 0 {
		c.debugf("%s: released %d open handle(s)", reason, len(victims))
	}
}
