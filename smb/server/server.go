package smb2

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/sambam/sambam/smb/internal/crypto/ccm"
	"github.com/sambam/sambam/smb/internal/crypto/cmac"
	. "github.com/sambam/sambam/smb/internal/erref"
	. "github.com/sambam/sambam/smb/internal/smb2"
	"github.com/sambam/sambam/smb/vfs"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/maps"
)

const DEFAULT_IOPS = 32

type Server struct {
	maxCreditBalance uint16 // if it's zero, clientMaxCreditBalance is used. (See feature.go for more details)
	negotiator       ServerNegotiator
	authenticator    Authenticator

	serverStartTime time.Time
	serverGuid      Guid

	listeners []net.Listener
	active    bool

	shares     map[string]vfs.VFSFileSystem
	origShares map[string]vfs.VFSFileSystem
	shareGuest map[string]bool
	shareUsers map[string]map[string]struct{}
	authUsers  map[string]struct{}
	userRO     map[string]bool

	opens       map[uint64]*Open
	opensByGuid map[Guid]*Open

	allowGuest           bool
	enableSMB3Encryption bool

	maxIOReads  int
	maxIOWrites int

	xattrs bool

	ignoreSetAttrErr bool

	hideDotfiles bool

	activeConns map[*conn]struct{}

	acceptSingleConn bool

	onConnect  func(remoteAddr string)
	onReject   func(remoteAddr string)
	allowConn  func(remoteAddr string) bool
	onRename   func(from, to string)
	onDetect   func(action, path string)
	onAuthFail func(remoteAddr, username string)

	fsWatcher   *fsnotify.Watcher
	fsWatchRefs map[string]int
	fsWatchRoot map[string]string // watched path → share base path (for path translation)

	lock sync.Mutex
}

type OpLockState uint8

const (
	LOCKSTATE_NONE OpLockState = iota
	LOCKSTATE_HELD
	LOCKSTATE_BREAKING
)

type notifyEvent struct {
	Action   uint32
	FileName string
}

type Open struct {
	ioMu                        sync.Mutex
	fileId                      uint64
	durableFileId               uint64
	session                     *session
	tree                        *treeConn
	grantedAccess               uint32
	oplockLevel                 uint8
	oplockState                 OpLockState
	oplockTimeout               time.Duration
	isDurable                   bool
	durableOpenTimeout          time.Duration
	durableOpenScavengerTimeout time.Duration
	durableOwner                uint64
	currentEaIndex              uint32
	currentQuotaIndex           uint32
	lockCount                   int
	pathName                    string
	fileName                    string
	resumeKey                   [24]byte
	createOptions               uint32
	deleteAfterClose            bool
	createDisposition           uint32
	fileAttributes              uint32
	clientGuid                  Guid
	lease                       *Lease
	isResilient                 bool
	resiliencyTimeout           time.Duration
	resilientOpenTimeout        time.Duration
	lockSequenceArray           [64]byte
	notifyReq                   []byte
	notifyReqAsyncId            uint64
	notifyCancel                chan struct{}
	notifyCh                    chan notifyEvent
	notifyWatchTree             bool
	isEa                        bool
	eaKey                       string
	isSymlink                   bool
	fsWatchPath                 string // real filesystem path being watched (persistent for handle lifetime)
	createGuid                  Guid
	appInstanceId               Guid
	isPersistent                bool
	channelSequence             uint16
	outstandingRequestCoun      int
	outstandingPreRequestCount  int
}

type Lease struct {
}

// Negotiator contains options for func (*Dialer) Dial.
type ServerNegotiator struct {
	RequireMessageSigning bool   // enforce signing?
	SpecifiedDialect      uint16 // if it's zero, clientDialects is used. (See feature.go for more details)
	Spnego                *spnegoServer
}

type ConnState int

const (
	STATE_NEGOTIATE = ConnState(iota)
	STATE_SESSION_SETUP
	STATE_SESSION_SETUP_CHALLENGE
	STATE_SESSION_ACTIVE
)

var (
	SRVSVC_GUID  = FileId{}
	INVALID_GUID = FileId{
		Persistent: [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		Volatile:   [8]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}
)

type ServerConfig struct {
	AllowGuest           bool
	EnableSMB3Encryption bool
	MaxIOReads           int
	MaxIOWrites          int
	Xatrrs               bool
	IgnoreSetAttrErr     bool
	AcceptSingleConn     bool
	HideDotfiles         bool                              // Hide files starting with '.'
	ShareGuest           map[string]bool                   // share -> allow guest access
	ShareAllowUsers      map[string][]string               // share -> allowed usernames (empty => all)
	AuthUsers            []string                          // configured authenticated users
	UserReadonly         map[string]bool                   // username(lowercase) -> readonly
	AllowConn            func(remoteAddr string) bool      // Return true to allow a client connection
	OnReject             func(remoteAddr string)           // Called when a client is rejected by allow policy
	OnConnect            func(remoteAddr string)           // Called when a client connects
	OnRename             func(from, to string)             // Called on file rename
	OnDetect             func(action, path string)         // Called on fsnotify event
	OnAuthFail           func(remoteAddr, username string) // Called on auth failure
}

func NewServer(cfg *ServerConfig, a Authenticator, shares map[string]vfs.VFSFileSystem) *Server {
	newShares := map[string]vfs.VFSFileSystem{}
	for i, v := range shares {
		newShares[strings.ToUpper(i)] = v
	}
	shareUsers := map[string]map[string]struct{}{}
	authUsers := map[string]struct{}{}
	for _, user := range cfg.AuthUsers {
		u := strings.ToLower(strings.TrimSpace(user))
		if u != "" {
			authUsers[u] = struct{}{}
		}
	}
	shareGuest := map[string]bool{}
	for share, guest := range cfg.ShareGuest {
		if guest {
			shareGuest[strings.ToUpper(share)] = true
		}
	}
	for share, users := range cfg.ShareAllowUsers {
		key := strings.ToUpper(share)
		set := map[string]struct{}{}
		for _, u := range users {
			u = strings.TrimSpace(strings.ToLower(u))
			if u != "" {
				set[u] = struct{}{}
			}
		}
		if len(set) > 0 {
			shareUsers[key] = set
		}
	}
	userRO := map[string]bool{}
	for user, ro := range cfg.UserReadonly {
		if ro {
			userRO[strings.ToLower(strings.TrimSpace(user))] = true
		}
	}

	srv := &Server{
		authenticator:        a,
		shares:               newShares,
		origShares:           shares,
		shareGuest:           shareGuest,
		shareUsers:           shareUsers,
		authUsers:            authUsers,
		userRO:               userRO,
		opens:                map[uint64]*Open{},
		allowGuest:           cfg.AllowGuest,
		enableSMB3Encryption: cfg.EnableSMB3Encryption,
		maxIOReads:           cfg.MaxIOReads,
		maxIOWrites:          cfg.MaxIOWrites,
		xattrs:               cfg.Xatrrs,
		ignoreSetAttrErr:     cfg.IgnoreSetAttrErr,
		hideDotfiles:         cfg.HideDotfiles,
		activeConns:          map[*conn]struct{}{},
		acceptSingleConn:     cfg.AcceptSingleConn,
		allowConn:            cfg.AllowConn,
		onReject:             cfg.OnReject,
		onConnect:            cfg.OnConnect,
		onRename:             cfg.OnRename,
		onDetect:             cfg.OnDetect,
		onAuthFail:           cfg.OnAuthFail,
		fsWatchRefs:          map[string]int{},
		fsWatchRoot:          map[string]string{},
	}

	if w, err := fsnotify.NewWatcher(); err == nil {
		srv.fsWatcher = w
	} else {
		log.Warnf("fsnotify: failed to create watcher: %v", err)
	}

	return srv
}

func (d *Server) isUserReadOnly(username string) bool {
	return d.userRO[strings.ToLower(strings.TrimSpace(username))]
}

func (d *Server) isShareAllowed(shareName, username string) bool {
	allowed, ok := d.shareUsers[strings.ToUpper(shareName)]
	if !ok || len(allowed) == 0 {
		return true
	}
	_, ok = allowed[strings.ToLower(strings.TrimSpace(username))]
	return ok
}

func (d *Server) isShareGuest(shareName string) bool {
	return d.shareGuest[strings.ToUpper(shareName)]
}

func (d *Server) isConfiguredUser(username string) bool {
	_, ok := d.authUsers[strings.ToLower(strings.TrimSpace(username))]
	return ok
}

func (d *Server) Serve(addr string) error {
	return d.ServeMany([]string{addr})
}

func (d *Server) ServeMany(addrs []string) error {
	if len(addrs) == 0 {
		return fmt.Errorf("no listen addresses provided")
	}

	_, err := rand.Read(d.serverGuid[:])
	if err != nil {
		log.Errorf("failed to generate server guid")
		return &InternalError{err.Error()}
	}
	rand.Read(SRVSVC_GUID.Persistent[:])
	rand.Read(SRVSVC_GUID.Volatile[:])

	listeners := make([]net.Listener, 0, len(addrs))
	for _, addr := range addrs {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			for _, opened := range listeners {
				_ = opened.Close()
			}
			return err
		}
		listeners = append(listeners, listener)
	}
	d.listeners = listeners
	defer func() {
		for _, l := range listeners {
			_ = l.Close()
		}
	}()
	d.active = true

	if d.fsWatcher != nil {
		d.startFsWatcher()
	}

	var wg sync.WaitGroup
	for _, listener := range listeners {
		wg.Add(1)
		go func(listener net.Listener) {
			defer wg.Done()
			d.serveListener(listener)
		}(listener)
	}
	wg.Wait()
	return nil
}

func (d *Server) serveListener(listener net.Listener) {
	for d.active {
		// Accept a new connection.
		c, err := listener.Accept()
		if err != nil {
			if !d.active {
				return
			}
			continue
		}

		remoteAddr := c.RemoteAddr().String()
		if d.allowConn != nil && !d.allowConn(remoteAddr) {
			if d.onReject != nil {
				d.onReject(remoteAddr)
			}
			_ = c.Close()
			continue
		}

		// Call connection callback if set
		if d.onConnect != nil {
			d.onConnect(remoteAddr)
		}

		ctx, cancel := context.WithCancel(context.Background())

		maxCreditBalance := d.maxCreditBalance
		if maxCreditBalance == 0 {
			maxCreditBalance = clientMaxCreditBalance
		}
		a := openAccount(maxCreditBalance)

		conn := &conn{
			t:                   direct(c),
			remoteAddr:          remoteAddr,
			clientOS:            "unknown",
			clientOSSrc:         "initial",
			sessions:            make(map[uint64]*session),
			outstandingRequests: newOutstandingRequests(),
			account:             a,
			rdone:               make(chan struct{}, 1),
			wdone:               make(chan struct{}, 1),
			write:               make(chan []byte, 10),
			werr:                make(chan error, 1),
			ctx:                 ctx,
			cancel:              cancel,
			serverCtx:           d,
			serverState:         STATE_NEGOTIATE,
			cipherId:            AES128GCM,
			hashId:              SHA512,
			treeMapByName:       make(map[string]treeOps),
			treeMapById:         make(map[uint32]treeOps),
		}

		d.lock.Lock()
		d.activeConns[conn] = struct{}{}
		d.lock.Unlock()
		go conn.runReciever()
		go conn.runSender()

		run := func() {
			if err := conn.Run(); err != nil {
				if !isNormalDisconnect(err) {
					conn.errorf("err: %v", err)
				}
				conn.infof("disconnect")
				c.Close()
				if d.acceptSingleConn {
					d.active = false
				}
			}
		}
		if d.acceptSingleConn {
			run()
		} else {
			// Handle the connection in a new goroutine.
			go run()
		}
	}
}

func (d *Server) Shutdown() {
	d.active = false
	for _, l := range d.listeners {
		_ = l.Close()
	}
	if d.fsWatcher != nil {
		_ = d.fsWatcher.Close()
	}
	d.lock.Lock()
	conns := make([]*conn, 0, len(d.activeConns))
	for c := range d.activeConns {
		conns = append(conns, c)
	}
	d.lock.Unlock()
	for _, c := range conns {
		c.shutdown()
	}
}

func (c *conn) Run() error {
	for {
		pkt, compCtx, err := c.srvRecv()
		if err != nil {
			return err
		}

		p := PacketCodec(pkt)
		if p.Flags()&SMB2_FLAGS_ASYNC_COMMAND != 0 {
			log.Tracef("Async command received")
		}

		// Route this request to the matching session for signing/encryption
		// and tree/session authorization checks.
		switch p.Command() {
		case SMB2_NEGOTIATE, SMB_COM_NEGOTIATE, SMB2_SESSION_SETUP, SMB2_ECHO:
			// no-op
		default:
			if c.useSession() {
				if c.setActiveSession(p.SessionId()) == nil {
					rsp := new(ErrorResponse)
					PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_USER_SESSION_DELETED))
					c.sendPacket(rsp, nil, compCtx)
					continue
				}
			}
		}

		switch p.Command() {
		case SMB2_NEGOTIATE, SMB_COM_NEGOTIATE:
			err = c.negotiate(pkt)
		case SMB2_SESSION_SETUP:
			err = c.sessionSetup(pkt)
		case SMB2_LOGOFF:
			err = c.logoff(pkt)
		case SMB2_TREE_CONNECT:
			err = c.treeConnect(pkt)
		case SMB2_TREE_DISCONNECT:
			err = c.treeDisconnect(pkt)
		case SMB2_ECHO:
			err = c.echo(compCtx, pkt)
		default:
			p := PacketCodec(pkt)
			tc, ok := c.treeMapById[p.TreeId()]
			if !ok {
				rsp := new(ErrorResponse)
				PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NETWORK_NAME_DELETED))
				c.sendPacket(rsp, nil, compCtx)
				continue
			}

			// if prev transaction req failed, don't forward it
			if compCtx != nil && compCtx.lastStatus != 0 {
				rsp := new(ErrorResponse)
				PrepareResponse(&rsp.PacketHeader, pkt, uint32(compCtx.lastStatus))
				c.sendPacket(rsp, tc.getTree(), compCtx)
				continue
			}

			switch p.Command() {
			case SMB2_CREATE:
				err = tc.create(compCtx, pkt)
			case SMB2_CLOSE:
				err = tc.close(compCtx, pkt)
			case SMB2_FLUSH:
				err = tc.flush(compCtx, pkt)
			case SMB2_READ:
				err = tc.read(compCtx, pkt)
			case SMB2_WRITE:
				err = tc.write(compCtx, pkt)
			case SMB2_LOCK:
				err = tc.lock(compCtx, pkt)
			case SMB2_IOCTL:
				err = tc.ioctl(compCtx, pkt)
			case SMB2_CANCEL:
				err = tc.cancel(compCtx, pkt)
			case SMB2_QUERY_DIRECTORY:
				err = tc.queryDirectory(compCtx, pkt)
			case SMB2_CHANGE_NOTIFY:
				err = tc.changeNotify(compCtx, pkt)
			case SMB2_QUERY_INFO:
				err = tc.queryInfo(compCtx, pkt)
			case SMB2_SET_INFO:
				err = tc.setInfo(compCtx, pkt)
			case SMB2_OPLOCK_BREAK:
				err = tc.oplockBreak(compCtx, pkt)
			default:
				rsp := new(ErrorResponse)
				PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
				c.sendPacket(rsp, tc.getTree(), compCtx)
				continue
			}
		}
		if err != nil {
			c.errorf("err: %v", err)
			return err
		}
	}
}

func (c *conn) echo(ctx *compoundContext, pkt []byte) error {
	c.tracef("Echo")

	p := PacketCodec(pkt)
	rsp := new(EchoResponse)

	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = 1

	return c.sendPacket(rsp, nil, nil)
}

func (c *conn) negotiate(pkt []byte) error {
	c.debugf("negotiate")

	if c.serverState != STATE_NEGOTIATE {
		if c.useSession() {
			// Do not reset an active authenticated session because some Windows
			// clients probe with extra negotiate/session traffic on the same TCP
			// connection while file operations are in progress.
			rsp := new(ErrorResponse)
			PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NETWORK_SESSION_EXPIRED))
			return c.sendPacket(rsp, nil, nil)
		}
	}

	return c.serverCtx.negotiator.negotiate(c, pkt)
}

func (c *conn) sessionSetup(pkt []byte) error {
	c.debugf("session setup")

	if c.useSession() {
		p := PacketCodec(pkt)
		reqSid := p.SessionId()

		if reqSid != 0 {
			// Check if this is step 2 of a pending session binding.
			if c.pendingSetup != nil && c.pendingSetup.sessionId == reqSid {
				return c.sessionSetupCompleteBinding(pkt)
			}

			s := c.getSession(reqSid)
			if s == nil {
				c.tracef("session setup denied on active connection: unknown req sid=%d", reqSid)
				rsp := new(ErrorResponse)
				PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_ACCESS_DENIED))
				return c.sendPacket(rsp, nil, nil)
			}

			c.setActiveSession(reqSid)
			rsp := &SessionSetupResponse{
				SessionFlags: s.sessionFlags,
			}
			rsp.Flags = 1
			rsp.CreditRequestResponse = p.CreditRequest()
			rsp.CreditCharge = 0
			rsp.MessageId = p.MessageId()
			rsp.SessionId = s.sessionId
			return c.sendPacket(rsp, nil, nil)
		}

		// sid=0 on an active connection: the client wants a new session
		// (e.g. Windows UAC elevation binding a second session).
		return c.sessionSetupNewBinding(pkt)
	}

	switch c.serverState {
	case STATE_NEGOTIATE:
		return c.sessionServerSetup(pkt)
	case STATE_SESSION_SETUP, STATE_SESSION_SETUP_CHALLENGE:
		return c.sessionServerSetupChallenge(pkt)
	default:
		break
	}

	c.warnf("wrong connection state: %d", c.serverState)
	return &InvalidRequestError{"wrong connction state"}
}

func (c *conn) logoff(pkt []byte) error {
	c.debugf("logoff")

	p := PacketCodec(pkt)
	rsp := new(LogoffResponse)

	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = 1

	return c.sendPacket(rsp, nil, nil)
}

func (c *conn) treeConnect(pkt []byte) error {
	c.debugf("tree connect")

	p := PacketCodec(pkt)

	res, err := accept(SMB2_TREE_CONNECT, pkt)
	if err != nil {
		return err
	}

	r := TreeConnectRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken tree connect format"}
	}

	c.debugf("tree connect path: %s", r.Path())

	rsp := new(TreeConnectResponse)
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = 1

	if strings.HasSuffix(r.Path(), "\\IPC$") {
		rsp.ShareType = SMB2_SHARE_TYPE_PIPE
		rsp.MaximalAccess = SYNCHRONIZE | WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE |
			FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
			FILE_EXECUTE | FILE_READ_EA | FILE_WRITE_EA |
			FILE_READ_DATA | FILE_WRITE_DATA | FILE_DELETE_CHILD

		var tc *treeConn
		if t, ok := c.treeMapByName["\\IPC$"]; ok {
			rsp.TreeId = t.getTree().treeId
			tc = t.getTree()
			tc.refCount++
		} else {
			shares := maps.Keys(c.serverCtx.origShares)
			ft := &ipcTree{
				treeConn: treeConn{
					session:    c.session,
					treeId:     randint32(),
					shareFlags: 0,
					path:       "\\IPC$",
					refCount:   1,
				},
				shares: shares,
			}

			tc = &ft.treeConn
			c.treeMapByName["\\IPC$"] = ft
			c.treeMapById[tc.treeId] = ft
			c.tracef("new ipc tree %d", tc.treeId)
		}

		err = c.sendPacket(rsp, tc, nil)
	} else {
		parts := strings.Split(r.Path(), "\\")
		if len(parts) < 1 {
			rsp.Status = uint32(STATUS_BAD_NETWORK_NAME)
			return c.sendPacket(rsp, nil, nil)
		}
		path := parts[len(parts)-1]

		fs, ok := c.serverCtx.shares[strings.ToUpper(path)]
		if !ok {
			if fs, ok = c.serverCtx.shares[strings.ToUpper(path)+"$"]; !ok {
				c.tracef("shares: %v", maps.Keys(c.serverCtx.shares))
				rsp.Status = uint32(STATUS_BAD_NETWORK_NAME)
				return c.sendPacket(rsp, nil, nil)
			}
		}
		isGuestSession := c.session == nil || c.session.sessionFlags&SMB2_SESSION_FLAG_IS_GUEST != 0 || strings.EqualFold(c.session.username, "guest") || c.session.username == ""
		if isGuestSession {
			if !c.serverCtx.isShareGuest(path) {
				c.warnf("share denied (guest disabled): %s user=%s", path, c.session.username)
				rsp.Status = uint32(STATUS_ACCESS_DENIED)
				return c.sendPacket(rsp, nil, nil)
			}
		} else if !c.serverCtx.isShareAllowed(path, c.session.username) {
			c.warnf("share denied: %s user=%s", path, c.session.username)
			rsp.Status = uint32(STATUS_ACCESS_DENIED)
			return c.sendPacket(rsp, nil, nil)
		}

		rsp.ShareType = SMB2_SHARE_TYPE_DISK
		rsp.MaximalAccess = SYNCHRONIZE | WRITE_OWNER | WRITE_DAC | READ_CONTROL | DELETE |
			FILE_READ_ATTRIBUTES | FILE_EXECUTE | FILE_READ_EA | FILE_READ_DATA

		var tc *treeConn
		if t, ok := c.treeMapByName[path]; ok {
			rsp.TreeId = t.getTree().treeId
			tc = t.getTree()
			tc.refCount++
		} else {
			maxIOWrites, maxIoReads := DEFAULT_IOPS, DEFAULT_IOPS
			if c.serverCtx.maxIOReads > 0 {
				maxIoReads = c.serverCtx.maxIOReads
			}
			if c.serverCtx.maxIOWrites > 0 {
				maxIOWrites = c.serverCtx.maxIOWrites
			}
			ft := &fileTree{
				treeConn: treeConn{
					session:    c.session,
					treeId:     randint32(),
					shareFlags: 0,
					path:       path,
					refCount:   1,
				},
				fs:         fs,
				openFiles:  make(map[uint64]bool),
				ioReadSem:  make(chan struct{}, maxIoReads),
				ioWriteSem: make(chan struct{}, maxIOWrites),
			}

			tc = &ft.treeConn
			c.treeMapByName[path] = ft
			c.treeMapById[tc.treeId] = ft
			c.infof("mounted share: %s", path)
		}

		err = c.sendPacket(rsp, tc, nil)
	}

	return err
}

func (c *conn) treeDisconnect(pkt []byte) error {
	c.debugf("tree disconnect")

	p := PacketCodec(pkt)

	tc, ok := c.treeMapById[p.TreeId()]
	if !ok {
		c.warnf("tree doesn't exist: %d", p.TreeId())
	}

	var tree *treeConn = nil
	if tc != nil {
		tree = tc.getTree()
		tree.refCount--
		if tree.refCount == 0 {
			if tree.path != "\\IPC$" {
				c.infof("unmounted share: %s", tree.path)
			}
			delete(c.treeMapByName, tree.path)
			delete(c.treeMapById, tree.treeId)
		}
	}

	rsp := new(TreeDisconnectResponse)
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.MessageId = p.MessageId()
	rsp.Flags = 1

	return c.sendPacket(rsp, tree, nil)
}

func (n *ServerNegotiator) negotiate(conn *conn, pkt []byte) error {
	p := PacketCodec(pkt)
	if p.IsSmb1() {
		n.SpecifiedDialect = SMB2
		rsp, _ := n.makeResponse(conn)
		return conn.sendPacket(rsp, nil, nil)
	}

	res, err := accept(SMB2_NEGOTIATE, pkt)
	if err != nil {
		return err
	}

	r := NegotiateRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken negotiate response format"}
	}

	n.SpecifiedDialect = uint16(SMB2)
	for _, d := range r.Dialects() {
		if d > n.SpecifiedDialect && d <= SMB311 {
			n.SpecifiedDialect = d
		}
	}

	if n.SpecifiedDialect == SMB2 {
		n.SpecifiedDialect = SMB210
	}

	if n.SpecifiedDialect == UnknownSMB {
		return &InvalidResponseError{"unexpected dialect returned"}
	}

	conn.requireSigning = n.RequireMessageSigning || r.SecurityMode()&SMB2_NEGOTIATE_SIGNING_REQUIRED != 0
	conn.capabilities = serverCapabilities & r.Capabilities()
	conn.dialect = n.SpecifiedDialect
	conn.maxTransactSize = serverMaxTransactSize
	conn.maxReadSize = serverMaxReadSize
	conn.maxWriteSize = serverMaxWriteSize
	conn.sequenceWindow = 1

	// conn.gssNegotiateToken = r.SecurityBuffer()
	// conn.clientGuid = n.ClientGuid
	// copy(conn.serverGuid[:], r.ServerGuid())

	n.Spnego = newSpnegoServer([]Authenticator{conn.serverCtx.authenticator})
	outputToken, _ := n.Spnego.initSecContext()
	signingMode := "optional"
	if conn.requireSigning {
		signingMode = "required"
	}
	conn.infof("negotiated dialect=%s signing=%s", dialectName(conn.dialect), signingMode)

	if conn.dialect != SMB311 {
		rsp, _ := n.makeResponse(conn)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(0))
		rsp.SecurityBuffer = outputToken
		err := conn.sendPacket(rsp, nil, nil)
		conn.negotiatePreauthHash = conn.preauthIntegrityHashValue
		return err
	}

	// handle context for SMB311
	list := r.NegotiateContextList()
	for count := r.NegotiateContextCount(); count > 0; count-- {
		ctx := NegotiateContextDecoder(list)
		if ctx.IsInvalid() {
			return &InvalidResponseError{"broken negotiate context format"}
		}

		switch ctx.ContextType() {
		case SMB2_PREAUTH_INTEGRITY_CAPABILITIES:
			d := HashContextDataDecoder(ctx.Data())
			if d.IsInvalid() {
				return &InvalidResponseError{"broken hash context data format"}
			}

			algs := d.HashAlgorithms()

			if len(algs) != 1 {
				return &InvalidResponseError{"multiple hash algorithms"}
			}

			conn.preauthIntegrityHashId = algs[0]
			conn.calcPreauthHash(pkt)
		case SMB2_ENCRYPTION_CAPABILITIES:
			d := CipherContextDataDecoder(ctx.Data())
			if d.IsInvalid() {
				return &InvalidResponseError{"broken cipher context data format"}
			}

			ciphs := d.Ciphers()
			for _, ciph := range ciphs {
				if ciph == AES128CCM || ciph == AES128GCM {
					conn.cipherId = ciph
					break
				}
			}

			switch conn.cipherId {
			case AES128CCM:
			case AES128GCM:
			default:
				return &InvalidResponseError{"unknown cipher algorithm"}
			}
		case SMB2_POSIX_EXTENSIONS_AVAILABLE:
			conn.posixExtensions = true
			conn.setClientOS("linux", "posix negotiate context", clientOSPrioPOSIX)
			conn.debugf("POSIX extensions negotiated")
		default:
			// skip unsupported context
		}

		off := ctx.Next()

		if len(list) < off {
			list = nil
		} else {
			list = list[off:]
		}
	}

	rsp, _ := n.makeResponse(conn)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(0))
	rsp.SecurityBuffer = outputToken
	err = conn.sendPacket(rsp, nil, nil)
	conn.negotiatePreauthHash = conn.preauthIntegrityHashValue
	return err
}

func (n *ServerNegotiator) makeResponse(conn *conn) (*NegotiateResponse, error) {
	rsp := new(NegotiateResponse)

	if n.RequireMessageSigning {
		rsp.SecurityMode = SMB2_NEGOTIATE_SIGNING_REQUIRED
	} else {
		rsp.SecurityMode = SMB2_NEGOTIATE_SIGNING_ENABLED
	}
	rsp.Flags = 1

	rsp.Capabilities = serverCapabilities
	rsp.MaxTransactSize = serverMaxTransactSize
	rsp.MaxReadSize = serverMaxReadSize
	rsp.MaxWriteSize = serverMaxWriteSize
	rsp.SystemTime = NsecToFiletime(time.Now().UnixNano())
	rsp.ServerStartTime = &Filetime{}
	rsp.ServerGuid = conn.serverCtx.serverGuid

	if n.SpecifiedDialect != UnknownSMB {
		rsp.DialectRevision = n.SpecifiedDialect

		switch n.SpecifiedDialect {
		case SMB2:
		case SMB202:
		case SMB210:
		case SMB300:
		case SMB302:
		case SMB311:
			hc := &HashContext{
				HashAlgorithms: []uint16{conn.hashId},
				HashSalt:       make([]byte, 32),
			}
			if _, err := rand.Read(hc.HashSalt); err != nil {
				return nil, &InternalError{err.Error()}
			}

			cc := &CipherContext{
				Ciphers: []uint16{conn.cipherId},
			}

			crc := &CompressionContext{
				Compressions: []uint16{0},
				Flags:        0,
			}

			rsp.Contexts = append(rsp.Contexts, hc, cc, crc)

			if conn.posixExtensions {
				rsp.Contexts = append(rsp.Contexts, &PosixContext{})
			}
		default:
			return nil, &InternalError{"unsupported dialect specified"}
		}
	} else {
		rsp.DialectRevision = defaultDerverDialect

		hashID := conn.hashId
		if hashID == 0 {
			hashID = SHA512
		}
		hc := &HashContext{
			HashAlgorithms: []uint16{hashID},
			HashSalt:       make([]byte, 32),
		}
		if _, err := rand.Read(hc.HashSalt); err != nil {
			return nil, &InternalError{err.Error()}
		}

		cipherID := conn.cipherId
		if cipherID == 0 {
			cipherID = AES128GCM
		}
		cc := &CipherContext{
			Ciphers: []uint16{cipherID},
		}

		rsp.Contexts = append(rsp.Contexts, hc, cc)
	}

	return rsp, nil
}

func randint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return uint32(binary.LittleEndian.Uint32(b[:]))
}

func randint64() uint64 {
	var b [8]byte
	rand.Read(b[:])
	return uint64(binary.LittleEndian.Uint64(b[:]))
}

func dialectName(d uint16) string {
	switch d {
	case SMB202:
		return "SMB2.0.2"
	case SMB210:
		return "SMB2.1"
	case SMB300:
		return "SMB3.0"
	case SMB302:
		return "SMB3.0.2"
	case SMB311:
		return "SMB3.1.1"
	default:
		return fmt.Sprintf("0x%04x", d)
	}
}

func authFailedUserFromError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	const p = "no such user "
	if strings.HasPrefix(msg, p) {
		return strings.TrimSpace(strings.TrimPrefix(msg, p))
	}
	return ""
}

func (c *conn) shouldEncryptSession() bool {
	if c.serverCtx == nil || !c.serverCtx.enableSMB3Encryption {
		return false
	}
	if c.dialect < SMB300 {
		return false
	}
	return c.capabilities&SMB2_GLOBAL_CAP_ENCRYPTION != 0
}

func (c *conn) encryptionDisabledReason() string {
	if c.serverCtx == nil {
		return "server context unavailable"
	}
	if !c.serverCtx.enableSMB3Encryption {
		return "disabled by server config"
	}
	if c.dialect < SMB300 {
		return fmt.Sprintf("dialect=%s", dialectName(c.dialect))
	}
	if c.capabilities&SMB2_GLOBAL_CAP_ENCRYPTION == 0 {
		return "client capability not advertised"
	}
	return "not negotiated"
}

func (c *conn) calcPreauthHash(pkt []byte) {
	switch c.dialect {
	case SMB311:
		switch c.preauthIntegrityHashId {
		case SHA512:
			h := sha512.New()
			h.Write(c.preauthIntegrityHashValue[:])
			h.Write(pkt)
			h.Sum(c.preauthIntegrityHashValue[:0])
		}
	}
}

func (c *conn) sessionServerSetup(pkt []byte) error {
	c.debugf("session setup step 1")

	p := PacketCodec(pkt)

	res, err := accept(SMB2_SESSION_SETUP, pkt)
	if err != nil {
		c.debugf("session setup decode failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_PARAMETER))
		return c.sendPacket(rsp, nil, nil)
	}

	c.calcPreauthHash(pkt)

	r := SessionSetupRequestDecoder(res)
	if r.IsInvalid() {
		c.debugf("session setup invalid request")
		return &InvalidRequestError{"broken session setup request format"}
	}

	/*if c.requireSigning && r.SecurityMode() != SMB2_NEGOTIATE_SIGNING_REQUIRED {
		return &InvalidRequestError{"request security mode doesn't match connection requirement"}
	}*/

	outputToken, err := c.serverCtx.negotiator.Spnego.challenge(r.SecurityBuffer())
	if err != nil {
		c.warnf("session setup challenge failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_LOGON_FAILURE))
		return c.sendPacket(rsp, nil, nil)
	}

	rsp := &SessionSetupResponse{
		SessionFlags:   0,
		SecurityBuffer: outputToken,
	}

	sessionId := randint64()

	rsp.Flags = 1
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.CreditCharge = 0 //c.CreditCharge()
	rsp.MessageId = p.MessageId()
	rsp.Status = uint32(STATUS_MORE_PROCESSING_REQUIRED)
	rsp.SessionId = sessionId

	c.serverState = STATE_SESSION_SETUP_CHALLENGE

	return c.sendPacket(rsp, nil, nil)
}

func (c *conn) sessionServerSetupChallenge(pkt []byte) error {
	c.debugf("session setup step 2")

	p := PacketCodec(pkt)

	res, err := accept(SMB2_SESSION_SETUP, pkt)
	if err != nil {
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_PARAMETER))
		return c.sendPacket(rsp, nil, nil)
	}

	r := SessionSetupRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken session setup request format"}
	}

	c.calcPreauthHash(pkt)

	outputToken, user, err := c.serverCtx.negotiator.Spnego.authenticate(r.SecurityBuffer())
	if err != nil {
		if c.serverCtx.onAuthFail != nil {
			c.serverCtx.onAuthFail(c.remoteAddr, authFailedUserFromError(err))
		}
		c.warnf("authentication failed: %v", err)
		// Reset state so the client can retry with different credentials.
		c.serverState = STATE_SESSION_SETUP
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_LOGON_FAILURE))
		return c.sendPacket(rsp, nil, nil)
	}

	if err == nil {
		if ntlmAuth, ok := c.serverCtx.negotiator.Spnego.selectedMech.(*NTLMAuthenticator); ok {
			c.observeNTLMInfo(ntlmAuth.infoMap())
		}
	}
	c.ensureDefaultClientOS()
	c.logClientProfile()
	c.infof("authenticated: %s", user)
	flags := uint16(0)
	isGuest := strings.EqualFold(user, "guest") || user == "" || (c.serverCtx.allowGuest && !c.serverCtx.isConfiguredUser(user))
	if isGuest {
		flags |= SMB2_SESSION_FLAG_IS_GUEST
	} else if c.shouldEncryptSession() {
		flags |= SMB2_SESSION_FLAG_ENCRYPT_DATA
	}

	sessionId := p.SessionId()
	s := &session{
		conn:           c,
		treeConnTables: make(map[uint32]*treeConn),
		sessionFlags:   flags,
		sessionId:      sessionId,
		username:       user,
	}

	rsp := &SessionSetupResponse{
		SessionFlags:   s.sessionFlags,
		SecurityBuffer: outputToken,
	}

	rsp.Flags = 1
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.CreditCharge = 0 //c.CreditCharge()
	rsp.MessageId = p.MessageId()
	rsp.SessionId = sessionId
	rsp.SecurityBuffer = outputToken

	if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
		sessionKey := c.serverCtx.negotiator.Spnego.sessionKey()
		if err := c.deriveSessionKeys(s, sessionKey, c.preauthIntegrityHashValue); err != nil {
			return err
		}
	}
	if s.sessionFlags&SMB2_SESSION_FLAG_ENCRYPT_DATA != 0 {
		c.infof("session security: encryption=enabled cipher=%s", cipherName(c.cipherId))
	} else if isGuest {
		c.infof("session security: encryption=disabled reason=guest session")
	} else {
		c.infof("session security: encryption=disabled reason=%s", c.encryptionDisabledReason())
	}

	// Set session before sending final SESSION_SETUP so response can be signed.
	c.setSession(s)
	c.serverState = STATE_SESSION_ACTIVE
	if err = c.sendPacket(rsp, nil, nil); err == nil {
		c.enableSession()
	}
	return err
}

// deriveSessionKeys sets up signing, encryption and decryption keys on
// the session based on the negotiated dialect.  preauthHash is only used
// for SMB 3.1.1.
func (c *conn) deriveSessionKeys(s *session, sessionKey []byte, preauthHash [64]byte) error {
	switch c.dialect {
	case SMB202, SMB210:
		s.signer = hmac.New(sha256.New, sessionKey)
		s.verifier = hmac.New(sha256.New, sessionKey)
	case SMB300, SMB302:
		s.cipherId = AES128CCM
		signingKey := kdf(sessionKey, []byte("SMB2AESCMAC\x00"), []byte("SmbSign\x00"))
		ciph, err := aes.NewCipher(signingKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.signer = cmac.New(ciph)
		s.verifier = cmac.New(ciph)

		// SMB3.0/3.0.2: server encrypts with ServerOut and decrypts with ServerIn.
		encryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerOut\x00"))
		decryptionKey := kdf(sessionKey, []byte("SMB2AESCCM\x00"), []byte("ServerIn \x00"))

		ciph, err = aes.NewCipher(encryptionKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		if err != nil {
			return &InternalError{err.Error()}
		}

		ciph, err = aes.NewCipher(decryptionKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
		if err != nil {
			return &InternalError{err.Error()}
		}
	case SMB311:
		s.preauthIntegrityHashValue = preauthHash
		s.cipherId = c.cipherId
		signingKey := kdf(sessionKey, []byte("SMBSigningKey\x00"), s.preauthIntegrityHashValue[:])
		ciph, err := aes.NewCipher(signingKey)
		if err != nil {
			return &InternalError{err.Error()}
		}
		s.signer = cmac.New(ciph)
		s.verifier = cmac.New(ciph)

		// SMB3.1.1: server encrypts with S2C key and decrypts with C2S key.
		encryptionKey := kdf(sessionKey, []byte("SMBS2CCipherKey\x00"), s.preauthIntegrityHashValue[:])
		decryptionKey := kdf(sessionKey, []byte("SMBC2SCipherKey\x00"), s.preauthIntegrityHashValue[:])

		switch c.cipherId {
		case AES128CCM:
			ciph, err := aes.NewCipher(encryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.encrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.decrypter, err = ccm.NewCCMWithNonceAndTagSizes(ciph, 11, 16)
			if err != nil {
				return &InternalError{err.Error()}
			}
		case AES128GCM:
			ciph, err := aes.NewCipher(encryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.encrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
			if err != nil {
				return &InternalError{err.Error()}
			}

			ciph, err = aes.NewCipher(decryptionKey)
			if err != nil {
				return &InternalError{err.Error()}
			}
			s.decrypter, err = cipher.NewGCMWithNonceSize(ciph, 12)
			if err != nil {
				return &InternalError{err.Error()}
			}
		}
	}
	return nil
}

// sessionSetupNewBinding starts a new session binding on an already-active
// connection.  This is used when Windows UAC elevation needs a second
// session for the elevated process.
func (c *conn) sessionSetupNewBinding(pkt []byte) error {
	c.debugf("session binding step 1 (new session on active connection)")

	p := PacketCodec(pkt)

	res, err := accept(SMB2_SESSION_SETUP, pkt)
	if err != nil {
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_PARAMETER))
		return c.sendPacket(rsp, nil, nil)
	}

	r := SessionSetupRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken session setup request format"}
	}

	// Create a fresh SPNEGO server for this binding (the connection-level
	// Spnego was used for the original session and may retain stale state).
	bindSpnego := newSpnegoServer([]Authenticator{c.serverCtx.authenticator})

	outputToken, err := bindSpnego.challenge(r.SecurityBuffer())
	if err != nil {
		c.warnf("session binding challenge failed: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_LOGON_FAILURE))
		return c.sendPacket(rsp, nil, nil)
	}

	sessionId := randint64()

	// Compute the binding's preauth hash: start from the post-negotiate
	// hash and add this request packet.
	bindHash := c.negotiatePreauthHash
	if c.dialect == SMB311 {
		h := sha512.New()
		h.Write(bindHash[:])
		h.Write(pkt)
		h.Sum(bindHash[:0])
	}

	c.pendingSetup = &pendingSessionSetup{
		spnego:      bindSpnego,
		sessionId:   sessionId,
		preauthHash: bindHash,
	}

	rsp := &SessionSetupResponse{
		SecurityBuffer: outputToken,
	}
	rsp.Flags = 1
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.CreditCharge = 0
	rsp.MessageId = p.MessageId()
	rsp.Status = uint32(STATUS_MORE_PROCESSING_REQUIRED)
	rsp.SessionId = sessionId

	c.tracef("session binding: issued challenge, pending sid=%d", sessionId)

	// sendPacket will hash the response into pendingSetup.preauthHash
	// for SMB 3.1.1 (see conn.go sendPacket logic).
	return c.sendPacket(rsp, nil, nil)
}

// sessionSetupCompleteBinding completes a pending session binding (step 2).
func (c *conn) sessionSetupCompleteBinding(pkt []byte) error {
	c.debugf("session binding step 2 (completing binding)")

	p := PacketCodec(pkt)
	ps := c.pendingSetup

	res, err := accept(SMB2_SESSION_SETUP, pkt)
	if err != nil {
		c.pendingSetup = nil
		rsp := new(ErrorResponse)
		PrepareResponse(rsp.Header(), pkt, uint32(STATUS_INVALID_PARAMETER))
		return c.sendPacket(rsp, nil, nil)
	}

	r := SessionSetupRequestDecoder(res)
	if r.IsInvalid() {
		c.pendingSetup = nil
		return &InvalidRequestError{"broken session setup request format"}
	}

	// Update binding preauth hash with this request.
	if c.dialect == SMB311 {
		h := sha512.New()
		h.Write(ps.preauthHash[:])
		h.Write(pkt)
		h.Sum(ps.preauthHash[:0])
	}

	outputToken, user, err := ps.spnego.authenticate(r.SecurityBuffer())
	if err != nil {
		if c.serverCtx.onAuthFail != nil {
			c.serverCtx.onAuthFail(c.remoteAddr, authFailedUserFromError(err))
		}
		c.warnf("session binding authentication failed: %v", err)
		c.pendingSetup = nil
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_LOGON_FAILURE))
		return c.sendPacket(rsp, nil, nil)
	}

	c.infof("session binding authenticated: %s (sid=%d)", user, ps.sessionId)

	flags := uint16(0)
	isGuest := strings.EqualFold(user, "guest") || user == "" || (c.serverCtx.allowGuest && !c.serverCtx.isConfiguredUser(user))
	if isGuest {
		flags |= SMB2_SESSION_FLAG_IS_GUEST
	} else if c.shouldEncryptSession() {
		flags |= SMB2_SESSION_FLAG_ENCRYPT_DATA
	}

	s := &session{
		conn:           c,
		treeConnTables: make(map[uint32]*treeConn),
		sessionFlags:   flags,
		sessionId:      ps.sessionId,
		username:       user,
	}

	rsp := &SessionSetupResponse{
		SessionFlags:   s.sessionFlags,
		SecurityBuffer: outputToken,
	}
	rsp.Flags = 1
	rsp.CreditRequestResponse = p.CreditRequest()
	rsp.CreditCharge = 0
	rsp.MessageId = p.MessageId()
	rsp.SessionId = s.sessionId
	rsp.SecurityBuffer = outputToken

	if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
		sessionKey := ps.spnego.sessionKey()
		if err := c.deriveSessionKeys(s, sessionKey, ps.preauthHash); err != nil {
			c.pendingSetup = nil
			return err
		}
	}
	if s.sessionFlags&SMB2_SESSION_FLAG_ENCRYPT_DATA != 0 {
		c.infof("session binding security: encryption=enabled cipher=%s", cipherName(c.cipherId))
	} else if isGuest {
		c.infof("session binding security: encryption=disabled reason=guest session")
	} else {
		c.infof("session binding security: encryption=disabled reason=%s", c.encryptionDisabledReason())
	}

	// Add the new session to the connection's session map.
	c.setSession(s)
	err = c.sendPacket(rsp, nil, nil)
	c.pendingSetup = nil
	return err
}

func (d *Server) addOpen(open *Open) {
	d.lock.Lock()
	defer d.lock.Unlock()

	d.opens[open.fileId] = open
	if open.isDurable {
		d.opensByGuid[open.createGuid] = open
	}
}

func (d *Server) getOpen(fileId uint64) *Open {
	d.lock.Lock()
	defer d.lock.Unlock()

	return d.opens[fileId]
}

func (d *Server) deleteOpen(fileId uint64) {
	d.lock.Lock()
	defer d.lock.Unlock()
	if open, ok := d.opens[fileId]; ok {
		delete(d.opens, fileId)
		if open.isDurable {
			delete(d.opensByGuid, open.createGuid)
		}
	}
}

func (d *Server) addFsWatch(realPath, shareRoot string) {
	d.lock.Lock()
	defer d.lock.Unlock()
	if d.fsWatcher == nil {
		return
	}
	d.fsWatchRefs[realPath]++
	if d.fsWatchRefs[realPath] == 1 {
		d.fsWatchRoot[realPath] = shareRoot
		if err := d.fsWatcher.Add(realPath); err != nil {
			log.Debugf("fsnotify: failed to watch %s: %v", realPath, err)
			delete(d.fsWatchRefs, realPath)
			delete(d.fsWatchRoot, realPath)
		}
	}
}

func (d *Server) removeFsWatch(realPath string) {
	d.lock.Lock()
	defer d.lock.Unlock()
	if d.fsWatcher == nil {
		return
	}
	d.fsWatchRefs[realPath]--
	if d.fsWatchRefs[realPath] <= 0 {
		d.fsWatcher.Remove(realPath)
		delete(d.fsWatchRefs, realPath)
		delete(d.fsWatchRoot, realPath)
	}
}

func (d *Server) startFsWatcher() {
	go func() {
		for {
			select {
			case ev, ok := <-d.fsWatcher.Events:
				if !ok {
					return
				}
				// Convert absolute path to SMB-relative path
				dir := filepath.Dir(ev.Name)
				base := filepath.Base(ev.Name)

				d.lock.Lock()
				shareRoot := d.fsWatchRoot[dir]
				d.lock.Unlock()

				if shareRoot == "" {
					continue
				}

				// Build SMB-relative path: strip share root from dir
				relDir, err := filepath.Rel(shareRoot, dir)
				if err != nil {
					continue
				}
				if relDir == "." {
					relDir = ""
				}

				var smbPath string
				if relDir == "" {
					smbPath = base
				} else {
					smbPath = relDir + "/" + base
				}

				var action uint32
				var actionName string
				switch {
				case ev.Op&fsnotify.Create != 0:
					action = FILE_ACTION_ADDED
					actionName = "created"
				case ev.Op&fsnotify.Remove != 0:
					action = FILE_ACTION_REMOVED
					actionName = "removed"
				case ev.Op&fsnotify.Write != 0:
					action = FILE_ACTION_MODIFIED
					actionName = "modified"
				case ev.Op&fsnotify.Rename != 0:
					action = FILE_ACTION_RENAMED_OLD_NAME
					actionName = "renamed"
				default:
					continue
				}

				if d.onDetect != nil {
					d.onDetect(actionName, smbPath)
				} else {
					log.Infof("detected: %s %s", actionName, smbPath)
				}
				log.Tracef("fsnotify: %s action=%d smbPath=%s", ev.Name, action, smbPath)
				d.notifyChange(smbPath, action)

			case _, ok := <-d.fsWatcher.Errors:
				if !ok {
					return
				}
			}
		}
	}()
}

// notifyChange sends a change notification to any pending ChangeNotify
// watchers on the parent directory of the given file path.
func (d *Server) notifyChange(filePath string, action uint32) {
	// Find parent directory and base name
	// Paths use forward slashes internally (e.g. "Quake 3/file.exe")
	dir := ""
	base := filePath
	if idx := strings.LastIndex(filePath, "/"); idx >= 0 {
		dir = filePath[:idx]
		base = filePath[idx+1:]
	}

	// Suppress notifications for macOS metadata files
	if strings.HasPrefix(base, "._") || base == ".DS_Store" {
		return
	}
	// Convert base name to backslashes for SMB response
	smbBase := strings.ReplaceAll(base, "/", "\\")

	d.lock.Lock()
	defer d.lock.Unlock()
	for _, open := range d.opens {
		if open.notifyCh == nil {
			continue
		}
		// Normalize root: pathName "/" and dir "" both mean the share root
		openDir := open.pathName
		if openDir == "/" {
			openDir = ""
		}
		if openDir == dir || (open.notifyWatchTree && strings.HasPrefix(dir, openDir)) {
			select {
			case open.notifyCh <- notifyEvent{Action: action, FileName: smbBase}:
			default:
			}
		}
	}
}
