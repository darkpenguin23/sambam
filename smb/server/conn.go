package smb2

import (
	"context"
	"crypto/sha512"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	. "github.com/sambam/sambam/smb/internal/erref"
	"github.com/sambam/sambam/smb/internal/ntlm"
	. "github.com/sambam/sambam/smb/internal/smb2"
	log "github.com/sirupsen/logrus"
)

// isBenignError checks if an error is expected/normal (not worth logging as ERROR)
func isNormalDisconnect(err error) bool {
	if err == nil {
		return false
	}
	if err == io.EOF || err == context.Canceled {
		return true
	}
	errStr := err.Error()
	return strings.Contains(errStr, "EOF") ||
		strings.Contains(errStr, "context canceled") ||
		strings.Contains(errStr, "use of closed network connection") ||
		strings.Contains(errStr, "no such user") ||
		strings.Contains(errStr, "login failure")
}

type requestResponse struct {
	msgId         uint64
	creditRequest uint16
	pkt           []byte // request packet
	compCtx       *compoundContext
	ctx           context.Context
	recv          chan []byte
	err           error
}

type outstandingRequests struct {
	m        sync.Mutex
	s        chan uint64
	requests map[uint64]*requestResponse
}

func newOutstandingRequests() *outstandingRequests {
	return &outstandingRequests{
		requests: make(map[uint64]*requestResponse, 0),
		s:        make(chan uint64),
	}
}

func (r *outstandingRequests) set(msgId uint64, rr *requestResponse) {
	r.m.Lock()

	r.requests[msgId] = rr
	r.m.Unlock()

	r.s <- msgId
}

func (r *outstandingRequests) pop(ctx context.Context) ([]byte, *compoundContext, error) {
	var msgId uint64

again:
	select {
	case <-ctx.Done():
		return nil, nil, &ContextError{Err: ctx.Err()}
	case msgId = <-r.s:
		break
	}

	r.m.Lock()
	defer r.m.Unlock()

	rr := r.requests[msgId]
	delete(r.requests, msgId)
	if rr == nil {
		// Cancel message
		goto again
	}
	return rr.pkt, rr.compCtx, nil
}

func (r *outstandingRequests) shutdown(err error) {
	r.m.Lock()
	defer r.m.Unlock()

	for _, rr := range r.requests {
		rr.err = err
		close(rr.recv)
	}
}

type conn struct {
	t             transport
	remoteAddr    string
	clientHost    string
	clientOS      string
	clientOSSrc   string
	clientOSPrio  int
	profileLogged bool

	session                   *session
	sessions                  map[uint64]*session
	outstandingRequests       *outstandingRequests
	sequenceWindow            uint64
	dialect                   uint16
	maxTransactSize           uint32
	maxReadSize               uint32
	maxWriteSize              uint32
	requireSigning            bool
	capabilities              uint32
	preauthIntegrityHashId    uint16
	preauthIntegrityHashValue [64]byte
	cipherId                  uint16
	hashId                    uint16
	posixExtensions           bool

	account *account

	rdone chan struct{}
	wdone chan struct{}
	write chan []byte
	werr  chan error

	m sync.Mutex

	err error

	// gssNegotiateToken []byte
	// serverGuid        [16]byte
	// clientGuid        [16]byte

	_useSession int32 // receiver use session?

	ctx         context.Context
	cancel      context.CancelFunc
	serverCtx   *Server
	serverState ConnState

	// Post-negotiate preauth hash, saved for session binding (SMB 3.1.1).
	negotiatePreauthHash [64]byte

	// Pending session binding (e.g. UAC elevation on the same connection).
	pendingSetup *pendingSessionSetup

	treeMapByName map[string]treeOps
	treeMapById   map[uint32]treeOps
}

const (
	clientOSPrioDefault = 10
	clientOSPrioNTLM    = 20
	clientOSPrioPOSIX   = 80
	clientOSPrioAAPL    = 90
)

func (c *conn) logger() *log.Entry {
	return log.WithField("client", c.remoteAddr)
}

func (c *conn) tracef(format string, args ...interface{}) {
	c.logger().Tracef(format, args...)
}

func (c *conn) debugf(format string, args ...interface{}) {
	c.logger().Debugf(format, args...)
}

func (c *conn) infof(format string, args ...interface{}) {
	c.logger().Infof(format, args...)
}

func (c *conn) warnf(format string, args ...interface{}) {
	c.logger().Warnf(format, args...)
}

func (c *conn) errorf(format string, args ...interface{}) {
	c.logger().Errorf(format, args...)
}

func (c *conn) setClientOS(osName, source string, priority int) {
	if strings.TrimSpace(osName) == "" {
		return
	}
	c.m.Lock()
	changed := false
	if priority >= c.clientOSPrio && (c.clientOS != osName || c.clientOSSrc != source) {
		c.clientOS = osName
		c.clientOSSrc = source
		c.clientOSPrio = priority
		changed = true
	}
	profileLogged := c.profileLogged
	c.m.Unlock()

	if changed && profileLogged {
		c.infof("client os updated: %s (%s)", osName, source)
	}
}

func (c *conn) setClientHost(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	c.m.Lock()
	if c.clientHost == "" {
		c.clientHost = name
	}
	c.m.Unlock()
}

func (c *conn) observeNTLMInfo(info *ntlm.InfoMap) {
	if info == nil {
		return
	}
	if info.NbComputerName != "" {
		c.setClientHost(info.NbComputerName)
	} else if info.DnsComputerName != "" {
		c.setClientHost(info.DnsComputerName)
	}

	blob := strings.ToLower(strings.Join([]string{
		info.NbComputerName,
		info.NbDomainName,
		info.DnsComputerName,
		info.DnsDomainName,
		info.DnsTreeName,
	}, " "))

	switch {
	case strings.Contains(blob, "mac") || strings.Contains(blob, "darwin"):
		c.setClientOS("macOS", "ntlm metadata heuristic", clientOSPrioNTLM)
	case strings.Contains(blob, "linux") ||
		strings.Contains(blob, "ubuntu") ||
		strings.Contains(blob, "debian") ||
		strings.Contains(blob, "fedora") ||
		strings.Contains(blob, "arch"):
		c.setClientOS("linux", "ntlm metadata heuristic", clientOSPrioNTLM)
	}
}

func (c *conn) logClientProfile() {
	c.m.Lock()
	host := c.clientHost
	osName := c.clientOS
	c.profileLogged = true
	c.m.Unlock()

	if host == "" {
		host = "unknown"
	}
	if osName == "" {
		osName = "unknown"
	}
	if host == "unknown" {
		c.infof("client profile: os=%s", osName)
		return
	}
	c.infof("client profile: host=%s os=%s", host, osName)
}

func (c *conn) ensureDefaultClientOS() {
	c.m.Lock()
	osName := c.clientOS
	c.m.Unlock()
	if osName == "" || strings.EqualFold(osName, "unknown") {
		c.setClientOS("windows", "default SMB client heuristic", clientOSPrioDefault)
	}
}

// pendingSessionSetup holds state for a second session being established
// on an already-active connection (e.g. Windows UAC elevation).
type pendingSessionSetup struct {
	spnego      *spnegoServer
	sessionId   uint64
	preauthHash [64]byte // running preauth hash for this binding
}

func (conn *conn) getSession(sessionId uint64) *session {
	conn.m.Lock()
	defer conn.m.Unlock()
	return conn.sessions[sessionId]
}

func (conn *conn) setSession(s *session) {
	conn.m.Lock()
	defer conn.m.Unlock()
	conn.sessions[s.sessionId] = s
	conn.session = s
}

func (conn *conn) setActiveSession(sessionId uint64) *session {
	conn.m.Lock()
	defer conn.m.Unlock()
	s := conn.sessions[sessionId]
	conn.session = s
	return s
}

func (conn *conn) shutdown() {
	conn.cancel()
	// Close transport first to unblock any pending reads/writes
	conn.t.Close()
	// Non-blocking send to signal goroutines (they may already be done)
	select {
	case conn.wdone <- struct{}{}:
	default:
	}
	select {
	case conn.rdone <- struct{}{}:
	default:
	}
}

func (conn *conn) useSession() bool {
	return atomic.LoadInt32(&conn._useSession) != 0
}

func (conn *conn) enableSession() {
	atomic.StoreInt32(&conn._useSession, 1)
}

func (conn *conn) resetSession() {
	atomic.StoreInt32(&conn._useSession, 0)
}

func (conn *conn) encodePacket(req Packet, tc *treeConn, ctx context.Context) ([]byte, error) {
	var err error
	hdr := req.Header()

	if _, ok := req.(*CancelRequest); !ok {
		creditCharge := hdr.CreditCharge

		conn.sequenceWindow += uint64(creditCharge)
		if hdr.CreditRequestResponse == 0 {
			hdr.CreditRequestResponse = creditCharge
		}

		hdr.CreditRequestResponse += conn.account.opening()
	}

	s := conn.session

	if s != nil && s.conn.useSession() {
		// Only set SessionId from the active session if the caller hasn't
		// already set it explicitly (e.g. session binding responses carry
		// the new pending session ID).
		if hdr.SessionId == 0 {
			hdr.SessionId = s.sessionId
		}

		if tc != nil {
			hdr.TreeId = tc.treeId
		}
	}

	pkt := make([]byte, req.Size())

	req.Encode(pkt)

	if s != nil {
		if _, ok := req.(*SessionSetupRequest); !ok {
			if s.sessionFlags&SMB2_SESSION_FLAG_ENCRYPT_DATA != 0 || (tc != nil && tc.shareFlags&SMB2_SHAREFLAG_ENCRYPT_DATA != 0) {
				pkt, err = s.encrypt(pkt)
				if err != nil {
					return nil, &InternalError{err.Error()}
				}
			} else {
				if s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
					pkt = s.sign(pkt)
				}
			}
		}
	}
	return pkt, nil
}

func (conn *conn) srvRecv() ([]byte, *compoundContext, error) {
	return conn.outstandingRequests.pop(conn.ctx)
}

func (conn *conn) runSender() {
	for {
		select {
		case <-conn.wdone:
			conn.tracef("runsender finished")
			return
		case pkt := <-conn.write:
			_, err := conn.t.Write(pkt)

			conn.werr <- err
		}
	}
}

func (conn *conn) runReciever() {
	var err error

	for {
		n, e := conn.t.ReadSize()
		if e != nil {
			err = &TransportError{e}

			goto exit
		}

		pkt := make([]byte, n)

		_, e = conn.t.Read(pkt)
		if e != nil {
			err = &TransportError{e}

			goto exit
		}

		hasSession := conn.useSession()

		var isEncrypted bool

		if hasSession {
			pkt, e, isEncrypted = conn.tryDecrypt(pkt)
			if e != nil {
				log.Warning("skip:", e)

				continue
			}

			p := PacketCodec(pkt)
			if p.Command() != SMB2_NEGOTIATE &&
				p.Command() != SMB2_SESSION_SETUP &&
				p.Command() != SMB2_ECHO {
				s := conn.getSession(p.SessionId())
				if s == nil {
					conn.tracef("skip: unknown session id (cmd %d, sid %d)", p.Command(), p.SessionId())
					continue
				}

				if tc, ok := s.treeConnTables[p.TreeId()]; ok {
					if tc.treeId != p.TreeId() {
						conn.warnf("skip: %v", &InvalidResponseError{"unknown tree id"})
						continue
					}
				}
			}
		}

		var next []byte
		var compCtx *compoundContext = nil

		for {
			p := PacketCodec(pkt)
			if p.IsInvalid() {
				err = &InvalidRequestError{}
				goto exit
			}
			if log.IsLevelEnabled(log.TraceLevel) {
				conn.tracef(
					"req: cmd=%d mid=%d sid=%d tid=%d flags=0x%x len=%d",
					p.Command(),
					p.MessageId(),
					p.SessionId(),
					p.TreeId(),
					p.Flags(),
					len(pkt),
				)
			}

			if p.IsCompoundFirst() {
				compCtx = &compoundContext{
					treeId:    uint64(p.TreeId()),
					sessionId: p.SessionId(),
				}
			}

			if p.IsCompoundLast() {
				compCtx.lastMsgId = p.MessageId()
			}

			if off := p.NextCommand(); off != 0 {
				pkt, next = pkt[:off], pkt[off:]
			} else {
				next = nil
			}

			if hasSession {
				e = conn.tryVerify(pkt, isEncrypted)
				if e != nil {
					conn.errorf("verify error: %v", e)
				}
			}

			e = conn.tryHandle(pkt, compCtx, e)
			if e != nil {
				conn.warnf("skip: %v", e)
			}

			if next == nil {
				break
			}

			pkt = next
		}
	}

exit:
	select {
	case <-conn.rdone:
		err = nil
	default:
		if !isNormalDisconnect(err) {
			conn.errorf("error: %v", err)
		}
	}

	conn.m.Lock()
	defer conn.m.Unlock()

	conn.outstandingRequests.shutdown(err)

	conn.err = err

	conn.tracef("receiver finished")

	conn.shutdown()
}

func accept(cmd uint16, pkt []byte) (res []byte, err error) {
	p := PacketCodec(pkt)
	if command := p.Command(); cmd != command {
		return nil, &InvalidResponseError{fmt.Sprintf("expected command: %v, got %v", cmd, command)}
	}

	// request, don't check status
	if (p.Flags() & SMB2_FLAGS_SERVER_TO_REDIR) == 0 {
		return p.Data(), nil
	}

	status := NtStatus(p.Status())

	switch status {
	case STATUS_SUCCESS:
		return p.Data(), nil
	case STATUS_OBJECT_NAME_COLLISION:
		return nil, os.ErrExist
	case STATUS_OBJECT_NAME_NOT_FOUND, STATUS_OBJECT_PATH_NOT_FOUND:
		return nil, os.ErrNotExist
	case STATUS_ACCESS_DENIED, STATUS_CANNOT_DELETE:
		return nil, os.ErrPermission
	}

	switch cmd {
	case SMB2_SESSION_SETUP:
		if status == STATUS_MORE_PROCESSING_REQUIRED {
			return p.Data(), nil
		}
	case SMB2_QUERY_INFO:
		if status == STATUS_BUFFER_OVERFLOW {
			return nil, &ResponseError{Code: uint32(status)}
		}
	case SMB2_IOCTL:
		if status == STATUS_BUFFER_OVERFLOW {
			if !IoctlResponseDecoder(p.Data()).IsInvalid() {
				return p.Data(), &ResponseError{Code: uint32(status)}
			}
		}
	case SMB2_READ:
		if status == STATUS_BUFFER_OVERFLOW {
			return nil, &ResponseError{Code: uint32(status)}
		}
	case SMB2_CHANGE_NOTIFY:
		if status == STATUS_NOTIFY_ENUM_DIR {
			return nil, &ResponseError{Code: uint32(status)}
		}
	}

	return nil, acceptError(uint32(status), p.Data())
}

func acceptError(status uint32, res []byte) error {
	r := ErrorResponseDecoder(res)
	if r.IsInvalid() {
		return &InvalidResponseError{"broken error response format"}
	}

	eData := r.ErrorData()

	if count := r.ErrorContextCount(); count != 0 {
		data := make([][]byte, count)
		for i := range data {
			ctx := ErrorContextResponseDecoder(eData)
			if ctx.IsInvalid() {
				return &InvalidResponseError{"broken error context response format"}
			}

			data[i] = ctx.ErrorContextData()

			next := ctx.Next()

			if len(eData) < next {
				return &InvalidResponseError{"broken error context response format"}
			}

			eData = eData[next:]
		}
		return &ResponseError{Code: status, data: data}
	}
	return &ResponseError{Code: status, data: [][]byte{eData}}
}

func (conn *conn) tryDecrypt(pkt []byte) ([]byte, error, bool) {
	p := PacketCodec(pkt)
	if p.IsInvalid() {
		t := TransformCodec(pkt)
		if t.IsInvalid() {
			return nil, &InvalidResponseError{"broken packet header format"}, false
		}

		if t.Flags() != Encrypted {
			return nil, &InvalidResponseError{"encrypted flag is not on"}, false
		}

		s := conn.getSession(t.SessionId())
		if s == nil {
			return nil, &InvalidResponseError{"unknown session id returned"}, false
		}

		pkt, err := s.decrypt(pkt)
		if err != nil {
			return nil, &InvalidResponseError{err.Error()}, false
		}

		return pkt, nil, true
	}

	return pkt, nil, false
}

func (conn *conn) tryVerify(pkt []byte, isEncrypted bool) error {
	p := PacketCodec(pkt)

	msgId := p.MessageId()

	if msgId != 0xFFFFFFFFFFFFFFFF {
		if p.Flags()&SMB2_FLAGS_SIGNED != 0 {
			s := conn.getSession(p.SessionId())
			if s == nil {
				return &InvalidResponseError{"unknown session id returned"}
			}
			if !s.verify(pkt) {
				return &InvalidResponseError{"unverified packet returned"}
			}
		} else {
			if conn.requireSigning && !isEncrypted {
				s := conn.getSession(p.SessionId())
				if s != nil && s.sessionFlags&(SMB2_SESSION_FLAG_IS_GUEST|SMB2_SESSION_FLAG_IS_NULL) == 0 {
					return &InvalidResponseError{"signing required"}
				}
			}
		}
	}

	return nil
}

func (conn *conn) tryHandle(pkt []byte, compCtx *compoundContext, e error) error {
	p := PacketCodec(pkt)

	msgId := p.MessageId()

	rr := &requestResponse{
		msgId:         msgId,
		creditRequest: p.CreditRequest(),
		pkt:           pkt,
		ctx:           conn.ctx,
		recv:          make(chan []byte, 1),
		compCtx:       compCtx,
	}

	conn.outstandingRequests.set(msgId, rr)
	return nil
}

func (conn *conn) sendPacket(req Packet, tc *treeConn, compCtx *compoundContext) error {
	conn.m.Lock()

	if compCtx != nil {
		if !compCtx.isEmpty() {
			req.Header().Flags |= SMB2_FLAGS_RELATED_OPERATIONS
		}

		if req.Header().MessageId != compCtx.lastMsgId {
			l := Align(req.Size(), 8)
			req.Header().NextCommand = uint32(l)
		}
	}

	pkt, err := conn.encodePacket(req, tc, conn.ctx)
	if err != nil {
		conn.m.Unlock()
		return err
	}
	if p := PacketCodec(pkt); !p.IsInvalid() && p.Status() != 0 {
		log.Tracef(
			"rsp err: cmd=%d status=0x%08x (%s) mid=%d sid=%d tid=%d",
			p.Command(),
			p.Status(),
			NtStatus(p.Status()).Error(),
			p.MessageId(),
			p.SessionId(),
			p.TreeId(),
		)
	} else if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef(
			"rsp: cmd=%d status=0x%08x mid=%d sid=%d tid=%d",
			p.Command(),
			p.Status(),
			p.MessageId(),
			p.SessionId(),
			p.TreeId(),
		)
	}

	if compCtx != nil {
		compCtx.lastStatus = req.Header().Status

		compCtx.addResponse(pkt)
		if req.Header().MessageId != compCtx.lastMsgId {
			conn.m.Unlock()
			return nil
		}
		pkt = make([]byte, compCtx.Size())
		compCtx.Encode(pkt)
	}

	switch conn.serverState {
	case STATE_NEGOTIATE, STATE_SESSION_SETUP, STATE_SESSION_SETUP_CHALLENGE:
		conn.calcPreauthHash(pkt)
	}

	// Hash session-binding responses into the pending preauth chain.
	if conn.pendingSetup != nil && conn.dialect == SMB311 {
		rp := PacketCodec(pkt)
		if rp.Command() == SMB2_SESSION_SETUP && rp.SessionId() == conn.pendingSetup.sessionId {
			h := sha512.New()
			h.Write(conn.pendingSetup.preauthHash[:])
			h.Write(pkt)
			h.Sum(conn.pendingSetup.preauthHash[:0])
		}
	}
	conn.m.Unlock()

	ctx := conn.ctx
	select {
	case conn.write <- pkt:
		select {
		case err = <-conn.werr:
			if err != nil {
				return &TransportError{err}
			}
		case <-ctx.Done():
			return &ContextError{Err: ctx.Err()}
		}
	case <-ctx.Done():
		return &ContextError{Err: ctx.Err()}
	}

	return nil
}
