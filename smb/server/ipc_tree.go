package smb2

import (
	"reflect"
	"time"

	. "github.com/sambam/sambam/smb/internal/erref"
	. "github.com/sambam/sambam/smb/internal/smb2"
	log "github.com/sirupsen/logrus"
)

type ipcTree struct {
	treeConn
	shares []string

	dceReq []byte
}

func (t *ipcTree) getTree() *treeConn {
	return &t.treeConn
}

func (t *ipcTree) create(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, err := accept(SMB2_CREATE, pkt)
	if err != nil {
		return err
	}

	r := CreateRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken create format"}
	}

	log.Tracef("create name: %s", r.Name())
	rsp := new(CreateResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	rsp.FileAttributes = FILE_ATTRIBUTE_NORMAL
	rsp.CreateAction = 1
	rsp.CreationTime = &Filetime{}
	rsp.LastAccessTime = &Filetime{}
	rsp.LastWriteTime = &Filetime{}
	rsp.ChangeTime = &Filetime{}

	if r.Name() != "srvsvc" {
		rsp.Status = uint32(STATUS_NOT_SUPPORTED)
	} else {
		rsp.FileId = &SRVSVC_GUID
	}
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) close(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, err := accept(SMB2_CLOSE, pkt)
	if err != nil {
		return err
	}

	r := CloseRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken close request"}
	}

	if !reflect.DeepEqual(r.FileId().Persistent(), SRVSVC_GUID.Persistent[:]) {
		return &InvalidRequestError{"bad file in close request"}
	}

	rsp := new(CloseResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	rsp.FileAttributes = FILE_ATTRIBUTE_NORMAL
	rsp.CreationTime = &Filetime{}
	rsp.LastAccessTime = &Filetime{}
	rsp.LastWriteTime = &Filetime{}
	rsp.ChangeTime = &Filetime{}

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) flush(ctx *compoundContext, pkt []byte) error {
	return &InvalidRequestError{"invalid flush request for ipcTree"}
}

func (t *ipcTree) write(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, _ := accept(SMB2_WRITE, pkt)
	r := WriteRequestDecoder(res)

	t.dceReq = r.Data()
	log.Tracef("ipc write: dce-bytes=%d", len(t.dceReq))
	rsp := new(WriteResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	rsp.Count = uint32(len(t.dceReq))
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) read(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn
	start := time.Now()

	rsp := new(ReadResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)
	if t.dceReq == nil {
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	dceReq := DCERequestDecoder(t.dceReq)
	if dceReq.IsInvalid() {
		log.Errorf("dceReq is invalid")
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, 0)
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	var rpc Encoder
	var err error

	switch dceReq.Header().PacketType {
	case PacketTypeBind:
		rpc, err = t.ipcTreeBindReq(ctx, t.dceReq)
	case PacketTypeRequest:
		rpc, err = t.ipcTreeReq(ctx, t.dceReq)
	default:
		err = &InvalidRequestError{"invalid read request for ipcTree"}
	}

	if err != nil {
		log.Errorf("error handling dce request: %v", err)
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_DATA_ERROR))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	t.dceReq = nil

	rsp.Data = make([]byte, rpc.Size())
	rpc.Encode(rsp.Data)
	log.Tracef("ipc read: rpc-response-bytes=%d dur=%s", len(rsp.Data), time.Since(start))
	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) ipcTreeBindReq(ctx *compoundContext, pkt []byte) (Encoder, error) {
	start := time.Now()

	dceReq := DCERequestDecoder(pkt)
	bindReq := DCEBindRequestDecoder(pkt)

	ctxRsp := []ContextResponseItem{}
	for _, item := range bindReq.CtxItems() {
		rspItem := ContextResponseItem{}

		if !UUIDIsEqual(item.InterfaceUUID, SRVSVC_UUID) {
			rspItem.Result = 1
			log.Errorf("unsupported interface in bind req")
		}
		if len(item.TransferSyntaxes) != 1 {
			log.Errorf("too many transfer items in bind req")
			rspItem.Result = 2
		}
		transfer := item.TransferSyntaxes[0]
		if !UUIDIsEqual(transfer.SyntaxUUID, NDR_UUID) {
			//log.Errorf("bad transfer syntax in bind req")
			rspItem.Result = 2
		}

		if rspItem.Result == 0 {
			rspItem.TransferUUID = item.TransferSyntaxes[0].SyntaxUUID[:]
			ver := uint32(item.TransferSyntaxes[0].VersionMinor)<<16 | uint32(item.TransferSyntaxes[0].VersionMajor)
			rspItem.TransferVersion = ver
		}
		ctxRsp = append(ctxRsp, rspItem)
	}

	rpc := new(DCEBindAck)
	rpc.AssocGroupID = 0xcc21
	rpc.MaxRecvFragSize = bindReq.MaxRecvFragSize()
	rpc.MaxSendFragSize = bindReq.MaxSendFragSize()
	rpc.CallID = dceReq.Header().CallID
	rpc.SecAddr = append([]byte("\\pipe\\srvsvc"), 0)
	rpc.SecAddrLen = 13
	rpc.CtxCount = uint8(len(ctxRsp))
	rpc.CtxItems = ctxRsp
	log.Tracef("ipc bind: callid=%d contexts=%d dur=%s", dceReq.Header().CallID, len(ctxRsp), time.Since(start))

	return rpc, nil
}

func (t *ipcTree) ipcTreeReq(ctx *compoundContext, pkt []byte) (Encoder, error) {
	start := time.Now()

	dceReq := DCERequestDecoder(pkt)
	req := DCERequestReqDecoder(pkt)
	op := req.Opnum()

	var data Encoder
	switch op {
	case OpNetShareEnumAll:
		data = MakeNetShareEnumAllResponse(t.shares)
	case OpNetShareGetInfo:
		infoReq := NetShareGetInfoRequestDecoder(req.Data())
		data = MakeGetInfoShareResponse(infoReq.ShareName())
	default:
		log.Tracef("ipc rpc: callid=%d opnum=%d (%s) unsupported dur=%s", dceReq.Header().CallID, op, rpcOpName(op), time.Since(start))
		return nil, &RequestError{Code: uint32(STATUS_NOT_SUPPORTED)}
	}

	rpc := new(DCERequestRes)
	rpc.CallID = dceReq.Header().CallID
	rpc.Data = data
	log.Tracef("ipc rpc: callid=%d opnum=%d (%s) req-bytes=%d dur=%s", dceReq.Header().CallID, op, rpcOpName(op), len(req.Data()), time.Since(start))

	return rpc, nil
}

func (t *ipcTree) ioctl(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn
	start := time.Now()

	res, err := accept(SMB2_IOCTL, pkt)
	if err != nil {
		return err
	}

	r := IoctlRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken ioctl request"}
	}
	log.Tracef("ipc ioctl req: code=0x%x fileId=%v inLen=%d outLen=%d maxOut=%d flags=0x%x",
		r.CtlCode(),
		r.FileId().Decode(),
		r.InputCount(),
		r.OutputCount(),
		r.MaxOutputResponse(),
		r.Flags(),
	)

	switch r.CtlCode() {
	case FSCTL_PIPE_TRANSCEIVE:
		break
	case FSCTL_DFS_GET_REFERRALS:
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_FS_DRIVER_REQUIRED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	default:
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if !reflect.DeepEqual(r.FileId().Persistent(), SRVSVC_GUID.Persistent[:]) ||
		!reflect.DeepEqual(r.FileId().Volatile(), SRVSVC_GUID.Volatile[:]) {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	var rpc Encoder

	dceReq := DCERequestDecoder(r.Data())
	switch dceReq.Header().PacketType {
	case PacketTypeRequest:
		rpc, err = t.ipcTreeReq(ctx, r.Data())
	case PacketTypeBind:
		rpc, err = t.ipcTreeBindReq(ctx, r.Data())
	default:
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if err != nil {
		rsp := new(ErrorResponse)
		status := uint32(STATUS_ACCESS_DENIED)
		if re, ok := err.(*RequestError); ok {
			status = re.Code
		} else if _, ok := err.(*InvalidRequestError); ok {
			status = uint32(STATUS_NOT_SUPPORTED)
		}
		PrepareResponse(&rsp.PacketHeader, pkt, status)
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	rsp := new(IoctlResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, 0)

	rsp.CtlCode = FSCTL_PIPE_TRANSCEIVE
	rsp.FileId = &SRVSVC_GUID
	rsp.Output = rpc
	log.Tracef("ipc ioctl: ctl=0x%x rpc-bytes=%d dur=%s", r.CtlCode(), rpc.Size(), time.Since(start))

	return c.sendPacket(rsp, &t.treeConn, ctx)
}

func rpcOpName(op uint16) string {
	switch op {
	case OpNetShareEnumAll:
		return "NetShareEnumAll"
	case OpNetShareGetInfo:
		return "NetShareGetInfo"
	default:
		return "Unknown"
	}
}

func (t *ipcTree) cancel(ctx *compoundContext, pkt []byte) error {
	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
	return t.session.conn.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) queryDirectory(ctx *compoundContext, pkt []byte) error {
	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
	return t.session.conn.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) changeNotify(ctx *compoundContext, pkt []byte) error {
	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
	return t.session.conn.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) queryInfo(ctx *compoundContext, pkt []byte) error {
	c := t.session.conn

	res, err := accept(SMB2_QUERY_INFO, pkt)
	if err != nil {
		return err
	}

	r := QueryInfoRequestDecoder(res)
	if r.IsInvalid() {
		return &InvalidRequestError{"broken query info request for ipcTree"}
	}

	fileId := r.FileId().Decode()
	if fileId == nil || !reflect.DeepEqual(fileId.Persistent[:], SRVSVC_GUID.Persistent[:]) ||
		!reflect.DeepEqual(fileId.Volatile[:], SRVSVC_GUID.Volatile[:]) {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_HANDLE))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if r.InfoType() != INFO_FILE && r.InfoType() != INFO_SECURITY {
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
		return c.sendPacket(rsp, &t.treeConn, ctx)
	}

	if r.InfoType() == INFO_SECURITY {
		// Minimal security descriptor for named pipe srvsvc.
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
			sd.Sacl = &ACL{
				ACE{
					Sid:  &SID{IdentifierAuthority: MANDATORY_LABEL_AUTHORITY, SubAuthority: []uint32{8192}},
					Type: SYSTEM_MANDATORY_LABEL_ACE_TYPE,
					Mask: 0,
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

	var info Encoder
	switch r.FileInfoClass() {
	case FileBasicInformation:
		info = &FileBasicInformationInfo{
			CreationTime:   Filetime{},
			LastAccessTime: Filetime{},
			LastWriteTime:  Filetime{},
			ChangeTime:     Filetime{},
			FileAttributes: FILE_ATTRIBUTE_NORMAL,
		}
	case FileStandardInformation:
		info = &FileStandardInformationInfo{
			EndOfFile:      0,
			AllocationSize: 0,
			NumberOfLinks:  1,
			Directory:      0,
		}
	case FileInternalInformation:
		info = &FileInternalInformationInfo{IndexNumber: 0}
	case FileEaInformation:
		info = &FileEaInformationInfo{}
	case FileNetworkOpenInformation:
		info = &FileNetworkOpenInformationInfo{
			CreationTime:   Filetime{},
			LastAccessTime: Filetime{},
			LastWriteTime:  Filetime{},
			ChangeTime:     Filetime{},
			AllocationSize: 0,
			EndOfFile:      0,
			FileAttributes: FILE_ATTRIBUTE_NORMAL,
		}
	case FileAllInformation:
		info = &FileAllInformationInfo{
			BasicInformation: FileBasicInformationInfo{
				CreationTime:   Filetime{},
				LastAccessTime: Filetime{},
				LastWriteTime:  Filetime{},
				ChangeTime:     Filetime{},
				FileAttributes: FILE_ATTRIBUTE_NORMAL,
			},
			StandardInformation: FileStandardInformationInfo{
				EndOfFile:      0,
				AllocationSize: 0,
				NumberOfLinks:  1,
				Directory:      0,
			},
			Internal: FileInternalInformationInfo{
				IndexNumber: 0,
			},
			EaInformation: FileEaInformationInfo{},
			AccessInformation: FileAccessInformationInfo{
				AccessFlags: GENERIC_READ | GENERIC_WRITE | READ_CONTROL,
			},
			PositionInformation: FilePositionInformationInfo{},
			ModeInformation: FileModeInformationInfo{
				Mode: FILE_SYNCHRONOUS_IO_ALERT,
			},
			AlignmentInformation: FileAlignmentInformationInfo{},
			NameInformation: FileAlternateNameInformationInfo{
				FileName: "srvsvc",
			},
		}
	default:
		rsp := new(ErrorResponse)
		PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_INVALID_INFO_CLASS))
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

func (t *ipcTree) setInfo(ctx *compoundContext, pkt []byte) error {
	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
	return t.session.conn.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) lock(ctx *compoundContext, pkt []byte) error {
	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
	return t.session.conn.sendPacket(rsp, &t.treeConn, ctx)
}

func (t *ipcTree) oplockBreak(ctx *compoundContext, pkt []byte) error {
	rsp := new(ErrorResponse)
	PrepareResponse(&rsp.PacketHeader, pkt, uint32(STATUS_NOT_SUPPORTED))
	return t.session.conn.sendPacket(rsp, &t.treeConn, ctx)
}
