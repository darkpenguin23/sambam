package smb2

import "testing"

func encodeRequestBody(req interface {
	Size() int
	Encode([]byte)
}) []byte {
	pkt := make([]byte, req.Size())
	req.Encode(pkt)
	out := make([]byte, len(pkt)-64)
	copy(out, pkt[64:])
	return out
}

func mustNotPanic(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decoder panicked: %v", r)
		}
	}()
	fn()
}

func FuzzRequestDecodersNoPanic(f *testing.F) {
	f.Add(byte(0), encodeRequestBody(&SessionSetupRequest{
		SecurityMode:   SMB2_NEGOTIATE_SIGNING_ENABLED,
		Capabilities:   SMB2_GLOBAL_CAP_ENCRYPTION,
		SecurityBuffer: []byte{0x60, 0x03, 0x02, 0x01, 0x05},
	}))
	f.Add(byte(1), encodeRequestBody(&TreeConnectRequest{
		Path: `\\127.0.0.1\share`,
	}))
	f.Add(byte(2), encodeRequestBody(&CreateRequest{
		Name:              "test.txt",
		DesiredAccess:     FILE_READ_DATA,
		ShareAccess:       FILE_SHARE_READ,
		CreateDisposition: FILE_OPEN_IF,
		CreateOptions:     FILE_NON_DIRECTORY_FILE,
	}))
	f.Add(byte(3), encodeRequestBody(&QueryDirectoryRequest{
		FileInfoClass:      0x25,
		FileId:             &FileId{},
		OutputBufferLength: 4096,
		FileName:           "*",
	}))

	f.Fuzz(func(t *testing.T, selector byte, data []byte) {
		switch selector % 4 {
		case 0:
			r := SessionSetupRequestDecoder(data)
			mustNotPanic(t, func() {
				if r.IsInvalid() {
					return
				}
				_ = r.StructureSize()
				_ = r.Flags()
				_ = r.SecurityMode()
				_ = r.Capabilities()
				_ = r.Channel()
				_ = r.PreviousSessionId()
				_ = r.SecurityBufferOffset()
				_ = r.SecurityBufferLength()
				_ = r.SecurityBuffer()
			})
		case 1:
			r := TreeConnectRequestDecoder(data)
			mustNotPanic(t, func() {
				if r.IsInvalid() {
					return
				}
				_ = r.StructureSize()
				_ = r.Flags()
				_ = r.PathOffset()
				_ = r.PathLength()
				_ = r.Path()
			})
		case 2:
			r := CreateRequestDecoder(data)
			mustNotPanic(t, func() {
				if r.IsInvalid() {
					return
				}
				_ = r.StructureSize()
				_ = r.SecurityFlags()
				_ = r.RequestedOplockLevel()
				_ = r.ImpersonationLevel()
				_ = r.SmbCreateFlags()
				_ = r.DesiredAccess()
				_ = r.FileAttributes()
				_ = r.ShareAccess()
				_ = r.CreateDisposition()
				_ = r.CreateOptions()
				_ = r.NameOffset()
				_ = r.NameLength()
				_ = r.CreateContextsOffset()
				_ = r.CreateContextsLength()
				_ = r.Name()
				_ = r.CreateContexts()
			})
		case 3:
			r := QueryDirectoryRequestDecoder(data)
			mustNotPanic(t, func() {
				if r.IsInvalid() {
					return
				}
				_ = r.StructureSize()
				_ = r.FileInfoClass()
				_ = r.Flags()
				_ = r.FileIndex()
				_ = r.FileId()
				_ = r.FileNameOffset()
				_ = r.FileNameLength()
				_ = r.OutputBufferLength()
				_ = r.FileName()
			})
		}
	})
}
