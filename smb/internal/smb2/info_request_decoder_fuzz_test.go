package smb2

import "testing"

type fuzzRawInput []byte

func (f fuzzRawInput) Size() int {
	return len(f)
}

func (f fuzzRawInput) Encode(pkt []byte) {
	copy(pkt, f)
}

func FuzzInfoRequestDecodersNoPanic(f *testing.F) {
	f.Add(byte(0), encodeRequestBody(&QueryInfoRequest{
		InfoType:           0x01,
		FileInfoClass:      0x05,
		OutputBufferLength: 4096,
		FileId:             &FileId{},
		Input:              fuzzRawInput{0x01, 0x02, 0x03, 0x04},
	}))
	f.Add(byte(1), encodeRequestBody(&SetInfoRequest{
		InfoType:      0x01,
		FileInfoClass: 0x0d,
		FileId:        &FileId{},
		Input:         fuzzRawInput{0x10, 0x20, 0x30, 0x40},
	}))

	f.Fuzz(func(t *testing.T, selector byte, data []byte) {
		switch selector % 2 {
		case 0:
			r := QueryInfoRequestDecoder(data)
			mustNotPanic(t, func() {
				if r.IsInvalid() {
					return
				}
				_ = r.StructureSize()
				_ = r.InfoType()
				_ = r.FileInfoClass()
				_ = r.OutputBufferLength()
				_ = r.InputBufferOffset()
				_ = r.InputBufferLength()
				_ = r.AdditionalInformation()
				_ = r.Flags()
				_ = r.FileId()
			})
		case 1:
			r := SetInfoRequestDecoder(data)
			mustNotPanic(t, func() {
				if r.IsInvalid() {
					return
				}
				_ = r.StructureSize()
				_ = r.InfoType()
				_ = r.FileInfoClass()
				_ = r.BufferLength()
				_ = r.BufferOffset()
				_ = r.AdditionalInformation()
				_ = r.FileId()
				_ = r.Buffer()
			})
		}
	})
}

