package smb2

import "testing"

func FuzzIoctlRequestDecoderNoPanic(f *testing.F) {
	f.Add(encodeRequestBody(&IoctlRequest{
		CtlCode:           FSCTL_PIPE_TRANSCEIVE,
		FileId:            &FileId{},
		MaxInputResponse:  4096,
		MaxOutputResponse: 65536,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input:             fuzzRawInput{0x05, 0x00, 0x0b, 0x03, 0x10, 0x20, 0x30},
	}))
	f.Add(encodeRequestBody(&IoctlRequest{
		CtlCode:           FSCTL_VALIDATE_NEGOTIATE_INFO,
		FileId:            &FileId{},
		MaxInputResponse:  1024,
		MaxOutputResponse: 1024,
		Flags:             SMB2_0_IOCTL_IS_FSCTL,
		Input:             fuzzRawInput{0x11, 0x22, 0x33, 0x44},
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		r := IoctlRequestDecoder(data)
		mustNotPanic(t, func() {
			if r.IsInvalid() {
				return
			}
			_ = r.StructureSize()
			_ = r.CtlCode()
			_ = r.FileId()
			_ = r.InputOffset()
			_ = r.InputCount()
			_ = r.MaxInputResponse()
			_ = r.OutputOffset()
			_ = r.OutputCount()
			_ = r.MaxOutputResponse()
			_ = r.Flags()
			_ = r.Data()
		})
	})
}

