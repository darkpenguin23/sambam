package smb2

import (
	. "github.com/sambam/sambam/smb/internal/smb2"
)

// aceModeBits maps an access mask to rwx bits. Generic rights count as
// well; they used to be ignored, so e.g. GENERIC_ALL mapped to no access.
func aceModeBits(mask uint32) uint32 {
	bits := uint32(0)
	if mask&(FILE_READ_DATA|GENERIC_READ|GENERIC_ALL) != 0 {
		bits |= 4
	}
	if mask&(FILE_WRITE_DATA|GENERIC_WRITE|GENERIC_ALL) != 0 {
		bits |= 2
	}
	if mask&(FILE_EXECUTE|GENERIC_EXECUTE|GENERIC_ALL) != 0 {
		bits |= 1
	}
	return bits
}

// modeFromDacl derives Unix permission bits from the allow ACEs of a DACL
// written by a POSIX-aware client (Linux cifs with cifsacl/idsfromsid),
// which names the owner and group with Unix SIDs (S-1-22-1-uid,
// S-1-22-2-gid or the NFS forms S-1-5-88-1/2-id); "Everyone" stands for
// "other". Classes without an ACE keep their current bits.
//
// A DACL without a Unix owner or group ACE - one written by Windows, or the
// synthetic "Everyone: full control" DACL this server reports itself - does
// not describe Unix permissions and leaves the mode alone (ok == false).
// Deriving a mode from such a DACL used to zero the owner and group bits:
// writing back the server's own DACL made a file mode 000.
func modeFromDacl(dacl AclDecoder, current uint32) (mode uint32, ok bool) {
	var owner, group, other uint32
	var hasOwner, hasGroup, hasOther bool
	buf := dacl.Aces()
	for i := 0; i < int(dacl.AceCount()); i++ {
		if len(buf) < 8 {
			break
		}
		ace := AceDecoder(buf)
		size := int(ace.Size())
		if size < 8 || size > len(buf) {
			break
		}
		if ace.Type() == ACCESS_ALLOWED_ACE_TYPE {
			sid := SidDecoder(ace.Sid())
			if !sid.IsInvalid() {
				subs := sid.SubAuthority()
				auth, cnt := sid.IdentifierAuthority(), sid.SubAuthorityCount()
				bits := aceModeBits(ace.Mask())
				switch {
				case auth == 22 && cnt == 2 && subs[0] == 1,
					auth == 5 && cnt == 3 && subs[0] == 88 && subs[1] == 1:
					owner |= bits
					hasOwner = true
				case auth == 22 && cnt == 2 && subs[0] == 2,
					auth == 5 && cnt == 3 && subs[0] == 88 && subs[1] == 2:
					group |= bits
					hasGroup = true
				case auth == 1 && cnt == 1 && subs[0] == 0:
					other |= bits
					hasOther = true
				}
			}
		}
		buf = buf[size:]
	}
	if !hasOwner && !hasGroup {
		return 0, false
	}
	mode = current & 0o777
	if hasOwner {
		mode = mode&^0o700 | owner<<6
	}
	if hasGroup {
		mode = mode&^0o070 | group<<3
	}
	if hasOther {
		mode = mode&^0o007 | other
	}
	return mode, true
}
