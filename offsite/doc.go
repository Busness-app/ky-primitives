// Package offsite copies opaque data to S3, pinned SFTP, signed SMB 2/3, or a
// local directory. Products retain target persistence, credential sealing,
// scheduling, audit, and the decision about what to copy.
//
// SMB targets require message signing and never negotiate SMB1. The underlying
// go-smb2 library can nevertheless accept an unsigned guest session from a
// server that grants one. An impersonating server could then swallow uploads
// while observing the NTLMv2 exchange. Use SMB only on a trusted network and
// verify the share independently; a host-mounted share used through file://
// avoids this library limitation.
//
// SMB Put refuses to replace an existing object and returns ErrObjectExists:
// go-smb2 does not expose an atomic replace-on-rename operation, and deleting
// the previous object before rename could lose the last good replica.
package offsite
