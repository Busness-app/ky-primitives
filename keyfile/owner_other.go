//go:build !linux

package keyfile

import "os"

// Ownership metadata is not exposed portably. Symlink, identity, type and mode checks still
// apply on these platforms.
func ownedByCurrentUser(os.FileInfo) bool { return true }
