package capsule

import "crypto/hpke"

// The HPKE suite is fixed. It is not negotiated in the container and there is no field
// that names it: a capsule is kycap/3, and kycap/3 is this suite.
//
// KEM: X-Wing, in recoverykey. KDF and AEAD: here, because Seal and Open are the only
// callers. info binds the container format into the key schedule so a ciphertext lifted
// into some future container fails without a format check having to remember to exist.
//
// The single-shot hpke.Seal and hpke.Open are never used: they take no AAD, and the
// manifest-as-AAD is the property that retired kycap/1.

func hpkeKDF() hpke.KDF   { return hpke.HKDFSHA256() }
func hpkeAEAD() hpke.AEAD { return hpke.AES256GCM() }
func hpkeInfo() []byte    { return []byte(KycapFileFormat) }
