package capsule

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// The CFRG companion vector for HKDF-SHA256 + AES-256-GCM, through the same hpkeKDF and
// hpkeAEAD that Open uses. If either function is ever changed to a different suite, this
// stops matching a document.
func TestHPKESuiteMatchesTheCFRGVector(t *testing.T) {
	const (
		info = "4f6465206f6e2061204772656369616e2055726e"
		skRm = "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d"
		pkRm = "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c"
		enc  = "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256"
		aad  = "436f756e742d30"
		pt   = "4265617574792069732074727574682c20747275746820626561757479"
		ct   = "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a"
	)

	priv, err := ecdh.X25519().NewPrivateKey(mustHex(t, skRm))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(priv.PublicKey().Bytes(), mustHex(t, pkRm)) {
		t.Fatal("vector's skRm does not produce its pkRm; the constants above are mistyped")
	}
	k, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	r, err := hpke.NewRecipient(mustHex(t, enc), k, hpkeKDF(), hpkeAEAD(), mustHex(t, info))
	if err != nil {
		t.Fatalf("NewRecipient: %v", err)
	}
	got, err := r.Open(mustHex(t, aad), mustHex(t, ct))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, mustHex(t, pt)) {
		t.Fatalf("plaintext = %x, want %s", got, pt)
	}
}

func TestHPKEInfoIsTheContainerFormat(t *testing.T) {
	if string(hpkeInfo()) != KycapFileFormat {
		t.Fatalf("info = %q, want %q", hpkeInfo(), KycapFileFormat)
	}
	if KycapFileFormat != "kycap/3" {
		t.Fatalf("KycapFileFormat = %q, want kycap/3", KycapFileFormat)
	}
}
