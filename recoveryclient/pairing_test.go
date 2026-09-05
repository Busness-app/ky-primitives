package recoveryclient

import (
	"errors"
	"os"
	"testing"
)

type fatalSealer struct{ t *testing.T }

func (f fatalSealer) Seal(b []byte) (string, error) { return string(b), nil }
func (f fatalSealer) Open(string) ([]byte, error)   { f.t.Fatal("Open called"); return nil, nil }

func TestStorePairingRefusesEmptyToken(t *testing.T) {
	for _, tok := range []string{"", "  ", "\n\t"} {
		if err := StorePairing(memSettings{}, testSealer(t), "https://r.test", tok); err == nil {
			t.Fatalf("token %q stored", tok)
		}
	}
}

func TestHasPairingNeverDecrypts(t *testing.T) {
	s := memSettings{}
	if err := StorePairing(s, fatalSealer{t}, "https://r.test", "tok"); err != nil {
		t.Fatal(err)
	}
	if !HasPairing(s) {
		t.Fatal("not paired")
	}
}

func TestLoadPairingReportsKeyPinMissing(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	pair(t, dir, s)
	if _, err := LoadPairing(dir, s, testSealer(t)); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(RecoveryKeyPath(dir))
	_, err := LoadPairing(dir, s, testSealer(t))
	if !errors.Is(err, ErrKeyPinMissing) || errors.Is(err, ErrNotPaired) {
		t.Fatalf("lost pin: %v", err)
	}
}

func TestLoadPairingWrongSealerFails(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	pair(t, dir, s)
	other, _ := NewAESGCMSealer(make([]byte, 32), "other-label")
	if _, err := LoadPairing(dir, s, other); err == nil {
		t.Fatal("token opened under another sealer")
	}
	p, err := LoadPairing(dir, s, testSealer(t))
	if err != nil || p.Token != "kyrec_live_t" || p.URL != "https://recovery.example.test" {
		t.Fatalf("%v %+v", err, p)
	}
}

func TestClearPairingKeepsKeyPinAndReceipt(t *testing.T) {
	dir, s := t.TempDir(), memSettings{}
	priv := pair(t, dir, s)
	s[settingLastDeposit] = `{"capsule_id":"cap-1"}`
	if err := ClearPairing(s); err != nil {
		t.Fatal(err)
	}
	if HasPairing(s) {
		t.Error("still paired")
	}
	if _, ok := s[settingRecoveryToken]; ok {
		t.Error("token row survived")
	}
	if k, err := LoadRecoveryKey(dir, s); err != nil || k.Public.ID() != priv.Public().ID() {
		t.Errorf("key pin lost: %v", err)
	}
	if last, ok, _ := LastDeposit(s); !ok || last.CapsuleID != "cap-1" {
		t.Error("receipt lost")
	}
	if err := ClearPairing(s); !errors.Is(err, ErrNotPaired) {
		t.Errorf("second clear: %v", err)
	}
}

func TestClearPairingHalfClearedStillClears(t *testing.T) {
	s := memSettings{settingRecoveryURL: "https://r.test"}
	if err := ClearPairing(s); err != nil {
		t.Fatal(err)
	}
	if len(s) != 0 {
		t.Errorf("rows left: %v", s)
	}
}
