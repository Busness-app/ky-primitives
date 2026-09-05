package recoveryclient

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDrillOpensWhatItSealedAndWipesScratch(t *testing.T) {
	var seen string
	res, err := Drill(context.Background(), testPayload(), func(dir string) []Check {
		seen = dir
		b, err := os.ReadFile(filepath.Join(dir, "data", "app.db"))
		info, _ := os.Stat(dir)
		return []Check{{Name: "db", Passed: err == nil && len(b) > 0 && info.Mode().Perm() == 0700}}
	})
	if err != nil || !res.Passed || len(res.Checks) != 3 || res.SizeBytes == 0 {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := os.Stat(seen); !os.IsNotExist(err) {
		t.Fatalf("scratch dir %s survived", seen)
	}
}

func TestDrillFailsWhenAProductCheckFails(t *testing.T) {
	res, err := Drill(context.Background(), testPayload(), func(string) []Check {
		return []Check{{Name: "admin", Passed: false, Message: "no active admin"}}
	})
	if err != nil || res.Passed || res.ErrorMessage != "admin: no active admin" {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestDrillReportsASealItCannotPerform(t *testing.T) {
	res, err := Drill(context.Background(), Payload{ServiceName: "Svc"}, nil)
	if err != nil || res.Passed || len(res.Checks) != 1 || res.Checks[0].Name != "Seal" {
		t.Fatalf("%v %+v", err, res)
	}
}
