package recoveryclient

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
)

// Check is one drill assertion and its verdict.
type Check struct {
	Name    string `json:"name"`
	Passed  bool   `json:"passed"`
	Message string `json:"message,omitempty"`
}

// DrillResult is what a restore drill reports.
type DrillResult struct {
	Passed       bool    `json:"passed"`
	Checks       []Check `json:"checks"`
	ErrorMessage string  `json:"error_message,omitempty"`
	DurationMs   int64   `json:"duration_ms"`
	SizeBytes    int     `json:"size_bytes"`
}

// Drill proves the payload restores: it seals to a throwaway key generated and discarded
// inside this call, opens the capsule into a 0700 scratch directory wiped on return, and
// appends the product's checks, which see only the scratch directory path. The suite key is
// never involved, so a passing drill says the format restores, not that the custodians'
// cards do; that is what the product's restore runbook is for.
func Drill(ctx context.Context, payload Payload, checks func(dir string) []Check) (*DrillResult, error) {
	start := time.Now()
	result := &DrillResult{}
	fail := func(name, msg string) {
		result.Checks = append(result.Checks, Check{Name: name, Passed: false, Message: msg})
	}
	pass := func(name, msg string) {
		result.Checks = append(result.Checks, Check{Name: name, Passed: true, Message: msg})
	}
	finish := func() (*DrillResult, error) {
		result.DurationMs = time.Since(start).Milliseconds()
		result.Passed = len(result.Checks) > 0
		for _, c := range result.Checks {
			if !c.Passed {
				result.Passed = false
				if result.ErrorMessage == "" {
					result.ErrorMessage = c.Name + ": " + c.Message
				}
			}
		}
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	throwaway, err := recoverykey.Generate()
	if err != nil {
		return nil, err
	}
	raw, m, err := Seal(payload, RecoveryKey{Public: throwaway.Public(), Threshold: 2, TotalShares: 3})
	if err != nil {
		fail("Seal", AuditSafe(err.Error()))
		return finish()
	}
	result.SizeBytes = len(raw)
	pass("Seal", fmt.Sprintf("%d files, %d bytes, capsule %s", len(payload.Files), len(raw), m.CapsuleID))

	dir, err := os.MkdirTemp("", "recoveryclient-drill-*")
	if err != nil {
		fail("Sandbox", AuditSafe(err.Error()))
		return finish()
	}
	defer os.RemoveAll(dir)
	if err := os.Chmod(dir, 0700); err != nil {
		fail("Sandbox", AuditSafe(err.Error()))
		return finish()
	}
	opened, files, err := capsule.Open(raw, throwaway, dir)
	if err != nil {
		fail("Directory Unpack", AuditSafe(err.Error()))
		return finish()
	}
	if opened.CapsuleID != m.CapsuleID {
		fail("Directory Unpack", "opened manifest does not name the sealed capsule")
		return finish()
	}
	pass("Directory Unpack", fmt.Sprintf("%d files extracted into a 0700 sandbox", len(files)))
	if checks != nil {
		result.Checks = append(result.Checks, checks(dir)...)
	}
	return finish()
}
