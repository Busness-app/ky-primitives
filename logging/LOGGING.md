# Logging policy

Every Ky product emits JSON lines on stderr and nothing else. A collector agent ships
them to the central log server. No product opens a socket to ship logs, and no product
writes application logs to a file from inside the process.

## What may appear on a line

Only declared keys. The vocabulary lives in `logging/field.go`; a product adds its own
with `DeclareString` and friends at package level. A key that was never declared is
dropped and counted in `dropped_fields`.

Values are sanitized and capped at 256 bytes. Control characters become U+FFFD, which is
what makes it impossible for a field value to forge a line.

## What must never be logged

Key material, share values, password hashes, session tokens, recovery codes, capsule
keys, and the plaintext of anything a user stored. The vocabulary is the enforcement: none
of these has a declared key, so there is no way to log one by accident. `ErrText` and a
`Declare*` call for something sensitive are the two ways to defeat this, and both grep.

## Levels

`KY_LOG_LEVEL` — `debug`, `info`, `warn` or `error`. Default `info`. A misspelling is a
startup error, not a silent fallback.

## Severity and facility

Every line carries an RFC 5424 `severity` and `facility`. Ordinary lines are facility 16
(`local0`); security and audit lines are facility 10 (`authpriv`), so a collector can
route the security stream to different retention without reading payloads.

## Audit records

Audit lines carry `seq`, `prev`, `hash` and `fields` at the top level, which is what
`cmd/kyauditverify` parses. Point it at the collector's export to verify a chain
centrally. `Audit` recomputes the flat keys from the fields it is given and compares them
against the record's own `Fields`; a disagreement withholds the flat keys and sets
`audit_fields_mismatch` instead of shipping a flat key that contradicts what the record
digested — the record itself, the part that is authenticated, still ships either way. The
product keeps writing its own local chained file regardless: a chain that exists only on a
machine the attacker may also own is not evidence.
