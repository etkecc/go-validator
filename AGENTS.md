# go-validator

Go library (module `github.com/etkecc/go-validator/v2`) validating DNS records, domain names, and email addresses. One package, `validator`, at the repo root; every check hangs off a `*V` created by `New(*Config)`. No codegen, no `Makefile`, no vendor directory, no services: DNS, SPF, and SMTP reach the network only through the injection points in `validator.go`.

## Commands

- Full check: `just test && just lint`
- Test: `just test` prints per-function coverage, then deletes `cover.out`
- Single test: `go test -run 'TestEmailMX/record_found' ./...` (spaces in a subtest name become `_`)
- Lint: `just lint` runs `comment-guard`, then golangci-lint v2
- Fix: `just lintfix` applies golangci-lint's automatic fixes; the comment policy has no autofix
- Build: `go build ./...`
- Deps: `just update` rewrites `go.mod` and `go.sum`; ask before running it
- Prerequisites: Go 1.26+, `just`, `golangci-lint` v2. CI runs golangci-lint plus `just test`, so `comment-guard` only ever runs locally.

## Layout

| Path | Responsibility |
|---|---|
| `validator.go` | `V`, `New`, the injectable fields (`dnsResolver`, `spfChecker`, `smtpDialer`, `checkTimeout`), spamlist glob to regex |
| `emails.go` | email pipeline (parse, spamlist, MX, SPF, SMTP), sentinel errors, per-check goroutines |
| `domains.go` | domain syntax regex, base-domain extraction via public suffix list |
| `lookups.go` | one-shot A/CNAME/MX/NS helpers |
| `config.go` | `Config`; the zero value is valid |
| `fakes_test.go` | `fakeResolver`/`fakeSPF`/`fakeDialer`/`logRecorder` plus the `newEnv(t)` harness |

## Conventions

- The exported API of `/v2` is frozen: extend it with new methods and new `Config` fields, and leave a breaking change for a `/v3` module path.
- Rejection is a sentinel (`ErrSpamlist`, `ErrNoMX`, `ErrSPF`, `ErrSMTP`, `ErrTimeout`); callers match it with `errors.Is`.
- A check that needs cancellation takes `ctx context.Context` first and keeps a non-ctx wrapper: `Email` -> `EmailWithError` -> `EmailWithContext`. `Domain` pairs a bool with a `*WithError` twin; the lookup checks (`A`, `CNAME`, `MX`, `NS`) are bare bools and context-free.
- The email pipeline shares one deadline, `emailCheckTimeout` (30s, on `v.checkTimeout` so tests can shrink it). Hitting it returns `ErrTimeout`, a cancelled caller context returns `ctx.Err()`, and a done context never counts as a pass even when every check reported nil.
- New network dependency: add an unexported field on `V`, wire its real value in `New`, override it in `newEnv`. No `net.*` calls inside a check body.
- `*V` is safe for concurrent use after `New`. `New` mutates the `*Config` it is given (installs `Log`, compiles the spamlist), so build a fresh `Config` per validator instead of sharing one.
- Addresses are parsed with `net/mail`, and every later check sees the parsed `.Address`. Never regex an email.
- Comments: one line, max 120 chars, no `/* */`, no stacked `//` lines. golangci-lint does not catch this, `comment-guard` does.

## Testing

- Tests are in-package (`package validator`), table-driven, each case in `t.Run`.
- Build the validator with `newEnv(t)` and stub `env.dns`, `env.spf`, `env.smtp`. Assert through their accessors (`calls`, `senders`, `snapshot`), which are mutex-guarded because the checks run concurrently.
- No test may resolve real DNS, evaluate real SPF, or dial real SMTP; the fakes are the only transport.
- Bug fix: add the failing input as a row in the existing table for that function.

## Landmines

- A panic inside any email check is logged as `panic in <name> check` and the check PASSES. Panicking on bad input fails open, so never lean on a panic to reject.
- The first SMTP check writes `trysmtp.SMTPAddrs = []string{":25"}` for the whole process (`setSMTPAddrs`), discarding any port the host application configured. Intended: the check only talks to port 25.
- SMTP verdicts are parsed from error text: a message starting with `45` means greylist (accepted, logged as "may be invalid"), any other dial error returns `ErrSMTP`, transport failures included.
- An empty email or domain passes unless `Config.Email.Enforce` or `Config.Domain.Enforce` is set.

## Boundaries

- Always: `just test` and `just lint` before handoff, `go test -race` when touching `emails.go`.
- Ask first: `just update`, adding a module dependency, editing `.github/workflows/`.
- Never: real DNS/SPF/SMTP in tests, hand-editing `go.sum`, a fresh `//nolint` over a real finding.

## Pointers

- `justfile` - `comment-guard` is the enforced comment policy; read it before arguing with a comment failure.
- `README.md` - user-facing feature list, the only place it lives; update it when adding a check. Browse the API with `go doc`.
