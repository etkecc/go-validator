package validator

import (
	"fmt"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"

	"blitiri.com.ar/go/spf"
)

type fakeResolver struct {
	mu          sync.Mutex
	hosts       []string
	lookupIP    func(host string) ([]net.IP, error)
	lookupCNAME func(host string) (string, error)
	lookupMX    func(host string) ([]*net.MX, error)
	lookupNS    func(host string) ([]*net.NS, error)
}

func (r *fakeResolver) record(host string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hosts = append(r.hosts, host)
}

func (r *fakeResolver) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.hosts)
}

func (r *fakeResolver) LookupIP(host string) ([]net.IP, error) {
	r.record(host)
	if r.lookupIP == nil {
		return nil, nil
	}
	return r.lookupIP(host)
}

func (r *fakeResolver) LookupCNAME(host string) (string, error) {
	r.record(host)
	if r.lookupCNAME == nil {
		return "", nil
	}
	return r.lookupCNAME(host)
}

func (r *fakeResolver) LookupMX(host string) ([]*net.MX, error) {
	r.record(host)
	if r.lookupMX == nil {
		return nil, nil
	}
	return r.lookupMX(host)
}

func (r *fakeResolver) LookupNS(host string) ([]*net.NS, error) {
	r.record(host)
	if r.lookupNS == nil {
		return nil, nil
	}
	return r.lookupNS(host)
}

type spfCall struct {
	ip     net.IP
	helo   string
	sender string
}

type fakeSPF struct {
	mu      sync.Mutex
	calls   []spfCall
	results map[string]spf.Result
	panics  map[string]bool
}

func (f *fakeSPF) check(ip net.IP, helo, sender string, _ ...spf.Option) (spf.Result, error) {
	f.mu.Lock()
	f.calls = append(f.calls, spfCall{ip: ip, helo: helo, sender: sender})
	shouldPanic := f.panics[sender]
	result, ok := f.results[sender]
	f.mu.Unlock()
	if shouldPanic {
		panic("spf exploded")
	}
	if !ok {
		return spf.Pass, nil
	}
	return result, nil
}

func (f *fakeSPF) snapshot() []spfCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeSPF) senders() []string {
	calls := f.snapshot()
	senders := make([]string, 0, len(calls))
	for _, call := range calls {
		senders = append(senders, call.sender)
	}
	return senders
}

type dialCall struct {
	from string
	to   string
}

type fakeDialer struct {
	mu            sync.Mutex
	calls         []dialCall
	err           error
	errWithClient bool
	panics        bool
	closed        int
	gate          <-chan struct{}
}

func (d *fakeDialer) dial(from, to string) (io.Closer, error) {
	d.mu.Lock()
	d.calls = append(d.calls, dialCall{from: from, to: to})
	err, shouldPanic, gate, errWithClient := d.err, d.panics, d.gate, d.errWithClient
	d.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if shouldPanic {
		panic("smtp exploded")
	}
	if err != nil {
		if errWithClient {
			return closeFunc(d.markClosed), err
		}
		return nil, err
	}
	return closeFunc(d.markClosed), nil
}

func (d *fakeDialer) markClosed() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed++
	return nil
}

func (d *fakeDialer) snapshot() (calls []dialCall, closed int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.calls), d.closed
}

type closeFunc func() error

func (f closeFunc) Close() error { return f() }

type logRecorder struct {
	mu   sync.Mutex
	msgs []string
}

func (l *logRecorder) log(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.msgs = append(l.msgs, fmt.Sprintf(msg, args...))
}

func (l *logRecorder) contains(sub string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, msg := range l.msgs {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}

type testEnv struct {
	v    *V
	logs *logRecorder
	dns  *fakeResolver
	spf  *fakeSPF
	smtp *fakeDialer
}

func newEnv(t *testing.T) *testEnv {
	t.Helper()
	logs := &logRecorder{}
	env := &testEnv{
		logs: logs,
		dns:  &fakeResolver{},
		spf:  &fakeSPF{},
		smtp: &fakeDialer{},
	}
	env.v = New(&Config{
		Log: logs.log,
		Email: Email{
			From:     "check@example.net",
			Spamlist: []string{"*@spam.host", "spam@email.host", "spam@*"},
		},
		Domain: Domain{PrivateSuffixes: []string{".etke.host"}},
	})
	env.v.resolver = env.dns
	env.v.spfCheck = env.spf.check
	env.v.smtpDial = env.smtp.dial
	return env
}
