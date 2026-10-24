package scanner

import (
	"context"
	"errors"
	"io"
	"sync"

	"github.com/mzyy94/airscap/internal/authz"
	"github.com/mzyy94/airscap/internal/vens"
)

// SimulatedScanner replaces the data channel: it counts how often a scan
// was started (scan commands sent) and serves pages.
type SimulatedScanner struct {
	mu       sync.Mutex
	Pages    int
	FailAt   int // NextPage call that returns a scanner error (1-based), 0 = never
	OpenErr  error
	Opened   int
	Closed   int
	Served   int
	nextCall int
}

func (s *SimulatedScanner) open(vens.ScanConfig) (pageStream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Opened++
	if s.OpenErr != nil {
		return nil, s.OpenErr
	}
	return s, nil
}

func (s *SimulatedScanner) NextPage() (vens.Page, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextCall++
	if s.FailAt != 0 && s.nextCall == s.FailAt {
		return vens.Page{}, &vens.ScanError{Kind: vens.ScanErrPaperJam, Msg: "simulated jam"}
	}
	if s.Served >= s.Pages {
		return vens.Page{}, io.EOF
	}
	s.Served++
	return vens.Page{Sheet: s.Served - 1, JPEG: []byte{0xff, 0xd8, 0xff, byte(s.Served)}}, nil
}

func (s *SimulatedScanner) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Closed++
	return nil
}

// RecordingAuthorizer grants (or refuses) and records every call.
type RecordingAuthorizer struct {
	mu          sync.Mutex
	Refuse      bool
	LoseAt      int // Activity call (1-based) from which the session is lost; 0 = never
	Sources     []authz.Source
	Activities  int
	Finishes    []bool
	finishCalls int
}

func (a *RecordingAuthorizer) Authorize(_ context.Context, source authz.Source) (authz.Grant, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.Sources = append(a.Sources, source)
	if a.Refuse {
		return nil, errors.Join(authz.ErrNotAuthorized, errors.New("no active session"))
	}
	return &recordingGrant{a: a, source: source}, nil
}

type recordingGrant struct {
	a      *RecordingAuthorizer
	source authz.Source
	done   bool
}

func (g *recordingGrant) ReservationID() string { return "0123456789abcdef0123456789abcdef" }
func (g *recordingGrant) JobID() string         { return "job-under-test" }
func (g *recordingGrant) Mode() string          { return "letters" }
func (g *recordingGrant) Source() authz.Source  { return g.source }

func (g *recordingGrant) Activity(ctx context.Context) error {
	g.a.mu.Lock()
	defer g.a.mu.Unlock()
	g.a.Activities++
	// Like the HTTP call of the real client.
	if err := ctx.Err(); err != nil {
		return err
	}
	if g.a.LoseAt != 0 && g.a.Activities >= g.a.LoseAt {
		return errors.New("session expired")
	}
	return nil
}

func (g *recordingGrant) Finish(_ context.Context, success bool) error {
	g.a.mu.Lock()
	defer g.a.mu.Unlock()
	g.a.finishCalls++
	if !g.done {
		g.done = true
		g.a.Finishes = append(g.a.Finishes, success)
	}
	return nil
}

func (a *RecordingAuthorizer) FinishCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.finishCalls
}

// newSimulated returns an online scanner backed by a simulated scanner.
func newSimulated(a authz.Authorizer, pages int) (*Scanner, *SimulatedScanner) {
	sim := &SimulatedScanner{Pages: pages}
	s := New("127.0.0.1", vens.DefaultDataPort, vens.DefaultControlPort, "")
	s.connected = true
	s.openSession = sim.open
	if a != nil {
		s.SetAuthorizer(a)
	}
	return s, sim
}
