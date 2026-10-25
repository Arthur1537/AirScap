package authz

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/mzyy94/airscap/internal/vens"
)

const (
	testToken     = "scanner-token-QZ9-0123456789abcdefghijkl"
	reservationID = "0123456789abcdef0123456789abcdef"
)

// fakeControl emulates the internal API of ScanSnap Control.
type fakeControl struct {
	mu       sync.Mutex
	requests []recorded
	reserve  func(w http.ResponseWriter, source string)
	activity int // HTTP status for activity
	finish   int
	// contract answers GET /internal/v1/contract; nil is a version-1
	// server without that endpoint. Contract calls are counted, not
	// recorded, so request sequences stay those of the scan.
	contract      func(w http.ResponseWriter)
	contractCalls int
	// finishBody overrides the finish answer (contract-2 outcomes).
	finishBody string
	headers    []string // X-SSC-Contract of every request
}

type recorded struct {
	path, auth, body string
}

func newFakeControl(t *testing.T) (*fakeControl, *httptest.Server) {
	t.Helper()
	f := &fakeControl{activity: http.StatusOK, finish: http.StatusOK}
	f.reserve = func(w http.ResponseWriter, source string) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(withScan(map[string]any{
			"reservation_id": reservationID, "job_id": strings.Repeat("c", 32),
			"mode": "letters", "source": source, "status": "reserved",
		}))
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.headers = append(f.headers, r.Header.Get("X-SSC-Contract"))
		if r.Method == http.MethodGet && r.URL.Path == "/internal/v1/contract" {
			f.contractCalls++
			f.mu.Unlock()
			if f.contract == nil {
				w.WriteHeader(http.StatusNotFound)
				w.Write([]byte(`{"detail":"Not Found"}`))
			} else {
				f.contract(w)
			}
			return
		}
		f.requests = append(f.requests, recorded{r.URL.Path, r.Header.Get("Authorization"), string(body)})
		f.mu.Unlock()
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		switch {
		case r.URL.Path == "/internal/v1/reservations":
			var req map[string]string
			json.Unmarshal(body, &req)
			f.reserve(w, req["source"])
		case strings.HasSuffix(r.URL.Path, "/activity"):
			w.WriteHeader(f.activity)
			if f.activity == http.StatusOK {
				w.Write([]byte(`{"status":"recorded"}`))
			} else {
				w.Write([]byte(`{"detail":"session expired"}`))
			}
		case strings.HasSuffix(r.URL.Path, "/finish"):
			w.WriteHeader(f.finish)
			var outcome map[string]bool
			json.Unmarshal(body, &outcome)
			if f.finishBody != "" {
				w.Write([]byte(f.finishBody))
			} else if outcome["success"] {
				w.Write([]byte(`{"status":"finished"}`))
			} else {
				w.Write([]byte(`{"status":"recovery_required"}`))
			}
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	return f, server
}

func (f *fakeControl) paths() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var paths []string
	for _, r := range f.requests {
		paths = append(paths, r.path)
	}
	return paths
}

func newClient(t *testing.T, url string) *Control {
	t.Helper()
	c, err := NewControl(url, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestNewControlValidatesConfiguration(t *testing.T) {
	for _, tc := range []struct{ url, token string }{
		{"ftp://127.0.0.1", testToken},
		{"http://", testToken},
		{"http://user:pw@127.0.0.1", testToken},
		{"http://127.0.0.1/?x=1", testToken},
		{"://bad", testToken},
		{"http://127.0.0.1", "short"},
		{"http://127.0.0.1", strings.Repeat("x", 31)},
		{"http://127.0.0.1", testToken + "\n" + testToken},
		// Clear text only on loopback (IP literal); a name may resolve elsewhere.
		{"http://192.168.0.238:18082", testToken},
		{"http://localhost:18082", testToken},
		{"http://qnap.local", testToken},
	} {
		if _, err := NewControl(tc.url, tc.token, nil); err == nil {
			t.Errorf("accepted url=%q token len %d", tc.url, len(tc.token))
		}
	}
}

func TestAuthorizeGrantActivityFinish(t *testing.T) {
	f, server := newFakeControl(t)
	c := newClient(t, server.URL+"/")

	grant, err := c.Authorize(context.Background(), SourceButton)
	if err != nil {
		t.Fatal(err)
	}
	if grant.ReservationID() != reservationID || grant.Mode() != "letters" || grant.Source() != SourceButton {
		t.Errorf("grant = %+v", grant)
	}
	if err := grant.Activity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := grant.Finish(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	grant.Finish(context.Background(), false) // only the first call counts

	want := []string{
		"/internal/v1/reservations",
		"/internal/v1/reservations/" + reservationID + "/activity",
		"/internal/v1/reservations/" + reservationID + "/finish",
	}
	if got := f.paths(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %v", got)
	}
	for _, r := range f.requests {
		if r.auth != "Bearer "+testToken {
			t.Errorf("%s: authorization %q", r.path, r.auth)
		}
	}
	if f.requests[0].body != `{"source":"button"}` || f.requests[2].body != `{"success":true}` {
		t.Errorf("bodies: %q %q", f.requests[0].body, f.requests[2].body)
	}
}

func TestAuthorizeRefusals(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, source string){
		"no active session": func(w http.ResponseWriter, _ string) {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"detail":"no active session"}`))
		},
		"source not permitted": func(w http.ResponseWriter, _ string) {
			w.WriteHeader(http.StatusConflict)
			w.Write([]byte(`{"detail":"scan source not permitted"}`))
		},
		"unauthenticated": func(w http.ResponseWriter, _ string) { w.WriteHeader(http.StatusUnauthorized) },
		"disabled":        func(w http.ResponseWriter, _ string) { w.WriteHeader(http.StatusServiceUnavailable) },
		"ok but not 201":  func(w http.ResponseWriter, _ string) { w.WriteHeader(http.StatusOK) },
		"invalid json":    func(w http.ResponseWriter, _ string) { w.WriteHeader(http.StatusCreated); w.Write([]byte("{")) },
		"status not reserved": func(w http.ResponseWriter, s string) {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(withScan(map[string]any{"reservation_id": reservationID,
				"job_id": "job", "source": s, "status": "finished"}))
		},
		"other source": func(w http.ResponseWriter, _ string) {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(withScan(map[string]any{"reservation_id": reservationID,
				"job_id": "job", "source": "escl", "status": "reserved"}))
		},
		"path in reservation id": func(w http.ResponseWriter, s string) {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(withScan(map[string]any{"reservation_id": "../../jobs",
				"job_id": "job", "source": s, "status": "reserved"}))
		},
		"valid body but not 201": func(w http.ResponseWriter, s string) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(withScan(map[string]any{"reservation_id": reservationID,
				"job_id": "job", "source": s, "status": "reserved"}))
		},
		"missing job": func(w http.ResponseWriter, s string) {
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(withScan(map[string]any{"reservation_id": reservationID,
				"source": s, "status": "reserved"}))
		},
	}
	for name, reserve := range cases {
		t.Run(name, func(t *testing.T) {
			f, server := newFakeControl(t)
			f.reserve = reserve
			grant, err := newClient(t, server.URL).Authorize(context.Background(), SourceButton)
			if !errors.Is(err, ErrNotAuthorized) || grant != nil {
				t.Fatalf("grant=%v err=%v", grant, err)
			}
			for _, p := range f.paths() {
				if strings.Contains(p, "..") || strings.Contains(p, "/activity") {
					t.Errorf("unexpected follow-up request %s", p)
				}
			}
		})
	}
}

func TestUnusableReservationIsReleased(t *testing.T) {
	f, server := newFakeControl(t)
	f.reserve = func(w http.ResponseWriter, _ string) {
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(withScan(map[string]any{"reservation_id": reservationID,
			"job_id": "job", "source": "preview", "status": "reserved"}))
	}
	if _, err := newClient(t, server.URL).Authorize(context.Background(), SourceButton); err == nil {
		t.Fatal("expected refusal")
	}
	paths := f.paths()
	if len(paths) != 2 || !strings.HasSuffix(paths[1], reservationID+"/finish") {
		t.Errorf("requests = %v", paths)
	}
	if f.requests[1].body != `{"success":false}` {
		t.Errorf("release body %q", f.requests[1].body)
	}
}

func TestUnreachableControlRefuses(t *testing.T) {
	_, server := newFakeControl(t)
	url := server.URL
	server.Close()
	if _, err := newClient(t, url).Authorize(context.Background(), SourceButton); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("err = %v", err)
	}
}

func TestUnknownSourceRefusedLocally(t *testing.T) {
	f, server := newFakeControl(t)
	if _, err := newClient(t, server.URL).Authorize(context.Background(), Source("usb")); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("err = %v", err)
	}
	if len(f.paths()) != 0 {
		t.Errorf("request sent for unknown source")
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var leaked sync.Mutex
	leakedAuth := ""
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked.Lock()
		leakedAuth = r.Header.Get("Authorization")
		leaked.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer other.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	if _, err := newClient(t, redirect.URL).Authorize(context.Background(), SourceButton); !errors.Is(err, ErrNotAuthorized) {
		t.Fatalf("err = %v", err)
	}
	leaked.Lock()
	defer leaked.Unlock()
	if leakedAuth != "" {
		t.Errorf("token sent to redirect target: %q", leakedAuth)
	}
}

func TestActivityRefusalAndFinishAfterCancel(t *testing.T) {
	f, server := newFakeControl(t)
	f.activity = http.StatusConflict
	grant, err := newClient(t, server.URL).Authorize(context.Background(), SourceButton)
	if err != nil {
		t.Fatal(err)
	}
	if err := grant.Activity(context.Background()); err == nil || !strings.Contains(err.Error(), "session expired") {
		t.Errorf("activity err = %v", err)
	}

	// The request context is gone (client disconnected): release anyway.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := grant.Finish(ctx, false); err != nil {
		t.Fatalf("finish after cancel: %v", err)
	}
	if paths := f.paths(); !strings.HasSuffix(paths[len(paths)-1], "/finish") {
		t.Errorf("no release: %v", paths)
	}
}

func TestTokenNeverInErrorsAndRegistered(t *testing.T) {
	_, server := newFakeControl(t)
	c := newClient(t, server.URL)
	if vens.ScrubSecrets(testToken) != vens.Redacted {
		t.Error("token not registered for log redaction")
	}
	server.Close()
	_, err := c.Authorize(context.Background(), SourceButton)
	if err == nil || strings.Contains(err.Error(), testToken) {
		t.Errorf("err = %v", err)
	}
}

func TestRefusalDetailIsScrubbed(t *testing.T) {
	f, server := newFakeControl(t)
	f.reserve = func(w http.ResponseWriter, _ string) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"detail": "bad token " + testToken + "\x1b[2J"})
	}
	_, err := newClient(t, server.URL).Authorize(context.Background(), SourceButton)
	if err == nil || strings.Contains(err.Error(), testToken) || strings.ContainsRune(err.Error(), 0x1b) {
		t.Fatalf("err = %q", err)
	}
	if !strings.Contains(err.Error(), "HTTP 401: bad token "+vens.Redacted) {
		t.Errorf("err = %q", err)
	}
}

func TestDenyRefuses(t *testing.T) {
	if _, err := (Deny{}).Authorize(context.Background(), SourceButton); !errors.Is(err, ErrNotAuthorized) {
		t.Fatal(err)
	}
}

func TestNewControlTransportPolicy(t *testing.T) {
	for _, url := range []string{"http://127.0.0.1:18082", "http://127.8.9.10", "http://[::1]:18082",
		"https://192.168.0.238:18443", "https://qnap.local"} {
		if _, err := NewControl(url, testToken, nil); err != nil {
			t.Errorf("%s refused: %v", url, err)
		}
	}
}

var testScan = map[string]any{"sides": "simplex", "color": "gray", "dpi": 200, "bleed_through": true}

// withScan adds the job's scan settings, as ScanSnap Control sends them.
func withScan(body map[string]any) map[string]any {
	if _, ok := body["scan"]; !ok {
		body["scan"] = testScan
	}
	return body
}

func TestGrantCarriesScanSettings(t *testing.T) {
	_, server := newFakeControl(t)
	grant, err := newClient(t, server.URL).Authorize(context.Background(), SourceButton)
	if err != nil {
		t.Fatal(err)
	}
	want := ScanSettings{Sides: "simplex", Color: "gray", DPI: 200, BleedThrough: true}
	if got := grant.(SettingsGrant).ScanSettings(); got != want {
		t.Fatalf("settings = %+v", got)
	}
}

func TestMissingOrInvalidScanSettingsRefuseAndRelease(t *testing.T) {
	cases := map[string]any{
		"missing":        nil,
		"dpi 600":        map[string]any{"sides": "duplex", "color": "auto", "dpi": 600, "bleed_through": false},
		"dpi as string":  map[string]any{"sides": "duplex", "color": "auto", "dpi": "300", "bleed_through": false},
		"unknown color":  map[string]any{"sides": "duplex", "color": "mono", "dpi": 300, "bleed_through": false},
		"unknown sides":  map[string]any{"sides": "both", "color": "auto", "dpi": 300, "bleed_through": false},
		"bleed not bool": map[string]any{"sides": "duplex", "color": "auto", "dpi": 300, "bleed_through": "yes"},
		"field missing":  map[string]any{"sides": "duplex", "color": "auto", "dpi": 300},
		"extra field":    map[string]any{"sides": "duplex", "color": "auto", "dpi": 300, "bleed_through": false, "paper": "a4"},
		"not an object":  "duplex",
	}
	for name, scan := range cases {
		t.Run(name, func(t *testing.T) {
			f, server := newFakeControl(t)
			f.reserve = func(w http.ResponseWriter, source string) {
				body := map[string]any{"reservation_id": reservationID, "job_id": "job", "mode": "letters",
					"source": source, "status": "reserved"}
				if scan != nil {
					body["scan"] = scan
				}
				w.WriteHeader(http.StatusCreated)
				json.NewEncoder(w).Encode(body)
			}
			if _, err := newClient(t, server.URL).Authorize(context.Background(), SourceButton); !errors.Is(err, ErrNotAuthorized) {
				t.Fatalf("err = %v", err)
			}
			paths := f.paths()
			if len(paths) != 2 || !strings.HasSuffix(paths[1], "/finish") {
				t.Errorf("reservation not released: %v", paths)
			}
		})
	}
}
