package authz

// A1: scanner-gateway contract version 2 on the AirScap side.
// testdata/scanner-gateway.json is a byte copy of ScanSnap Control's
// contracts/scanner-gateway.json; both repositories pin its SHA-256.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
)

// contractSHA256 pins the shared contract file. Change it only together
// with ScanSnap Control (tests/test_scanner_contract.py pins the same hash).
const contractSHA256 = "fc404b33c43c9809ce0e3758be8912f4f2846b180be2558b227df6bffcc624bc"

type sharedContract struct {
	Name            string                     `json:"name"`
	Version         int                        `json:"version"`
	MinClient       int                        `json:"min_client"`
	Endpoints       map[string]json.RawMessage `json:"endpoints"`
	RecoveryReasons []string                   `json:"recovery_reasons"`
}

func loadContract(t *testing.T) (sharedContract, []byte) {
	t.Helper()
	raw, err := os.ReadFile("testdata/scanner-gateway.json")
	if err != nil {
		t.Fatal(err)
	}
	var c sharedContract
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c, raw
}

func TestSharedContractFile(t *testing.T) {
	c, raw := loadContract(t)
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != contractSHA256 {
		t.Fatalf("contract file changed (sha256 %x); update both repositories together", sum)
	}
	if c.Name != contractName || c.Version != ContractVersion || c.MinClient > ContractVersion {
		t.Fatalf("contract %s v%d min_client %d does not fit client v%d", c.Name, c.Version, c.MinClient, ContractVersion)
	}
	for _, reason := range c.RecoveryReasons {
		if !reasonPattern.MatchString(reason) {
			t.Fatalf("reason %q would be reported as unspecified", reason)
		}
	}
	for _, endpoint := range []string{"GET /internal/v1/contract", "POST /internal/v1/reservations",
		"POST /internal/v1/reservations/{reservation_id}/activity", "POST /internal/v1/reservations/{reservation_id}/finish",
		"POST /internal/v1/scan-receipts"} {
		if _, ok := c.Endpoints[endpoint]; !ok {
			t.Fatalf("client uses %s, contract lacks it", endpoint)
		}
	}
}

// v2 serves the contract endpoint from the shared file.
func v2(t *testing.T, f *fakeControl, minClient int) {
	c, _ := loadContract(t)
	f.contract = func(w http.ResponseWriter) {
		w.Header().Set("X-SSC-Contract", "2")
		json.NewEncoder(w).Encode(map[string]any{"name": c.Name, "version": c.Version, "min_client": minClient})
	}
}

func scan(t *testing.T, server string) (Grant, *Control, error) {
	t.Helper()
	control, err := NewControl(server, testToken, nil)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := control.Authorize(context.Background(), SourceButton)
	return grant, control, err
}

func TestVersion1ServerKeepsVersion1Behaviour(t *testing.T) {
	f, server := newFakeControl(t)
	grant, control, err := scan(t, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if control.ServerContract() != 1 || f.contractCalls != 1 {
		t.Fatalf("server contract %d after %d calls", control.ServerContract(), f.contractCalls)
	}
	// A version-1 server refuses a late success with 409: still a refusal.
	f.finish = http.StatusConflict
	f.finishBody = `{"detail":"session expired before completion"}`
	err = grant.Finish(context.Background(), true)
	if err == nil || errors.Is(err, ErrRecoveryRequired) || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("got %v", err)
	}
	// Negotiated once per Control, not per scan.
	if _, err := control.Authorize(context.Background(), SourceButton); err != nil || f.contractCalls != 1 {
		t.Fatalf("second scan: %v, %d contract calls", err, f.contractCalls)
	}
}

func TestVersion2RecoveryRequiredIsTypedNotAcknowledgementFailure(t *testing.T) {
	cases := []struct {
		name    string
		success bool
		body    string
		want    string // "" ok, "recovery:<reason>", or "ack"
	}{
		{"finished", true, `{"status":"finished"}`, ""},
		{"failure acknowledged", false, `{"status":"recovery_required","reason":"scanner_reported_failure"}`, ""},
		{"failure acknowledged, v1 shape", false, `{"status":"recovery_required"}`, ""},
		{"authority lost", true, `{"status":"recovery_required","reason":"browser_authority_lost"}`, "recovery:browser_authority_lost"},
		{"window closed", true, `{"status":"recovery_required","reason":"scan_window_closed"}`, "recovery:scan_window_closed"},
		{"reason not printable", true, `{"status":"recovery_required","reason":"x\u001b[31m"}`, "recovery:unspecified"},
		{"failure reported finished", false, `{"status":"finished"}`, "ack"},
		{"unknown status", true, `{"status":"released"}`, "ack"},
		{"garbage", true, `not json`, "ack"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, server := newFakeControl(t)
			v2(t, f, 1)
			grant, control, err := scan(t, server.URL)
			if err != nil || control.ServerContract() != 2 {
				t.Fatalf("authorize: %v, contract %d", err, control.ServerContract())
			}
			f.finishBody = c.body
			err = grant.Finish(context.Background(), c.success)
			var recovery *RecoveryRequiredError
			switch {
			case c.want == "":
				if err != nil {
					t.Fatalf("got %v", err)
				}
			case strings.HasPrefix(c.want, "recovery:"):
				if !errors.As(err, &recovery) || !errors.Is(err, ErrRecoveryRequired) || recovery.Reason != strings.TrimPrefix(c.want, "recovery:") {
					t.Fatalf("got %v", err)
				}
			default:
				if err == nil || errors.Is(err, ErrRecoveryRequired) || err.Error() != "finish acknowledgement unavailable" {
					t.Fatalf("got %v", err)
				}
			}
			for _, h := range f.headers {
				if h != "2" {
					t.Fatalf("request without contract header: %q", f.headers)
				}
			}
		})
	}
}

func TestServerRequiringNewerClientRefusesEveryScan(t *testing.T) {
	f, server := newFakeControl(t)
	v2(t, f, ContractVersion+1)
	_, control, err := scan(t, server.URL)
	if !errors.Is(err, ErrNotAuthorized) || !strings.Contains(err.Error(), "requires scanner contract 3") {
		t.Fatalf("got %v", err)
	}
	if len(f.requests) != 0 || control.ServerContract() != 0 {
		t.Fatalf("no reservation may be requested: %v", f.requests)
	}
}

func TestUnreadableOrForeignContractRefuses(t *testing.T) {
	for name, answer := range map[string]func(w http.ResponseWriter){
		"foreign name": func(w http.ResponseWriter) { w.Write([]byte(`{"name":"other","version":2,"min_client":1}`)) },
		"not json":     func(w http.ResponseWriter) { w.Write([]byte(`<html>`)) },
		"version 1 body": func(w http.ResponseWriter) {
			w.Write([]byte(`{"name":"scansnap-scanner-gateway","version":1,"min_client":1}`))
		},
		"server error": func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) },
	} {
		t.Run(name, func(t *testing.T) {
			f, server := newFakeControl(t)
			f.contract = answer
			_, control, err := scan(t, server.URL)
			if !errors.Is(err, ErrNotAuthorized) || len(f.requests) != 0 || control.ServerContract() != 0 {
				t.Fatalf("got %v, requests %v", err, f.requests)
			}
			// Not cached: the next scan asks again.
			control.Authorize(context.Background(), SourceButton)
			if f.contractCalls != 2 {
				t.Fatalf("contract calls %d", f.contractCalls)
			}
		})
	}
}

func TestRecoveryReasonsOfTheContractArePrintable(t *testing.T) {
	c, _ := loadContract(t)
	if len(c.RecoveryReasons) < 6 || !regexp.MustCompile(`browser_authority_lost`).MatchString(strings.Join(c.RecoveryReasons, ",")) {
		t.Fatalf("reasons %v", c.RecoveryReasons)
	}
}
