package scanner_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mzyy94/airscap/internal/authz"
	"github.com/mzyy94/airscap/internal/config"
	"github.com/mzyy94/airscap/internal/scanner"
	"github.com/mzyy94/airscap/internal/webui"
)

// The Web UI preview goes through the production checkpoint
// (Scanner.StartScan); only the data channel is simulated.
func preview(t *testing.T, a authz.Authorizer) (*httptest.ResponseRecorder, *scanner.SimulatedScanner) {
	t.Helper()
	sc, sim := scanner.NewSimulatedForTest(a, 1)
	adapter := scanner.NewESCLAdapter(sc, 8080, nil, nil)
	handler := webui.NewHandler(sc, adapter, 8080, config.NewMemoryStore(), nil,
		"test", scanner.NewScanGuard(time.Minute), false)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/scan/preview", nil))
	return rec, sim
}

func TestPreviewWithoutGrantIsForbidden(t *testing.T) {
	for name, a := range map[string]authz.Authorizer{
		"deny":    authz.Deny{},
		"refused": &scanner.RecordingAuthorizer{Refuse: true},
	} {
		t.Run(name, func(t *testing.T) {
			rec, sim := preview(t, a)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			var body map[string]string
			json.Unmarshal(rec.Body.Bytes(), &body)
			if body["error"] != "scan_not_authorized" {
				t.Errorf("body = %s", rec.Body)
			}
			if sim.Opened != 0 {
				t.Errorf("preview started a scan without grant")
			}
		})
	}
}

func TestPreviewStaysForbiddenEvenWithGrant(t *testing.T) {
	a := &scanner.RecordingAuthorizer{}
	rec, sim := preview(t, a)
	if rec.Code != http.StatusForbidden || sim.Opened != 0 || len(a.Sources) != 0 {
		t.Fatalf("preview bypass: status=%d opened=%d", rec.Code, sim.Opened)
	}
}
