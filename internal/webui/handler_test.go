package webui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mzyy94/airscap/internal/config"
)

const (
	testFTPPassword    = "ftp-QZ9-secret"
	testPaperlessToken = "paperless-QZ9-token"
)

func settingsHandler(t *testing.T) (http.Handler, *config.Store) {
	t.Helper()
	store := config.NewMemoryStore()
	s := store.Get()
	s.SaveType = "paperless"
	s.FTPPassword = testFTPPassword
	s.PaperlessURL = "http://paperless.local:8000"
	s.PaperlessToken = testPaperlessToken
	if err := store.Update(s); err != nil {
		t.Fatal(err)
	}
	return NewHandler(nil, nil, 8080, store, nil, "test", nil, false), store
}

func do(t *testing.T, h http.Handler, method, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, "/api/settings", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

func assertNoSecrets(t *testing.T, body string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if strings.Contains(body, secret) {
			t.Errorf("secret %q in response: %s", secret, body)
		}
	}
}

func TestGetSettingsNeverReturnsSecrets(t *testing.T) {
	h, _ := settingsHandler(t)

	code, body := do(t, h, http.MethodGet, "")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	assertNoSecrets(t, body, testFTPPassword, testPaperlessToken)

	var got map[string]any
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatal(err)
	}
	if got["ftpPasswordSet"] != true || got["paperlessTokenSet"] != true {
		t.Errorf("set flags missing: %s", body)
	}
	if got["paperlessUrl"] != "http://paperless.local:8000" {
		t.Errorf("non-secret settings lost: %s", body)
	}
}

func TestPutSettingsKeepsSecretsAndDoesNotEchoThem(t *testing.T) {
	h, store := settingsHandler(t)

	// The UI sends back what it received: empty secret fields.
	code, body := do(t, h, http.MethodPut,
		`{"saveType":"paperless","paperlessUrl":"http://paperless.local:8000","ftpPassword":"","paperlessToken":""}`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	assertNoSecrets(t, body, testFTPPassword, testPaperlessToken)
	if got := store.Get(); got.FTPPassword != testFTPPassword || got.PaperlessToken != testPaperlessToken {
		t.Errorf("stored secrets lost: %+v", got)
	}

	// A new secret replaces the stored one and is not echoed either.
	const newToken = "paperless-QZ9-rotated"
	code, body = do(t, h, http.MethodPut,
		`{"saveType":"paperless","paperlessToken":"`+newToken+`"}`)
	if code != http.StatusOK {
		t.Fatalf("status %d: %s", code, body)
	}
	assertNoSecrets(t, body, testFTPPassword, newToken)
	if got := store.Get(); got.PaperlessToken != newToken || got.FTPPassword != testFTPPassword {
		t.Errorf("rotation failed: %+v", got)
	}
	if !strings.Contains(body, `"paperlessTokenSet":true`) {
		t.Errorf("flag missing: %s", body)
	}
}
