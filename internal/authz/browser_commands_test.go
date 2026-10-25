package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserCommandRequiresAuthenticatedPrivateResponse(t *testing.T) {
	const token = "synthetic-scanner-token-01234567890123456789"
	command := BrowserCommand{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", JobID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	status := http.StatusOK
	body := any(command)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("scanner authentication missing")
		}
		w.Header().Set("X-SSC-Contract", "2")
		w.WriteHeader(status)
		if status != http.StatusNoContent {
			json.NewEncoder(w).Encode(body)
		}
	}))
	defer server.Close()
	c, _ := NewControl(server.URL, token, nil)
	got, err := c.NextBrowserCommand(context.Background())
	if err != nil || *got != command {
		t.Fatalf("command: %v %v", got, err)
	}
	status = http.StatusNoContent
	if got, err := c.NextBrowserCommand(context.Background()); got != nil || err != nil {
		t.Fatal("idle poll must not start work")
	}
	for _, code := range []int{401, 404, 409, 503} {
		status = code
		if _, err := c.NextBrowserCommand(context.Background()); err == nil {
			t.Fatalf("HTTP %d accepted", code)
		}
	}
	status = http.StatusOK
	body = BrowserCommand{ID: "../../invalid", JobID: command.JobID}
	if _, err := c.NextBrowserCommand(context.Background()); err == nil {
		t.Fatal("unsafe command accepted")
	}
}

func TestBrowserGrantRequestCarriesExactCommandAndRefusesAnotherJob(t *testing.T) {
	command := BrowserCommand{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", JobID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-SSC-Contract", "2")
		if r.Method == http.MethodGet {
			json.NewEncoder(w).Encode(map[string]any{"name": contractName, "version": 2, "min_client": 1})
			return
		}
		var payload map[string]string
		json.NewDecoder(r.Body).Decode(&payload)
		if payload["expected_job"] != command.JobID || payload["command_id"] != command.ID {
			t.Error("command was not bound")
		}
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]any{"reservation_id": command.ID, "job_id": "cccccccccccccccccccccccccccccccc", "mode": "letters", "source": "button", "status": "reserved", "scan": map[string]any{"sides": "simplex", "color": "color", "dpi": 300, "bleed_through": false}})
	}))
	defer server.Close()
	c, _ := NewControl(server.URL, "synthetic-scanner-token-01234567890123456789", nil)
	if _, err := c.Authorize(WithBrowserCommand(context.Background(), command), SourceButton); err == nil {
		t.Fatal("different job granted")
	}
}
