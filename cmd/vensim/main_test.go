package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/mzyy94/airscap/internal/vens/vensim"
)

// The simulator is a test tool: the production image must not contain it.
func TestProductionImageBuildsOnlyAirScap(t *testing.T) {
	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	text := string(dockerfile)
	if !strings.Contains(text, "./cmd/airscap") || strings.Contains(text, "vensim") || strings.Contains(text, "./...") {
		t.Fatal("Dockerfile must build ./cmd/airscap only")
	}
	// The simulator's own image is test-only and builds nothing else.
	own, err := os.ReadFile("Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(own), "./cmd/vensim") || strings.Contains(string(own), "./cmd/airscap") {
		t.Fatal("cmd/vensim/Dockerfile must build ./cmd/vensim only")
	}
}

func TestControlAPI(t *testing.T) {
	sim, err := vensim.Start(context.Background(), vensim.Config{IP: "127.0.0.3"}, vensim.Profile{})
	if err != nil {
		t.Skipf("simulator unavailable: %v", err)
	}
	defer sim.Close()
	server := httptest.NewServer(handler(context.Background(), sim))
	defer server.Close()
	for _, c := range []struct {
		method, path, body string
		status             int
	}{
		{"GET", "/health", "", 200},
		{"POST", "/profile", `{"Sheets":2,"Terminal":"H2"}`, 200},
		{"POST", "/profile", `{"Sheets":2,"Debug":true}`, 400},
		{"POST", "/press", "", 409}, // nobody paired
		{"POST", "/offline", "", 200},
		{"POST", "/online", "", 200},
		{"GET", "/requests", "", 200},
		{"DELETE", "/profile", "", 405},
	} {
		req, _ := http.NewRequest(c.method, server.URL+c.path, strings.NewReader(c.body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.status {
			t.Fatalf("%s %s: %d, want %d", c.method, c.path, resp.StatusCode, c.status)
		}
	}
}
