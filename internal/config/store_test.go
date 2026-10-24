package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testFTPPassword    = "ftp-QZ9-secret"
	testPaperlessToken = "paperless-QZ9-token"
)

func withSecrets() Settings {
	s := DefaultSettings()
	s.SaveType = "ftp"
	s.FTPHost = "nas.local:21"
	s.FTPUser = "scan"
	s.FTPPassword = testFTPPassword
	s.PaperlessToken = testPaperlessToken
	return s
}

func TestStoreFilesAreOwnerOnly(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A stale temporary file with wide permissions must not be reused.
	stale := filepath.Join(dir, "settings.json.tmp")
	if err := os.WriteFile(stale, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Update(withSecrets()); err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]os.FileMode{
		dir:                                 0o700,
		filepath.Join(dir, "settings.json"): 0o600,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s: mode %o, want %o", path, got, want)
		}
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".settings-") {
			t.Errorf("temporary file left behind: %s", e.Name())
		}
	}

	// Secrets survive a reload.
	reloaded, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reloaded.Get(); got.FTPPassword != testFTPPassword || got.PaperlessToken != testPaperlessToken {
		t.Errorf("secrets not persisted: %+v", got)
	}
}

func TestPublicSettingsHideSecrets(t *testing.T) {
	public := withSecrets().Public()
	raw, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, secret := range []string{testFTPPassword, testPaperlessToken} {
		if strings.Contains(text, secret) {
			t.Errorf("secret in public settings: %s", text)
		}
	}
	if !public.FTPPasswordSet || !public.PaperlessTokenSet {
		t.Errorf("set flags missing: %s", text)
	}
	if !strings.Contains(text, `"ftpUser":"scan"`) {
		t.Errorf("non-secret settings lost: %s", text)
	}
	if empty := DefaultSettings().Public(); empty.FTPPasswordSet || empty.PaperlessTokenSet {
		t.Errorf("flags set without secrets: %+v", empty)
	}
}

func TestKeepSecrets(t *testing.T) {
	current := withSecrets()

	kept := DefaultSettings().KeepSecrets(current)
	if kept.FTPPassword != testFTPPassword || kept.PaperlessToken != testPaperlessToken {
		t.Errorf("empty fields must keep stored secrets: %+v", kept)
	}

	update := DefaultSettings()
	update.FTPPassword = "new-ftp"
	update.PaperlessToken = "new-token"
	replaced := update.KeepSecrets(current)
	if replaced.FTPPassword != "new-ftp" || replaced.PaperlessToken != "new-token" {
		t.Errorf("new secrets must replace stored ones: %+v", replaced)
	}
}
