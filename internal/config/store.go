package config

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"github.com/mzyy94/airscap/internal/vens"
)

// Settings holds user-configurable scan defaults.
type Settings struct {
	ColorMode             string `json:"colorMode"`
	Resolution            int    `json:"resolution"`
	PaperSize             string `json:"paperSize"` // "auto", "a4", "a5", "business_card", "postcard"
	Duplex                bool   `json:"duplex"`
	Format                string `json:"format"`
	BlankPageRemoval      *bool  `json:"blankPageRemoval"` // nil = default (true)
	BleedThrough          bool   `json:"bleedThrough"`
	BWDensity             int    `json:"bwDensity"`   // -5 to +5, only for B&W mode
	Compression           int    `json:"compression"` // 1(best quality)..5(most compressed), default 3
	SaveType              string `json:"saveType"`    // "none", "local", "ftp", "paperless"
	SavePath              string `json:"savePath"`    // directory path when SaveType="local"
	FTPHost               string `json:"ftpHost"`
	FTPUser               string `json:"ftpUser"`
	FTPPassword           string `json:"ftpPassword"`
	PaperlessURL          string `json:"paperlessUrl"`
	PaperlessToken        string `json:"paperlessToken"`
	AirscanForcePaperAuto bool   `json:"airscanForcePaperAuto"` // AirScan: force paper auto-detect for eSCL clients
	AirscanBleedThrough   bool   `json:"airscanBleedThrough"`   // AirScan: apply bleed-through reduction
	AirscanBWDensity      int    `json:"airscanBwDensity"`      // AirScan: B&W density override (-5 to +5)
	OCRForButtonScan      bool   `json:"ocrForButtonScan"`      // Apply OCR to button scan PDF output
	OCRForAirscan         bool   `json:"ocrForAirscan"`         // Apply OCR to eSCL PDF output
}

// PublicSettings is what the Web UI receives: secrets are never sent back,
// only whether one is stored.
type PublicSettings struct {
	Settings
	FTPPasswordSet    bool `json:"ftpPasswordSet"`
	PaperlessTokenSet bool `json:"paperlessTokenSet"`
}

// Public returns the settings without secrets.
func (s Settings) Public() PublicSettings {
	p := PublicSettings{
		Settings:          s,
		FTPPasswordSet:    s.FTPPassword != "",
		PaperlessTokenSet: s.PaperlessToken != "",
	}
	p.FTPPassword = ""
	p.PaperlessToken = ""
	return p
}

// KeepSecrets returns s with empty secrets taken from current. The Web UI
// never receives stored secrets, so an empty field means "unchanged".
func (s Settings) KeepSecrets(current Settings) Settings {
	if s.FTPPassword == "" {
		s.FTPPassword = current.FTPPassword
	}
	if s.PaperlessToken == "" {
		s.PaperlessToken = current.PaperlessToken
	}
	return s
}

func registerSecrets(s Settings) {
	vens.RegisterSecret(s.FTPPassword)
	vens.RegisterSecret(s.PaperlessToken)
}

// DefaultSettings returns the default scan settings.
func DefaultSettings() Settings {
	return Settings{
		ColorMode:  "auto",
		Resolution: 0,
		Duplex:     false,
		Format:     "application/pdf",
		SaveType:   "none",
		SavePath:   "",
	}
}

// Store provides thread-safe settings persistence backed by a JSON file.
type Store struct {
	mu       sync.RWMutex
	settings Settings
	path     string
}

// NewStore creates a Store that persists settings to dataDir/settings.json.
// If the file does not exist or is invalid, default settings are used.
func NewStore(dataDir string) (*Store, error) {
	// settings.json holds FTP and Paperless credentials: owner only.
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	s := &Store{
		path:     filepath.Join(dataDir, "settings.json"),
		settings: DefaultSettings(),
	}
	s.load()
	return s, nil
}

// NewMemoryStore creates a Store that keeps settings in memory only (no file persistence).
func NewMemoryStore() *Store {
	return &Store{settings: DefaultSettings()}
}

// Get returns a copy of the current settings.
func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.settings
}

// Update replaces the settings and persists to disk.
func (s *Store) Update(settings Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	registerSecrets(settings)
	s.settings = settings
	return s.save()
}

func (s *Store) load() {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return // file missing is OK, use defaults
	}
	var settings Settings
	if err := json.Unmarshal(data, &settings); err != nil {
		slog.Warn("invalid settings file, using defaults", "path", s.path, "err", err)
		return
	}
	registerSecrets(settings)
	s.settings = settings
}

func (s *Store) save() error {
	if s.path == "" {
		return nil // memory-only mode
	}
	data, err := json.MarshalIndent(s.settings, "", "  ")
	if err != nil {
		return err
	}
	// CreateTemp creates the file with mode 0600; a stale temporary file
	// with wider permissions is never reused.
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".settings-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), s.path)
}
