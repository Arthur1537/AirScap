package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/mzyy94/airscap/internal/authz"
	"github.com/mzyy94/airscap/internal/vens"
	"image"
	"image/jpeg"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type artifactStream struct {
	count     int
	fail      bool
	closeFail bool
	data      []byte
}

func (s *artifactStream) NextPage() (vens.Page, error) {
	s.count++
	if s.count > 3 {
		if s.fail {
			return vens.Page{}, errors.New("abort after three pages")
		}
		return vens.Page{}, io.EOF
	}
	return vens.Page{JPEG: s.data}, nil
}
func (s *artifactStream) Close() error {
	if s.closeFail {
		return errors.New("close failed")
	}
	return nil
}
func intakeFixture(t *testing.T) (*Scanner, *RecordingAuthorizer, string, *artifactStream) {
	t.Helper()
	root := t.TempDir()
	os.Chmod(root, 0700)
	var b bytes.Buffer
	jpeg.Encode(&b, image.NewRGBA(image.Rect(0, 0, 10, 10)), nil)
	stream := &artifactStream{data: b.Bytes()}
	a := &RecordingAuthorizer{}
	s, _ := newSimulated(a, 0)
	s.openSession = func(vens.ScanConfig) (pageStream, error) { return stream, nil }
	return s, a, root, stream
}
func TestStagedScanCompleteEnvelope(t *testing.T) {
	s, _, root, _ := intakeFixture(t)
	m, e := StageButtonScan(context.Background(), s, scanConfig(), root)
	if e != nil {
		t.Fatal(e)
	}
	if m.Pages != 3 || m.State != "staged_not_released" || m.JobID != "job-under-test" {
		t.Fatal(m)
	}
	z, e := zip.OpenReader(filepath.Join(root, m.ReservationID+".scan"))
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	r, _ := z.File[1].Open()
	pdf, _ := io.ReadAll(r)
	r.Close()
	sum := sha256.Sum256(pdf)
	if hex.EncodeToString(sum[:]) != m.SHA256 {
		t.Fatal("hash")
	}
	r, _ = z.File[0].Open()
	var stored ScanManifest
	json.NewDecoder(r).Decode(&stored)
	r.Close()
	if stored != m {
		t.Fatal("binding")
	}
	info, _ := os.Stat(filepath.Join(root, m.ReservationID+".scan"))
	if info.Mode().Perm() != 0400 {
		t.Fatal(info.Mode())
	}
}
func TestStagedScanNegativeCases(t *testing.T) {
	for _, kind := range []string{"abort-after-three", "close", "expiry", "cancel", "invalid-image", "unsafe-mode", "finish-db-error", "receipt-db-error"} {
		t.Run(kind, func(t *testing.T) {
			s, a, root, stream := intakeFixture(t)
			ctx := context.Background()
			switch kind {
			case "abort-after-three":
				stream.fail = true
			case "close":
				stream.closeFail = true
			case "expiry":
				a.LoseAt = 3
			case "cancel":
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			case "invalid-image":
				stream.data = []byte("bad image")
			case "finish-db-error":
				s.SetAuthorizer(errorAuthorizer{finish: true})
			case "receipt-db-error":
				s.SetAuthorizer(errorAuthorizer{})
			case "unsafe-mode":
				os.Chmod(root, 0755)
			}
			_, err := StageButtonScan(ctx, s, scanConfig(), root)
			if err == nil {
				t.Fatal("accepted")
			}
			files, _ := os.ReadDir(root)
			if kind != "receipt-db-error" && len(files) != 0 {
				t.Fatal("published rejected scan")
			}
		})
	}
}
func TestStagedScanRejectsSymlink(t *testing.T) {
	s, _, root, _ := intakeFixture(t)
	link := filepath.Join(t.TempDir(), "link")
	os.Symlink(root, link)
	if _, e := StageButtonScan(context.Background(), s, scanConfig(), link); e == nil {
		t.Fatal("symlink")
	}
}
func TestArtifactNoClobberConcurrent(t *testing.T) {
	_, _, root, _ := intakeFixture(t)
	dir, e := openIntake(root)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	m := ScanManifest{ReservationID: "0123456789abcdef0123456789abcdef"}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- publishEnvelope(dir, m, []byte("payload")) }()
	}
	wg.Wait()
	close(results)
	success := 0
	for e := range results {
		if e == nil {
			success++
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
}
func TestStageRequiresGrant(t *testing.T) {
	s, _, root, _ := intakeFixture(t)
	s.SetAuthorizer(authz.Deny{})
	if _, e := StageButtonScan(context.Background(), s, scanConfig(), root); e == nil {
		t.Fatal("grant bypass")
	}
}

func (g *recordingGrant) RecordIntake(context.Context, map[string]any) error { return nil }

type errorAuthorizer struct{ finish bool }

func (a errorAuthorizer) Authorize(context.Context, authz.Source) (authz.Grant, error) {
	return errorGrant{&recordingGrant{a: &RecordingAuthorizer{}, source: authz.SourceButton}, a.finish}, nil
}

type errorGrant struct {
	*recordingGrant
	finish bool
}

func (g errorGrant) Finish(context.Context, bool) error {
	if g.finish {
		return errors.New("database unavailable")
	}
	return nil
}
func (g errorGrant) RecordIntake(context.Context, map[string]any) error {
	return errors.New("receipt database unavailable")
}

type invalidBinding struct{ *recordingGrant }

func (g invalidBinding) Mode() string { return "" }

type invalidAuthorizer struct{}

func (invalidAuthorizer) Authorize(context.Context, authz.Source) (authz.Grant, error) {
	return invalidBinding{&recordingGrant{a: &RecordingAuthorizer{}, source: authz.SourceButton}}, nil
}
func TestInvalidBindingNeverFeedsFirstSheet(t *testing.T) {
	s, sim := newSimulated(invalidAuthorizer{}, 3)
	_, err := s.StartScan(context.Background(), authz.SourceButton, scanConfig())
	if !errors.Is(err, authz.ErrNotAuthorized) || sim.Opened != 0 {
		t.Fatal("invalid binding reached data channel", err, sim.Opened)
	}
}
