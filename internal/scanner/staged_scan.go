package scanner

// A scan artifact is an intake envelope, NEVER a released document.
import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/mzyy94/airscap/internal/authz"
	"github.com/mzyy94/airscap/internal/vens"
	"golang.org/x/sys/unix"
)

const maxScanBytes = 128 << 20
const maxScanPages = 500

var artifactID = regexp.MustCompile(`^[0-9a-f]{32}$`)
var artifactJob = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

type ScanManifest struct {
	Version       int    `json:"version"`
	ReservationID string `json:"reservation_id"`
	JobID         string `json:"job_id"`
	Mode          string `json:"mode"`
	Source        string `json:"source"`
	Pages         int    `json:"pages"`
	SHA256        string `json:"sha256"`
	Size          int    `json:"size_bytes"`
	State         string `json:"state"`
}

// openIntake rejects symlinks in every component and requires a pre-existing
// private directory owned by this UID. Provisioning is a separate operation.
func openIntake(path string) (*os.File, error) {
	if !strings.HasPrefix(path, "/") {
		return nil, errors.New("absolute private intake required")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			continue
		}
		if part == "." || part == ".." {
			unix.Close(fd)
			return nil, errors.New("unsafe intake path")
		}
		var st unix.Stat_t
		if err = unix.Fstat(fd, &st); err != nil {
			unix.Close(fd)
			return nil, err
		}
		if st.Mode&0022 != 0 && !(st.Uid == 0 && st.Mode&unix.S_ISVTX != 0) {
			unix.Close(fd)
			return nil, errors.New("writable intake ancestor")
		}
		next, e := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		unix.Close(fd)
		if e != nil {
			return nil, e
		}
		fd = next
	}
	var st unix.Stat_t
	err = unix.Fstat(fd, &st)
	if err != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0777 != 0700 {
		unix.Close(fd)
		return nil, errors.New("intake must be owned by service UID with mode 0700")
	}
	return os.NewFile(uintptr(fd), path), nil
}

// StageButtonScan consumes exactly one authorized, cleanly terminated scan.
// No partial pages are ever published. Completion acknowledgement is mandatory.
// The single ZIP envelope is linked atomically, without overwrite, inside intake.
func StageButtonScan(ctx context.Context, sc *Scanner, cfg vens.ScanConfig, intake string) (ScanManifest, error) {
	var m ScanManifest
	if err := ctx.Err(); err != nil {
		return m, err
	}
	root, err := openIntake(intake)
	if err != nil {
		return m, err
	}
	defer root.Close()
	session, err := sc.StartScan(ctx, authz.SourceButton, cfg)
	if err != nil {
		return m, err
	}
	defer session.Close()
	g := session.Grant()
	recorder, ok := g.(authz.IntakeRecorder)
	if !ok {
		return m, errors.New("intake recorder unavailable")
	}
	if !artifactID.MatchString(g.ReservationID()) || !artifactJob.MatchString(g.JobID()) || g.Source() != authz.SourceButton {
		return m, errors.New("invalid scan binding")
	}
	switch g.Mode() {
	case "letters", "receipts", "books", "photos", "archive":
	default:
		return m, errors.New("invalid mode")
	}
	pages := []vens.Page{}
	size := 0
	for {
		if err = ctx.Err(); err != nil {
			return m, err
		}
		p, e := session.NextPage()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return m, e
		}
		size += len(p.JPEG)
		if len(p.JPEG) == 0 || size > maxScanBytes || len(pages) >= maxScanPages {
			return m, errors.New("empty or oversized scan")
		}
		ic, _, e := image.DecodeConfig(bytes.NewReader(p.JPEG))
		if e != nil || ic.Width <= 0 || ic.Height <= 0 || int64(ic.Width)*int64(ic.Height) > 40_000_000 {
			return m, errors.New("invalid page dimensions")
		}
		if _, _, e = image.Decode(bytes.NewReader(p.JPEG)); e != nil {
			return m, errors.New("incomplete image page")
		}
		pages = append(pages, p)
	}
	if len(pages) == 0 {
		return m, errors.New("empty scan")
	}
	// Ensure current authority still holds after the final page, before finishing.
	if err = g.Activity(ctx); err != nil {
		return m, err
	}
	if err = session.Close(); err != nil {
		return m, err
	}
	dpi := vens.QualityDPI[cfg.Quality]
	if dpi == 0 {
		dpi = 300
	}
	pdf, err := GeneratePDF(pages, dpi, cfg.ColorMode == vens.ColorBW)
	if err != nil {
		return m, err
	}
	if len(pdf) > maxScanBytes || !bytes.HasPrefix(pdf, []byte("%PDF-")) || !bytes.Contains(pdf, []byte("%%EOF")) {
		return m, errors.New("invalid generated PDF")
	}
	sum := sha256.Sum256(pdf)
	m = ScanManifest{1, g.ReservationID(), g.JobID(), g.Mode(), string(g.Source()), len(pages), hex.EncodeToString(sum[:]), len(pdf), "staged_not_released"}
	err = publishEnvelope(root, m, pdf)
	if err != nil {
		return m, err
	}
	encoded, _ := json.Marshal(m)
	var payload map[string]any
	json.Unmarshal(encoded, &payload)
	return m, recorder.RecordIntake(ctx, payload)
}

func publishEnvelope(root *os.File, m ScanManifest, pdf []byte) error {
	name := m.ReservationID
	if !artifactID.MatchString(name) {
		return errors.New("unsafe artifact name")
	}
	// A deterministic exclusive pending name also prevents retries from silently
	// replacing an interrupted artifact. Recovery must inspect it explicitly.
	fd, err := unix.Openat(int(root.Fd()), ".pending-"+name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	defer f.Close()
	z := zip.NewWriter(f)
	manifest, err := json.Marshal(m)
	if err != nil {
		return err
	}
	for _, entry := range []struct {
		name string
		data []byte
	}{{"manifest.json", manifest}, {"scan.pdf", pdf}} {
		w, e := z.Create(entry.name)
		if e != nil {
			return e
		}
		if _, e = w.Write(entry.data); e != nil {
			return e
		}
	}
	if err = z.Close(); err != nil {
		return err
	}
	if err = f.Chmod(0400); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	// Verify the closed ZIP and the exact bytes from disk before the link.
	st, err := f.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(f, st.Size())
	if err != nil {
		return err
	}
	for i, entry := range zr.File {
		r, e := entry.Open()
		if e != nil {
			return e
		}
		b, e := io.ReadAll(io.LimitReader(r, maxScanBytes+1))
		r.Close()
		if e != nil {
			return e
		}
		expected := manifest
		if i == 1 {
			expected = pdf
		}
		if !bytes.Equal(b, expected) {
			return errors.New("artifact integrity failure")
		}
	}
	if err = unix.Linkat(int(root.Fd()), ".pending-"+name, int(root.Fd()), name+".scan", 0); err != nil {
		return fmt.Errorf("publish intake: %w", err)
	}
	// On fsync failure the caller reports uncertainty, never release. Preserve
	// pending and linked artifacts as evidence; do not retry automatically.
	return root.Sync()
}
