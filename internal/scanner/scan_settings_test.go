package scanner

import (
	"context"
	"testing"

	"github.com/mzyy94/airscap/internal/authz"
	"github.com/mzyy94/airscap/internal/vens"
)

// settingsAuthorizer grants like ScanSnap Control: with the job's settings.
type settingsAuthorizer struct {
	RecordingAuthorizer
	settings authz.ScanSettings
}

type settingsGrant struct {
	authz.Grant
	settings authz.ScanSettings
}

func (g settingsGrant) ScanSettings() authz.ScanSettings { return g.settings }

func (a *settingsAuthorizer) Authorize(ctx context.Context, source authz.Source) (authz.Grant, error) {
	grant, err := a.RecordingAuthorizer.Authorize(ctx, source)
	if err != nil {
		return nil, err
	}
	return settingsGrant{grant, a.settings}, nil
}

func TestJobSettingsReachTheDataChannel(t *testing.T) {
	local := scanConfig() // AirScap's own settings (duplex default etc.)
	for _, tc := range []struct {
		settings authz.ScanSettings
		duplex   bool
		color    vens.ColorMode
		quality  vens.Quality
	}{
		{authz.ScanSettings{Sides: "simplex", Color: "gray", DPI: 200, BleedThrough: true}, false, vens.ColorGray, vens.QualityFine},
		{authz.ScanSettings{Sides: "duplex", Color: "color", DPI: 300}, true, vens.ColorColor, vens.QualitySuperFine},
		{authz.ScanSettings{Sides: "duplex", Color: "bw", DPI: 150}, true, vens.ColorBW, vens.QualityNormal},
		{authz.ScanSettings{Sides: "simplex", Color: "auto", DPI: 0}, false, vens.ColorAuto, vens.QualityAuto},
	} {
		a := &settingsAuthorizer{settings: tc.settings}
		s, sim := newSimulated(a, 1)
		if _, err := s.Scan(context.Background(), authz.SourceButton, local, nil); err != nil {
			t.Fatal(err)
		}
		if len(sim.Configs) != 1 {
			t.Fatalf("configs = %d", len(sim.Configs))
		}
		got := sim.Configs[0]
		if got.Duplex != tc.duplex || got.ColorMode != tc.color || got.Quality != tc.quality ||
			got.BleedThrough != tc.settings.BleedThrough {
			t.Errorf("%+v: duplex=%v color=%v quality=%v bleed=%v", tc.settings,
				got.Duplex, got.ColorMode, got.Quality, got.BleedThrough)
		}
		if got.PaperSize != local.PaperSize || got.CompressionArg != local.CompressionArg {
			t.Errorf("unrelated local settings changed")
		}
	}
}
