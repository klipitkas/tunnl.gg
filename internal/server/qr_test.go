package server

import (
	"strings"
	"testing"

	"rsc.io/qr"
)

// parseRenderedQR turns rendered half-block lines back into module rows.
func parseRenderedQR(t *testing.T, rendered string) [][]bool {
	t.Helper()
	var rows [][]bool
	for _, line := range strings.Split(strings.TrimSuffix(rendered, "\r\n"), "\r\n") {
		line = strings.TrimPrefix(line, qrColors)
		line = strings.TrimSuffix(line, qrReset)
		var top, bottom []bool
		for _, r := range line {
			top = append(top, r == '█' || r == '▀')
			bottom = append(bottom, r == '█' || r == '▄')
		}
		rows = append(rows, top, bottom)
	}
	return rows
}

func TestRenderQR_MatchesEncodedModules(t *testing.T) {
	const url = "https://happy-tiger-a1b2c3d4.tunnl.gg"
	rendered, err := renderQR(url, "")
	if err != nil {
		t.Fatalf("renderQR() error: %v", err)
	}
	code, err := qr.Encode(url, qr.M)
	if err != nil {
		t.Fatalf("qr.Encode() error: %v", err)
	}

	rows := parseRenderedQR(t, rendered)
	width := code.Size + 2*qrQuietZone
	if len(rows) < width {
		t.Fatalf("rendered %d module rows, want at least %d", len(rows), width)
	}
	for y := 0; y < width; y++ {
		if len(rows[y]) != width {
			t.Fatalf("row %d has %d modules, want %d", y, len(rows[y]), width)
		}
		for x := 0; x < width; x++ {
			want := code.Black(x-qrQuietZone, y-qrQuietZone)
			if rows[y][x] != want {
				t.Fatalf("module (%d,%d) = %v, want %v", x, y, rows[y][x], want)
			}
		}
	}
	// Any padding row past the code (odd heights) must be light
	for y := width; y < len(rows); y++ {
		for x, dark := range rows[y] {
			if dark {
				t.Fatalf("padding module (%d,%d) is dark", x, y)
			}
		}
	}
}

func TestRenderQR_BlackOnWhiteWithIndent(t *testing.T) {
	rendered, err := renderQR("https://happy-tiger-a1b2c3d4.tunnl.gg", "  ")
	if err != nil {
		t.Fatalf("renderQR() error: %v", err)
	}
	for i, line := range strings.Split(strings.TrimSuffix(rendered, "\r\n"), "\r\n") {
		if !strings.HasPrefix(line, "  "+qrColors) || !strings.HasSuffix(line, qrReset) {
			t.Fatalf("line %d should be indented and wrapped in explicit colors: %q", i, line)
		}
	}
}
