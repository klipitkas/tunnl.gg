package server

import (
	"strings"

	"rsc.io/qr"
)

const (
	// qrQuietZone is the light border, in modules, that scanners need around a
	// QR code. The terminal background may be dark, so it is drawn explicitly.
	qrQuietZone = 4

	// Black on white, set explicitly: with a dark terminal theme the code would
	// otherwise be drawn inverted, which many phone cameras can't read.
	qrColors = "\033[38;5;16;48;5;231m"
	qrReset  = "\033[0m"
)

// renderQR renders text as a QR code for a terminal. Each line of output holds
// two rows of modules using half-block characters, keeping the code compact.
// Lines end with "\r\n" for SSH sessions.
func renderQR(text string, indent string) (string, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	first, last := -qrQuietZone, code.Size+qrQuietZone
	for y := first; y < last; y += 2 {
		b.WriteString(indent)
		b.WriteString(qrColors)
		for x := first; x < last; x++ {
			// Black reports false outside the code, which draws the quiet zone
			top, bottom := code.Black(x, y), code.Black(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteString(" ")
			}
		}
		b.WriteString(qrReset)
		b.WriteString("\r\n")
	}
	return b.String(), nil
}
