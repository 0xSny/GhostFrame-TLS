package tui

import (
	"os"
	"regexp"
	"strings"
	"unicode"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

// StripANSI removes CSI ANSI color/style sequences from s.
func StripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

// SupportsANSI reports whether the terminal accepts ANSI escape sequences.
func SupportsANSI() bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	term := strings.ToLower(os.Getenv("TERM"))
	if term == "dumb" {
		return false
	}
	return true
}

// SupportsUTF8 reports whether the locale supports UTF-8 box-drawing & block runes.
func SupportsUTF8() bool {
	for _, k := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if v := os.Getenv(k); v != "" {
			return strings.Contains(strings.ToUpper(v), "UTF-8") || strings.Contains(strings.ToUpper(v), "UTF8")
		}
	}
	// Modern SSH / Windows Terminal / Linux servers usually default to UTF-8 unless explicitly C/POSIX.
	term := strings.ToLower(os.Getenv("TERM"))
	return term != "dumb"
}

// RuneWidth returns the terminal column width (0, 1, or 2) of a single Unicode rune.
func RuneWidth(r rune) int {
	if r < 0x20 || r == 0x7F {
		return 0
	}
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || unicode.Is(unicode.Cf, r) {
		return 0
	}
	// Variation selectors & zero-width joiner
	if (r >= 0xFE00 && r <= 0xFE0F) || r == 0x200D {
		return 0
	}
	// East Asian Wide / Fullwidth ranges & CJK blocks
	if (r >= 0x1100 && r <= 0x115F) ||
		r == 0x2329 || r == 0x232A ||
		(r >= 0x2E80 && r <= 0x303E) ||
		(r >= 0x3040 && r <= 0x3247) ||
		(r >= 0x3250 && r <= 0x4DBF) ||
		(r >= 0x4E00 && r <= 0xA4CF) ||
		(r >= 0xA960 && r <= 0xA97F) ||
		(r >= 0xAC00 && r <= 0xD7A3) ||
		(r >= 0xF900 && r <= 0xFAFF) ||
		(r >= 0xFE10 && r <= 0xFE19) ||
		(r >= 0xFE30 && r <= 0xFE6F) ||
		(r >= 0xFF01 && r <= 0xFF60) ||
		(r >= 0xFFE0 && r <= 0xFFE6) ||
		(r >= 0x20000 && r <= 0x3FFFD) {
		return 2
	}
	return 1
}

// DisplayWidth computes exact terminal cell columns of s after stripping ANSI escapes.
func DisplayWidth(s string) int {
	clean := StripANSI(s)
	w := 0
	for _, r := range clean {
		w += RuneWidth(r)
	}
	return w
}

// TruncateToWidth trims s so its visible DisplayWidth never exceeds maxCols (preserving words cleanly).
func TruncateToWidth(s string, maxCols int) string {
	if maxCols <= 0 {
		return ""
	}
	if DisplayWidth(s) <= maxCols {
		return s
	}
	var b strings.Builder
	cur := 0
	inEsc := false
	clean := StripANSI(s)
	_ = inEsc
	for _, r := range clean {
		rw := RuneWidth(r)
		if cur+rw > maxCols {
			break
		}
		b.WriteRune(r)
		cur += rw
	}
	return b.String()
}

// PadRight pads s with trailing spaces so total DisplayWidth == targetCols.
func PadRight(s string, targetCols int) string {
	w := DisplayWidth(s)
	if w >= targetCols {
		return s
	}
	return s + strings.Repeat(" ", targetCols-w)
}

// BoxStyle selects UTF-8 rounded borders or pure-ASCII fallback borders.
type BoxStyle struct {
	UTF8  bool
	Color bool
	Width int // inner content column width between vertical borders
}

// DefaultBoxStyle auto-detects terminal capabilities with a fixed column width.
func DefaultBoxStyle(innerWidth int) BoxStyle {
	if innerWidth < 40 {
		innerWidth = 74
	}
	return BoxStyle{
		UTF8:  SupportsUTF8(),
		Color: SupportsANSI(),
		Width: innerWidth,
	}
}

func (b BoxStyle) c(code, s string) string {
	if !b.Color {
		return s
	}
	return code + s + "\x1b[0m"
}

func (b BoxStyle) Top(title string) string {
	tl, h, tr := "+", "-", "+"
	if b.UTF8 {
		tl, h, tr = "╭", "─", "╮"
	}
	if title == "" {
		return b.c("\x1b[36m", tl+strings.Repeat(h, b.Width+2)+tr)
	}
	t := " " + title + " "
	tw := DisplayWidth(t)
	if tw > b.Width {
		t = TruncateToWidth(t, b.Width)
		tw = DisplayWidth(t)
	}
	rem := b.Width + 2 - 2 - tw
	if rem < 0 {
		rem = 0
	}
	return b.c("\x1b[36m", tl+strings.Repeat(h, 2)) + b.c("\x1b[1;37m", t) + b.c("\x1b[36m", strings.Repeat(h, rem)+tr)
}

func (b BoxStyle) Divider() string {
	ml, h, mr := "+", "-", "+"
	if b.UTF8 {
		ml, h, mr = "├", "─", "┤"
	}
	return b.c("\x1b[36m", ml+strings.Repeat(h, b.Width+2)+mr)
}

func (b BoxStyle) Bottom() string {
	bl, h, br := "+", "-", "+"
	if b.UTF8 {
		bl, h, br = "╰", "─", "╯"
	}
	return b.c("\x1b[36m", bl+strings.Repeat(h, b.Width+2)+br)
}

func (b BoxStyle) Line(content string) string {
	v := "|"
	if b.UTF8 {
		v = "│"
	}
	if DisplayWidth(content) > b.Width {
		content = TruncateToWidth(content, b.Width)
	}
	padded := PadRight(content, b.Width)
	return b.c("\x1b[36m", v) + " " + padded + " " + b.c("\x1b[36m", v)
}
