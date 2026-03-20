package report

import "github.com/fatih/color"

var (
	colorPass = color.New(color.FgGreen, color.Bold)
	colorFail = color.New(color.FgRed, color.Bold)
	colorWarn = color.New(color.FgYellow, color.Bold)
	colorDim  = color.New(color.FgHiBlack)
)

// StatusLabel renders a PASS/FAIL label, colored when the destination is a
// terminal.
func StatusLabel(compliant bool) string {
	if compliant {
		return colorPass.Sprint("PASS")
	}
	return colorFail.Sprint("FAIL")
}

// WarnLabel renders a colored WARN label.
func WarnLabel() string {
	return colorWarn.Sprint("WARN")
}

// Dim renders text in a dimmed color, used for secondary detail lines.
func Dim(s string) string {
	return colorDim.Sprint(s)
}
