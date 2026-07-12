package commandmode

import (
	"io"

	"github.com/vibepwners/hovel/internal/adapters/progressview"
)

func newInstallProgressRenderer(out io.Writer, width int, color bool) *progressview.InstallRenderer {
	return progressview.NewInstallRenderer(out, width, color)
}
