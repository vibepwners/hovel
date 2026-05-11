package rootcli

import (
	"os"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/testsupport"
)

func TestMain(m *testing.M) {
	os.Setenv("HOVEL_MODULE_CONFIG", testsupport.ExampleModuleConfigPath())
	os.Exit(m.Run())
}
