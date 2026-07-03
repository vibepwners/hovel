package rootcli

import (
	"os"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/testsupport"
)

func TestMain(m *testing.M) {
	if err := os.Setenv("HOVEL_MODULE_CONFIG", testsupport.ExampleModuleConfigPath()); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}
