package cli

import (
	"os"
	"testing"

	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/operatorsession"
	"github.com/Vibe-Pwners/hovel/internal/testsupport"
)

func TestMain(m *testing.M) {
	os.Setenv("HOVEL_MODULE_CONFIG", testsupport.ExampleModuleConfig)
	os.Exit(m.Run())
}

func newTestApp() App {
	session := operatorsession.New()
	modules := testModuleCatalog()
	return newAppWithSessionAndModules(session, modules)
}

func testModuleCatalog() modulecatalog.Catalog {
	return modulecatalog.New(
		modulecatalog.Module{
			ID:          "mock-survey@v0.0.0-example",
			Name:        "Mock Survey",
			Type:        modulecatalog.TypeSurvey,
			Version:     "v0.0.0-example",
			Summary:     "Collect example target facts.",
			RuntimeKind: modulecatalog.RuntimeJSONRPCStdio,
			Enabled:     true,
			TargetConfig: []modulecatalog.Requirement{
				{Key: "target.host", Type: modulecatalog.ValueHost, Required: true, Description: "Target host name or IP address."},
				{Key: "target.port", Type: modulecatalog.ValuePort, Required: true, Description: "Target TCP port."},
			},
		},
		modulecatalog.Module{
			ID:          "mock-exploit@v0.0.0-example",
			Name:        "Mock Exploit",
			Type:        modulecatalog.TypeExploit,
			Version:     "v0.0.0-example",
			Summary:     "Run an example exploit flow.",
			RuntimeKind: modulecatalog.RuntimeJSONRPCStdio,
			Enabled:     true,
			ChainConfig: []modulecatalog.Requirement{
				{Key: "operator.confirmed_lab", Type: modulecatalog.ValueBool, Required: true, Description: "Operator confirmed this is an authorized lab."},
			},
			TargetConfig: []modulecatalog.Requirement{
				{Key: "target.host", Type: modulecatalog.ValueHost, Required: true, Description: "Target host name or IP address."},
				{Key: "target.port", Type: modulecatalog.ValuePort, Required: true, Description: "Target TCP port."},
			},
		},
	)
}
