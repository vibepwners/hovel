package hovelconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadMergesDefaultsGlobalWorkspaceAndExplicitConfig(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	global := writeFile(t, root, "global.yaml", `apiVersion: hovel.dev/v1alpha1
kind: HovelConfig
workspace: global-workspace
modules:
  searchPaths: ["global-modules"]
  indexes: ["global-index.yaml"]
cache:
  enabled: false
runtime:
  python:
    pythonBuildStandalone:
      release: "global-pbs"
logging:
  level: warn
`)
	writeFile(t, workspace, "config.yaml", `apiVersion: hovel.dev/v1alpha1
kind: HovelConfig
modules:
  searchPaths: ["workspace-modules"]
cache:
  enabled: true
`)
	explicit := writeFile(t, root, "explicit.yaml", `apiVersion: hovel.dev/v1alpha1
kind: HovelConfig
modules:
  searchPaths: ["explicit-modules"]
logging:
  level: debug
`)

	config, sources, err := Load(Options{
		Workspace:    workspace,
		GlobalPath:   global,
		ExplicitPath: explicit,
	})
	if err != nil {
		t.Fatal(err)
	}
	if config.Workspace != "global-workspace" {
		t.Fatalf("workspace = %q, want global-workspace", config.Workspace)
	}
	if !reflect.DeepEqual(config.Modules.SearchPaths, []string{"explicit-modules"}) {
		t.Fatalf("search paths = %#v", config.Modules.SearchPaths)
	}
	if !reflect.DeepEqual(config.Modules.Indexes, []string{"global-index.yaml"}) {
		t.Fatalf("indexes = %#v", config.Modules.Indexes)
	}
	if !config.Cache.Enabled {
		t.Fatalf("cache enabled = false, want workspace override true")
	}
	if config.Runtime.Python.PythonBuildStandalone.Release != "global-pbs" {
		t.Fatalf("pbs release = %q", config.Runtime.Python.PythonBuildStandalone.Release)
	}
	if config.Logging.Level != "debug" {
		t.Fatalf("logging level = %q, want debug", config.Logging.Level)
	}
	wantSources := []string{global, filepath.Join(workspace, "config.yaml"), explicit}
	if !reflect.DeepEqual(sources, wantSources) {
		t.Fatalf("sources = %#v, want %#v", sources, wantSources)
	}
}

func TestLoadRejectsWrongKind(t *testing.T) {
	path := writeFile(t, t.TempDir(), "bad.yaml", `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
`)
	if _, _, err := Load(Options{ExplicitPath: path}); err == nil {
		t.Fatal("Load succeeded, want wrong kind error")
	}
}

func TestLoadUsesXDGConfigHomeDefaultPath(t *testing.T) {
	configHome := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configHome)
	path := filepath.Join(configHome, "hovel", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`apiVersion: hovel.dev/v1alpha1
kind: HovelConfig
logging:
  level: info
`), 0o644); err != nil {
		t.Fatal(err)
	}

	config, sources, err := Load(Options{})
	if err != nil {
		t.Fatal(err)
	}
	if config.Logging.Level != "info" {
		t.Fatalf("logging level = %q, want info", config.Logging.Level)
	}
	if !reflect.DeepEqual(sources, []string{path}) {
		t.Fatalf("sources = %#v, want %q", sources, path)
	}
}

func writeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
