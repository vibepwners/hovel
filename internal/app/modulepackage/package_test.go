package modulepackage

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestLoadDirSelectsMostSpecificLaunch(t *testing.T) {
	root := packageDir(t, `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: mock-survey
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector: {}
    command: ["bin/portable"]
  - selector:
      os: linux
      arch: amd64
    command: ["bin/linux-amd64/mock-survey"]
`)
	pkg, err := LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	launch, err := pkg.SelectLaunch("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(launch.Command, []string{"bin/linux-amd64/mock-survey"}) {
		t.Fatalf("command = %#v", launch.Command)
	}
	entry, err := pkg.LaunchEntry("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if entry.ID != "mock-survey" || entry.Runtime != "jsonrpc-stdio" {
		t.Fatalf("entry = %#v", entry)
	}
	if !filepath.IsAbs(entry.Command[0]) || filepath.Base(entry.Command[0]) != "mock-survey" {
		t.Fatalf("entry command = %#v, want absolute package command", entry.Command)
	}
}

func TestSelectLaunchRejectsAmbiguousMatches(t *testing.T) {
	root := packageDir(t, `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: ambiguous
  version: 0.1.0
  moduleType: exploit
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
    command: ["bin/a"]
  - selector:
      arch: amd64
    command: ["bin/b"]
`)
	pkg, err := LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pkg.SelectLaunch("linux", "amd64"); err == nil {
		t.Fatal("SelectLaunch succeeded, want ambiguous match error")
	}
}

func TestInstallLinkRunsScriptsAndWritesLock(t *testing.T) {
	workspace := t.TempDir()
	root := packageDir(t, `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: scripted
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/scripted"]
scripts:
  postInstall:
    command: ["/bin/sh", "scripts/post-install.sh"]
`)
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "post-install.sh"), []byte(`#!/bin/sh
printf "%s|%s|%s" "$HOVEL_MODULE_ROOT" "$HOVEL_INSTALL_ROOT" "$HOVEL_OFFLINE" > script.out
`), 0o755); err != nil {
		t.Fatal(err)
	}

	result, err := InstallLink(InstallOptions{
		Workspace: workspace,
		SourceDir: root,
		HostOS:    "linux",
		HostArch:  "amd64",
		Now:       time.Date(2026, 6, 22, 16, 20, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "scripted" || result.Version != "0.1.0" {
		t.Fatalf("result = %#v", result)
	}
	scriptOut, err := os.ReadFile(filepath.Join(root, "script.out"))
	if err != nil {
		t.Fatal(err)
	}
	wantScript := root + "|" + workspace + "|0"
	if string(scriptOut) != wantScript {
		t.Fatalf("script output = %q, want %q", string(scriptOut), wantScript)
	}
	lock, err := LoadLock(filepath.Join(workspace, "module-lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Modules) != 1 {
		t.Fatalf("lock modules = %#v", lock.Modules)
	}
	record := lock.Modules[0]
	if record.Name != "scripted" || record.Version != "0.1.0" || record.Source != root || !record.Linked {
		t.Fatalf("lock record = %#v", record)
	}
	if record.InstalledAt != "2026-06-22T16:20:00Z" {
		t.Fatalf("installedAt = %q", record.InstalledAt)
	}
}

func TestInstallLinkNoScriptsSkipsScripts(t *testing.T) {
	workspace := t.TempDir()
	root := packageDir(t, `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: quiet-script
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/quiet-script"]
scripts:
  postInstall:
    command: ["/bin/sh", "scripts/post-install.sh"]
`)
	if err := os.MkdirAll(filepath.Join(root, "scripts"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "scripts", "post-install.sh"), []byte(`#!/bin/sh
touch script-ran
`), 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := InstallLink(InstallOptions{
		Workspace: workspace,
		SourceDir: root,
		HostOS:    "linux",
		HostArch:  "amd64",
		NoScripts: true,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "script-ran")); !os.IsNotExist(err) {
		t.Fatalf("script output exists or stat failed unexpectedly: %v", err)
	}
	if _, err := LoadLock(filepath.Join(workspace, "module-lock.yaml")); err != nil {
		t.Fatalf("lock missing after no-script install: %v", err)
	}
}

func TestInstallLinkPostInstallFailureDoesNotWriteLock(t *testing.T) {
	workspace := t.TempDir()
	root := packageDir(t, `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: broken-script
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/broken-script"]
scripts:
  postInstall:
    command: ["/bin/sh", "-c", "exit 42"]
`)

	if _, err := InstallLink(InstallOptions{
		Workspace: workspace,
		SourceDir: root,
		HostOS:    "linux",
		HostArch:  "amd64",
	}); err == nil {
		t.Fatal("InstallLink succeeded, want postInstall failure")
	}
	if _, err := LoadLock(filepath.Join(workspace, "module-lock.yaml")); !os.IsNotExist(err) {
		t.Fatalf("lock exists after failed install or stat failed unexpectedly: %v", err)
	}
}

func TestInstallLinkCreatesManagedPythonVenv(t *testing.T) {
	workspace := t.TempDir()
	root := packageDir(t, `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: managed-python
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    python:
      managed:
        versions: ["3.10-3.14"]
      command: ["{python}", "-m", "managed_module"]
`)
	pbs := packageArchive(t, map[string]string{
		"python/bin/python3": `#!/bin/sh
if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
  mkdir -p "$3/bin"
  printf '#!/bin/sh\n' > "$3/bin/python"
  chmod +x "$3/bin/python"
  exit 0
fi
exit 1
`,
	})

	if _, err := InstallLink(InstallOptions{
		Workspace:                     workspace,
		SourceDir:                     root,
		HostOS:                        "linux",
		HostArch:                      "amd64",
		PythonBuildStandaloneArchive:  pbs,
		PythonBuildStandaloneCacheDir: t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	pkg, err := LoadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	entry, err := pkg.LaunchEntry("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	wantPython := filepath.Join(root, ".hovel", "python", "bin", "python")
	if entry.Command[0] != wantPython {
		t.Fatalf("command = %#v, want python %s", entry.Command, wantPython)
	}
	if _, err := os.Stat(wantPython); err != nil {
		t.Fatalf("managed venv python missing: %v", err)
	}
}

func TestInstallArchiveExtractsPackageAndWritesSHA(t *testing.T) {
	workspace := t.TempDir()
	archive := packageArchive(t, map[string]string{
		"hovel-module.yaml": `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: archived
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/archived"]
`,
		"bin/archived": "#!/bin/sh\n",
	})
	sum := fileSHA256(t, archive)

	result, err := InstallArchive(InstallOptions{
		Workspace:     workspace,
		SourceArchive: archive,
		SHA256:        sum,
		HostOS:        "linux",
		HostArch:      "amd64",
		Now:           time.Date(2026, 6, 22, 17, 50, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "archived" || result.Version != "0.1.0" {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Stat(filepath.Join(workspace, "modules", "archived", "0.1.0", ManifestName)); err != nil {
		t.Fatalf("extracted manifest missing: %v", err)
	}
	lock, err := LoadLock(filepath.Join(workspace, "module-lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Modules) != 1 || lock.Modules[0].SHA256 != sum || lock.Modules[0].Linked {
		t.Fatalf("lock modules = %#v", lock.Modules)
	}
}

func TestInstallArchivePostInstallFailureCleansExtractedPackageAndPreservesOldInstall(t *testing.T) {
	workspace := t.TempDir()
	first := packageArchive(t, map[string]string{
		"hovel-module.yaml":  minimalManifest("replace-script"),
		"bin/replace-script": "first\n",
	})
	if _, err := InstallArchive(InstallOptions{Workspace: workspace, SourceArchive: first, HostOS: "linux", HostArch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	installedRoot := filepath.Join(workspace, "modules", "replace-script", "0.1.0")
	second := packageArchive(t, map[string]string{
		"hovel-module.yaml": `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: replace-script
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/replace-script"]
scripts:
  postInstall:
    command: ["/bin/sh", "-c", "exit 42"]
`,
		"bin/replace-script": "second\n",
	})

	if _, err := InstallArchive(InstallOptions{Workspace: workspace, SourceArchive: second, HostOS: "linux", HostArch: "amd64", Replace: true}); err == nil {
		t.Fatal("InstallArchive succeeded, want postInstall failure")
	}
	body, err := os.ReadFile(filepath.Join(installedRoot, "bin", "replace-script"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "first\n" {
		t.Fatalf("installed package body = %q, want original install", string(body))
	}
	lock, err := LoadLock(filepath.Join(workspace, "module-lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Modules) != 1 || lock.Modules[0].Name != "replace-script" {
		t.Fatalf("lock modules = %#v", lock.Modules)
	}
}

func TestInstallArchiveManagedPythonRequirementsWorksWithRelativeWorkspace(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	workdir := t.TempDir()
	if err := os.Chdir(workdir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(cwd); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
	archive := packageArchive(t, map[string]string{
		"hovel-module.yaml": `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: python-reqs
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    python:
      managed:
        versions: ["3.10-3.14"]
      requirements: requirements.txt
      command: ["{python}", "-m", "python_reqs"]
`,
		"requirements.txt": "hovel-sdk\n",
	})
	pbs := packageArchive(t, map[string]string{
		"python/bin/python3": `#!/bin/sh
if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
  mkdir -p "$3/bin"
  cat > "$3/bin/python" <<'PY'
#!/bin/sh
if [ "$1" = "-m" ] && [ "$2" = "pip" ]; then
  req=""
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "-r" ]; then
      shift
      req="$1"
      break
    fi
    shift
  done
  if [ -z "$req" ] || [ ! -f "$req" ]; then
    echo "ERROR: Could not open requirements file: $req" >&2
    exit 1
  fi
  exit 0
fi
exit 1
PY
  chmod +x "$3/bin/python"
  exit 0
fi
exit 1
`,
	})

	result, err := InstallArchive(InstallOptions{
		Workspace:                     ".hovel",
		SourceArchive:                 archive,
		HostOS:                        "linux",
		HostArch:                      "amd64",
		PythonBuildStandaloneArchive:  pbs,
		PythonBuildStandaloneCacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "python-reqs" || result.Version != "0.1.0" {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Stat(filepath.Join(workdir, ".hovel", "modules", "python-reqs", "0.1.0", "requirements.txt")); err != nil {
		t.Fatalf("requirements.txt missing from installed package: %v", err)
	}
}

func TestUninstallRunsScriptsRemovesExtractedPackageAndUpdatesLock(t *testing.T) {
	workspace := t.TempDir()
	archive := packageArchive(t, map[string]string{
		"hovel-module.yaml": `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: removable
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/removable"]
scripts:
  preUninstall:
    command: ["/bin/sh", "scripts/pre-uninstall.sh"]
  postUninstall:
    command: ["/bin/sh", "scripts/post-uninstall.sh"]
`,
		"bin/removable":             "#!/bin/sh\n",
		"scripts/pre-uninstall.sh":  `printf "pre:%s\n" "$HOVEL_MODULE_ROOT" >> "$HOVEL_WORKSPACE/uninstall.log"` + "\n",
		"scripts/post-uninstall.sh": `printf "post:%s\n" "$HOVEL_MODULE_ROOT" >> "$HOVEL_WORKSPACE/uninstall.log"` + "\n",
	})
	if _, err := InstallArchive(InstallOptions{Workspace: workspace, SourceArchive: archive, HostOS: "linux", HostArch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	installedRoot := filepath.Join(workspace, "modules", "removable", "0.1.0")

	result, err := Uninstall(UninstallOptions{Workspace: workspace, Name: "removable", Version: "0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "removable" || result.Version != "0.1.0" {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Stat(installedRoot); !os.IsNotExist(err) {
		t.Fatalf("installed package still exists or stat failed unexpectedly: %v", err)
	}
	lock, err := LoadLock(filepath.Join(workspace, "module-lock.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Modules) != 0 {
		t.Fatalf("lock modules = %#v, want none", lock.Modules)
	}
	log, err := os.ReadFile(filepath.Join(workspace, "uninstall.log"))
	if err != nil {
		t.Fatal(err)
	}
	wantLog := "pre:" + installedRoot + "\npost:" + installedRoot + "\n"
	if string(log) != wantLog {
		t.Fatalf("uninstall log = %q, want %q", string(log), wantLog)
	}
}

func TestUninstallKeepsLinkedPackageRoot(t *testing.T) {
	workspace := t.TempDir()
	root := packageDir(t, `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: linked-remove
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/linked-remove"]
`)
	if _, err := InstallLink(InstallOptions{Workspace: workspace, SourceDir: root, HostOS: "linux", HostArch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(UninstallOptions{Workspace: workspace, Name: "linked-remove", Version: "0.1.0"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, ManifestName)); err != nil {
		t.Fatalf("linked package root was removed: %v", err)
	}
}

func TestInstallArchiveRejectsTraversal(t *testing.T) {
	archive := packageArchive(t, map[string]string{
		"hovel-module.yaml": minimalManifest("bad"),
		"../escape":         "nope",
	})
	if _, err := InstallArchive(InstallOptions{
		Workspace:     t.TempDir(),
		SourceArchive: archive,
		HostOS:        "linux",
		HostArch:      "amd64",
	}); err == nil {
		t.Fatal("InstallArchive succeeded, want traversal error")
	}
}

func TestInstallArchiveRejectsEscapingSymlink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "module.tgz")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	manifest := minimalManifest("badlink")
	if err := tw.WriteHeader(&tar.Header{Name: "hovel-module.yaml", Mode: 0o644, Size: int64(len(manifest))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(manifest)); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "bin/badlink", Typeflag: tar.TypeSymlink, Linkname: "../../escape"}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := InstallArchive(InstallOptions{
		Workspace:     t.TempDir(),
		SourceArchive: path,
		HostOS:        "linux",
		HostArch:      "amd64",
	}); err == nil {
		t.Fatal("InstallArchive succeeded, want escaping symlink error")
	}
}

func TestInstallArchiveRequiresReplaceForDifferentSHA(t *testing.T) {
	workspace := t.TempDir()
	first := packageArchive(t, map[string]string{
		"hovel-module.yaml": minimalManifest("same"),
		"bin/same":          "first",
	})
	second := packageArchive(t, map[string]string{
		"hovel-module.yaml": minimalManifest("same"),
		"bin/same":          "second",
	})
	opts := InstallOptions{Workspace: workspace, HostOS: "linux", HostArch: "amd64"}
	opts.SourceArchive = first
	if _, err := InstallArchive(opts); err != nil {
		t.Fatal(err)
	}
	opts.SourceArchive = second
	if _, err := InstallArchive(opts); err == nil {
		t.Fatal("InstallArchive succeeded with changed SHA, want --replace error")
	}
	opts.Replace = true
	if _, err := InstallArchive(opts); err != nil {
		t.Fatalf("InstallArchive with replace failed: %v", err)
	}
}

func TestLoadManifestArchiveReadsManifest(t *testing.T) {
	archive := packageArchive(t, map[string]string{
		"hovel-module.yaml": minimalManifest("discoverable"),
	})
	manifest, err := LoadManifestArchive(archive)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Metadata.Name != "discoverable" || manifest.Metadata.Version != "0.1.0" {
		t.Fatalf("manifest = %#v", manifest.Metadata)
	}
}

func TestLoadIndexReadsEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "index.yaml")
	if err := os.WriteFile(path, []byte(`apiVersion: hovel.dev/v1alpha1
kind: ModuleIndex
modules:
  - name: indexed
    version: 0.1.0
    url: ./indexed.tgz
    sha256: abc123
`), 0o644); err != nil {
		t.Fatal(err)
	}
	index, err := LoadIndex(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(index.Modules) != 1 || index.Modules[0].Name != "indexed" || index.Modules[0].SHA256 != "abc123" {
		t.Fatalf("index = %#v", index)
	}
}

func TestInstallURLDownloadsCachesAndInstallsArchive(t *testing.T) {
	workspace := t.TempDir()
	cache := t.TempDir()
	archive := packageArchive(t, map[string]string{
		"hovel-module.yaml": minimalManifest("remote"),
		"bin/remote":        "#!/bin/sh\n",
	})
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := fileSHA256(t, archive)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := w.Write(body); err != nil {
			t.Logf("write archive response: %v", err)
		}
	}))
	defer server.Close()

	result, err := InstallURL(InstallOptions{
		Workspace: workspace,
		SourceURL: server.URL + "/remote.tgz",
		SHA256:    sum,
		HostOS:    "linux",
		HostArch:  "amd64",
		CacheDir:  cache,
		Client:    server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "remote" || result.Version != "0.1.0" {
		t.Fatalf("result = %#v", result)
	}
	if _, err := os.Stat(filepath.Join(cache, sum+".tgz")); err != nil {
		t.Fatalf("cached archive missing: %v", err)
	}
}

func TestInstallURLReportsDownloadProgress(t *testing.T) {
	workspace := t.TempDir()
	cache := t.TempDir()
	archive := packageArchive(t, map[string]string{
		"hovel-module.yaml": minimalManifest("progress"),
		"bin/progress":      "#!/bin/sh\n",
	})
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	sum := fileSHA256(t, archive)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		if _, err := w.Write(body); err != nil {
			t.Logf("write progress archive response: %v", err)
		}
	}))
	defer server.Close()

	var events []InstallProgress
	_, err = InstallURL(InstallOptions{
		Workspace: workspace,
		SourceURL: server.URL + "/progress.tgz",
		SHA256:    sum,
		HostOS:    "linux",
		HostArch:  "amd64",
		CacheDir:  cache,
		Client:    server.Client(),
		Progress: func(event InstallProgress) {
			events = append(events, event)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !hasInstallProgressStage(events, InstallProgressDownloadStart) ||
		!hasInstallProgressStage(events, InstallProgressDownloadProgress) ||
		!hasInstallProgressStage(events, InstallProgressDownloadVerified) ||
		!hasInstallProgressStage(events, InstallProgressArchiveComplete) {
		t.Fatalf("missing expected progress events: %#v", events)
	}
	var lastDownload InstallProgress
	for _, event := range events {
		if event.Stage == InstallProgressDownloadProgress {
			lastDownload = event
		}
	}
	if lastDownload.Bytes != int64(len(body)) || lastDownload.Total != int64(len(body)) {
		t.Fatalf("last download event = %#v, want %d bytes", lastDownload, len(body))
	}
}

func TestInstallURLOfflineUsesCachedSHA(t *testing.T) {
	workspace := t.TempDir()
	cache := t.TempDir()
	archive := packageArchive(t, map[string]string{
		"hovel-module.yaml": minimalManifest("cached"),
		"bin/cached":        "#!/bin/sh\n",
	})
	sum := fileSHA256(t, archive)
	if err := os.MkdirAll(cache, 0o755); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, sum+".tgz"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := InstallURL(InstallOptions{
		Workspace: workspace,
		SourceURL: "https://example.invalid/cached.tgz",
		SHA256:    sum,
		HostOS:    "linux",
		HostArch:  "amd64",
		CacheDir:  cache,
		Offline:   true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Name != "cached" {
		t.Fatalf("result = %#v", result)
	}
}

func hasInstallProgressStage(events []InstallProgress, stage InstallProgressStage) bool {
	for _, event := range events {
		if event.Stage == stage {
			return true
		}
	}
	return false
}

func packageDir(t *testing.T, manifest string) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ManifestName), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func packageArchive(t *testing.T, files map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "module.tgz")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	got, err := FileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func minimalManifest(name string) string {
	return `apiVersion: hovel.dev/v1alpha1
kind: ModulePackage
metadata:
  name: ` + name + `
  version: 0.1.0
  moduleType: survey
runtime:
  protocol: jsonrpc-stdio
launch:
  - selector:
      os: linux
      arch: amd64
    command: ["bin/` + name + `"]
`
}
