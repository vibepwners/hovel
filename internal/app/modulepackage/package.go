package modulepackage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion           = "hovel.dev/v1alpha1"
	Kind                 = "ModulePackage"
	ManifestName         = "hovel-module.yaml"
	ProtocolJSONRPCStdio = "jsonrpc-stdio"
	DefaultPBSRelease    = "20260610"
	defaultHTTPTimeout   = 30 * time.Second
)

type Package struct {
	Root     string
	Manifest Manifest
}

type Manifest struct {
	APIVersion   string                 `yaml:"apiVersion"`
	Kind         string                 `yaml:"kind"`
	Metadata     Metadata               `yaml:"metadata"`
	Runtime      Runtime                `yaml:"runtime"`
	Launch       []Launch               `yaml:"launch"`
	Scripts      Scripts                `yaml:"scripts,omitempty"`
	Interpreters map[string]Interpreter `yaml:"interpreters,omitempty"`
}

type InstallSet struct {
	APIVersion string            `yaml:"apiVersion"`
	Kind       string            `yaml:"kind"`
	Modules    []InstallSetEntry `yaml:"modules"`
}

type Index struct {
	APIVersion string       `yaml:"apiVersion"`
	Kind       string       `yaml:"kind"`
	Modules    []IndexEntry `yaml:"modules"`
}

type IndexEntry struct {
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	URL     string `yaml:"url"`
	SHA256  string `yaml:"sha256,omitempty"`
}

type InstallSetEntry struct {
	Source string `yaml:"source"`
	SHA256 string `yaml:"sha256,omitempty"`
}

type Metadata struct {
	Name       string   `yaml:"name"`
	Version    string   `yaml:"version"`
	ModuleType string   `yaml:"moduleType"`
	Summary    string   `yaml:"summary,omitempty"`
	Tags       []string `yaml:"tags,omitempty"`
	Author     string   `yaml:"author,omitempty"`
	License    string   `yaml:"license,omitempty"`
	Homepage   string   `yaml:"homepage,omitempty"`
	Repository string   `yaml:"repository,omitempty"`
}

type Runtime struct {
	Protocol string `yaml:"protocol"`
}

type Launch struct {
	Selector Selector `yaml:"selector"`
	Command  []string `yaml:"command,omitempty"`
	Python   *Python  `yaml:"python,omitempty"`
}

type Selector struct {
	OS   string `yaml:"os,omitempty"`
	Arch string `yaml:"arch,omitempty"`
}

type Python struct {
	Managed      *ManagedPython `yaml:"managed,omitempty"`
	Interpreter  string         `yaml:"interpreter,omitempty"`
	Requirements string         `yaml:"requirements,omitempty"`
	Wheelhouse   string         `yaml:"wheelhouse,omitempty"`
	Command      []string       `yaml:"command"`
}

type ManagedPython struct {
	Versions []string `yaml:"versions"`
}

type Interpreter struct {
	Path string `yaml:"path"`
}

type Scripts struct {
	PreInstall    *Script `yaml:"preInstall,omitempty"`
	PostInstall   *Script `yaml:"postInstall,omitempty"`
	PreUninstall  *Script `yaml:"preUninstall,omitempty"`
	PostUninstall *Script `yaml:"postUninstall,omitempty"`
}

type Script struct {
	Command []string `yaml:"command"`
}

type LaunchEntry struct {
	ID         string   `json:"id"`
	Runtime    string   `json:"runtime"`
	ProjectDir string   `json:"project_dir,omitempty"`
	Module     string   `json:"module,omitempty"`
	Command    []string `json:"command,omitempty"`
}

func LoadDir(root string) (Package, error) {
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "." || root == "" {
		return Package{}, errors.New("module package root is required")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return Package{}, err
	}
	root = absRoot
	body, err := os.ReadFile(filepath.Join(root, ManifestName))
	if err != nil {
		return Package{}, err
	}
	var manifest Manifest
	if err := yaml.Unmarshal(body, &manifest); err != nil {
		return Package{}, err
	}
	manifest.normalize()
	if err := manifest.validate(); err != nil {
		return Package{}, err
	}
	return Package{Root: root, Manifest: manifest}, nil
}

func LoadManifestArchive(path string) (Manifest, error) {
	file, err := os.Open(path)
	if err != nil {
		return Manifest{}, err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return Manifest{}, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return Manifest{}, fmt.Errorf("%s not found in archive", ManifestName)
		}
		if err != nil {
			return Manifest{}, err
		}
		if filepath.Clean(header.Name) != ManifestName {
			continue
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return Manifest{}, err
		}
		var manifest Manifest
		if err := yaml.Unmarshal(body, &manifest); err != nil {
			return Manifest{}, err
		}
		manifest.normalize()
		if err := manifest.validate(); err != nil {
			return Manifest{}, err
		}
		return manifest, nil
	}
}

const InstallSetKind = "ModuleInstallSet"
const IndexKind = "ModuleIndex"

func LoadInstallSet(path string) (InstallSet, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return InstallSet{}, err
	}
	return ParseInstallSet(body)
}

func LoadInstallSetURL(source string, opts InstallOptions) (InstallSet, error) {
	source = strings.TrimSpace(source)
	parsed, err := url.Parse(source)
	if err != nil {
		return InstallSet{}, err
	}
	if parsed.Scheme != "https" {
		return InstallSet{}, errors.New("module bulk-install manifests require https")
	}
	if opts.Offline {
		return InstallSet{}, errors.New("offline module bulk-install cannot download a remote manifest")
	}
	client := installHTTPClient(opts)
	resp, err := client.Get(source)
	if err != nil {
		return InstallSet{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return InstallSet{}, fmt.Errorf("download %s failed: %s", source, resp.Status)
	}
	total := resp.ContentLength
	reportInstallProgress(opts, InstallProgress{
		Stage:  InstallProgressDownloadStart,
		Source: source,
		Total:  total,
	})
	var body bytes.Buffer
	if _, err := copyWithInstallProgress(&body, resp.Body, opts, InstallProgress{
		Stage:  InstallProgressDownloadProgress,
		Source: source,
		Total:  total,
	}); err != nil {
		return InstallSet{}, err
	}
	reportInstallProgress(opts, InstallProgress{
		Stage:  InstallProgressDownloadComplete,
		Source: source,
		Bytes:  int64(body.Len()),
		Total:  total,
	})
	return ParseInstallSet(body.Bytes())
}

func ParseInstallSet(body []byte) (InstallSet, error) {
	var set InstallSet
	if err := yaml.Unmarshal(body, &set); err != nil {
		return InstallSet{}, err
	}
	set.APIVersion = strings.TrimSpace(set.APIVersion)
	set.Kind = strings.TrimSpace(set.Kind)
	if set.APIVersion != APIVersion {
		return InstallSet{}, fmt.Errorf("unsupported apiVersion %q", set.APIVersion)
	}
	if set.Kind != InstallSetKind {
		return InstallSet{}, fmt.Errorf("unsupported kind %q", set.Kind)
	}
	if len(set.Modules) == 0 {
		return InstallSet{}, errors.New("modules is required")
	}
	for i := range set.Modules {
		set.Modules[i].Source = strings.TrimSpace(set.Modules[i].Source)
		set.Modules[i].SHA256 = strings.TrimSpace(set.Modules[i].SHA256)
		if set.Modules[i].Source == "" {
			return InstallSet{}, fmt.Errorf("modules[%d].source is required", i)
		}
	}
	return set, nil
}

func LoadIndex(path string) (Index, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Index{}, err
	}
	return ParseIndex(body)
}

func ParseIndex(body []byte) (Index, error) {
	var index Index
	if err := yaml.Unmarshal(body, &index); err != nil {
		return Index{}, err
	}
	index.APIVersion = strings.TrimSpace(index.APIVersion)
	index.Kind = strings.TrimSpace(index.Kind)
	if index.APIVersion != APIVersion {
		return Index{}, fmt.Errorf("unsupported apiVersion %q", index.APIVersion)
	}
	if index.Kind != IndexKind {
		return Index{}, fmt.Errorf("unsupported kind %q", index.Kind)
	}
	if len(index.Modules) == 0 {
		return Index{}, errors.New("modules is required")
	}
	for i := range index.Modules {
		index.Modules[i].Name = strings.TrimSpace(index.Modules[i].Name)
		index.Modules[i].Version = strings.TrimSpace(index.Modules[i].Version)
		index.Modules[i].URL = strings.TrimSpace(index.Modules[i].URL)
		index.Modules[i].SHA256 = strings.TrimSpace(index.Modules[i].SHA256)
		if index.Modules[i].Name == "" {
			return Index{}, fmt.Errorf("modules[%d].name is required", i)
		}
		if index.Modules[i].Version == "" {
			return Index{}, fmt.Errorf("modules[%d].version is required", i)
		}
		if index.Modules[i].URL == "" {
			return Index{}, fmt.Errorf("modules[%d].url is required", i)
		}
	}
	return index, nil
}

func (m *Manifest) normalize() {
	m.APIVersion = strings.TrimSpace(m.APIVersion)
	m.Kind = strings.TrimSpace(m.Kind)
	m.Metadata.Name = strings.TrimSpace(m.Metadata.Name)
	m.Metadata.Version = strings.TrimSpace(m.Metadata.Version)
	m.Metadata.ModuleType = strings.TrimSpace(m.Metadata.ModuleType)
	m.Metadata.Summary = strings.TrimSpace(m.Metadata.Summary)
	m.Runtime.Protocol = strings.TrimSpace(m.Runtime.Protocol)
	if m.Runtime.Protocol == "" {
		m.Runtime.Protocol = ProtocolJSONRPCStdio
	}
	for i := range m.Launch {
		m.Launch[i].Selector.OS = strings.TrimSpace(m.Launch[i].Selector.OS)
		m.Launch[i].Selector.Arch = strings.TrimSpace(m.Launch[i].Selector.Arch)
	}
}

func (m Manifest) validate() error {
	if m.APIVersion != APIVersion {
		return fmt.Errorf("unsupported apiVersion %q", m.APIVersion)
	}
	if m.Kind != Kind {
		return fmt.Errorf("unsupported kind %q", m.Kind)
	}
	if m.Metadata.Name == "" {
		return errors.New("metadata.name is required")
	}
	if m.Metadata.Version == "" {
		return errors.New("metadata.version is required")
	}
	if m.Metadata.ModuleType == "" {
		return errors.New("metadata.moduleType is required")
	}
	if m.Runtime.Protocol != ProtocolJSONRPCStdio {
		return fmt.Errorf("unsupported runtime protocol %q", m.Runtime.Protocol)
	}
	if len(m.Launch) == 0 {
		return errors.New("launch is required")
	}
	for i, launch := range m.Launch {
		if len(launch.Command) == 0 && launch.Python == nil {
			return fmt.Errorf("launch entry %d requires command or python", i+1)
		}
		if len(launch.Command) != 0 && launch.Python != nil {
			return fmt.Errorf("launch entry %d cannot set both command and python", i+1)
		}
		if launch.Python != nil && len(launch.Python.Command) == 0 {
			return fmt.Errorf("launch entry %d python.command is required", i+1)
		}
		if launch.Python != nil && launch.Python.Managed != nil && len(launch.Python.Managed.Versions) == 0 {
			return fmt.Errorf("launch entry %d python.managed.versions is required", i+1)
		}
	}
	return nil
}

func (p Package) SelectLaunch(goos, goarch string) (Launch, error) {
	goos = strings.TrimSpace(goos)
	goarch = strings.TrimSpace(goarch)
	bestScore := -1
	var best Launch
	ties := 0
	for _, launch := range p.Manifest.Launch {
		score, ok := selectorScore(launch.Selector, goos, goarch)
		if !ok {
			continue
		}
		if score > bestScore {
			bestScore = score
			best = launch
			ties = 1
			continue
		}
		if score == bestScore {
			ties++
		}
	}
	if bestScore < 0 {
		return Launch{}, fmt.Errorf("no launcher for host %s/%s", goos, goarch)
	}
	if ties > 1 {
		return Launch{}, fmt.Errorf("ambiguous launcher for host %s/%s", goos, goarch)
	}
	return best, nil
}

func selectorScore(selector Selector, goos, goarch string) (int, bool) {
	score := 0
	if selector.OS != "" {
		if selector.OS != goos {
			return 0, false
		}
		score++
	}
	if selector.Arch != "" {
		if selector.Arch != goarch {
			return 0, false
		}
		score++
	}
	return score, true
}

func (p Package) LaunchEntry(goos, goarch string) (LaunchEntry, error) {
	launch, err := p.SelectLaunch(goos, goarch)
	if err != nil {
		return LaunchEntry{}, err
	}
	entry := LaunchEntry{
		ID:         p.Manifest.Metadata.Name,
		Runtime:    p.Manifest.Runtime.Protocol,
		ProjectDir: p.Root,
	}
	if len(launch.Command) != 0 {
		entry.Command = resolveCommand(p.Root, launch.Command)
		return entry, nil
	}
	if launch.Python != nil {
		command, err := p.pythonCommand(*launch.Python, goos)
		if err != nil {
			return LaunchEntry{}, err
		}
		entry.Command = command
		entry.Module = pythonModuleName(command)
		return entry, nil
	}
	return LaunchEntry{}, errors.New("launch entry has no command")
}

func pythonModuleName(command []string) string {
	for i, arg := range command {
		if arg == "-m" && i+1 < len(command) {
			return strings.TrimSpace(command[i+1])
		}
	}
	return ""
}

func (p Package) pythonCommand(py Python, goos string) ([]string, error) {
	python := strings.TrimSpace(py.Interpreter)
	if python == "" {
		if interpreter, ok := p.Manifest.Interpreters["python"]; ok {
			python = strings.TrimSpace(interpreter.Path)
			if python != "" && !filepath.IsAbs(python) {
				python = filepath.Join(p.Root, python)
			}
		}
	}
	if python == "" && py.Managed != nil {
		python = managedVenvPython(p.Root, goos)
	}
	if python == "" {
		return nil, errors.New("python interpreter is required")
	}
	command := append([]string(nil), py.Command...)
	for i, arg := range command {
		if arg == "{python}" {
			command[i] = python
		}
	}
	if len(command) != 0 && command[0] != python {
		command = append([]string{python}, command...)
	}
	return command, nil
}

func resolveCommand(root string, command []string) []string {
	out := append([]string(nil), command...)
	if len(out) != 0 && out[0] != "" && !filepath.IsAbs(out[0]) {
		out[0] = filepath.Join(root, out[0])
	}
	return out
}

type InstallOptions struct {
	Workspace                     string
	SourceDir                     string
	SourceArchive                 string
	SourceURL                     string
	SHA256                        string
	HostOS                        string
	HostArch                      string
	NoScripts                     bool
	Offline                       bool
	Replace                       bool
	NoCache                       bool
	CacheDir                      string
	PythonBuildStandaloneRelease  string
	PythonBuildStandaloneCacheDir string
	PythonBuildStandaloneArchive  string
	Client                        *http.Client
	Progress                      func(InstallProgress)
	Now                           time.Time
}

type InstallResult struct {
	Name    string
	Version string
	Source  string
}

type InstallProgressStage string

const (
	InstallProgressDownloadCacheHit InstallProgressStage = "download-cache-hit"
	InstallProgressDownloadStart    InstallProgressStage = "download-start"
	InstallProgressDownloadProgress InstallProgressStage = "download-progress"
	InstallProgressDownloadComplete InstallProgressStage = "download-complete"
	InstallProgressDownloadVerified InstallProgressStage = "download-verified"
	InstallProgressDownloadCached   InstallProgressStage = "download-cached"
	InstallProgressArchiveStart     InstallProgressStage = "archive-install-start"
	InstallProgressArchiveComplete  InstallProgressStage = "archive-install-complete"
	InstallProgressSetEntry         InstallProgressStage = "install-set-entry"
)

type InstallProgress struct {
	Stage   InstallProgressStage
	Source  string
	Archive string
	Name    string
	Version string
	SHA256  string
	Bytes   int64
	Total   int64
	Cached  bool
	Index   int
	Count   int
}

type UninstallOptions struct {
	Workspace string
	Name      string
	Version   string
	NoScripts bool
	Offline   bool
}

type UninstallResult struct {
	Name    string
	Version string
	Source  string
	Linked  bool
}

func InstallLink(opts InstallOptions) (InstallResult, error) {
	workspace, err := requiredAbsPath(opts.Workspace, "workspace is required")
	if err != nil {
		return InstallResult{}, err
	}
	source, err := requiredAbsPath(opts.SourceDir, "module package root is required")
	if err != nil {
		return InstallResult{}, err
	}
	pkg, err := LoadDir(source)
	if err != nil {
		return InstallResult{}, err
	}
	if _, err := pkg.SelectLaunch(opts.HostOS, opts.HostArch); err != nil {
		return InstallResult{}, err
	}
	if err := installPackage(pkg, workspace, source, "", true, opts); err != nil {
		return InstallResult{}, err
	}
	return InstallResult{Name: pkg.Manifest.Metadata.Name, Version: pkg.Manifest.Metadata.Version, Source: source}, nil
}

func InstallArchive(opts InstallOptions) (InstallResult, error) {
	workspace, err := requiredAbsPath(opts.Workspace, "workspace is required")
	if err != nil {
		return InstallResult{}, err
	}
	source := filepath.Clean(strings.TrimSpace(opts.SourceArchive))
	if !strings.EqualFold(filepath.Ext(source), ".tgz") {
		return InstallResult{}, errors.New("module package archive must use .tgz")
	}
	source, err = filepath.Abs(source)
	if err != nil {
		return InstallResult{}, err
	}
	sum, err := FileSHA256(source)
	if err != nil {
		return InstallResult{}, err
	}
	if expected := strings.TrimSpace(opts.SHA256); expected != "" && !strings.EqualFold(expected, sum) {
		return InstallResult{}, fmt.Errorf("sha256 mismatch for %s", source)
	}
	reportInstallProgress(opts, InstallProgress{
		Stage:   InstallProgressArchiveStart,
		Source:  source,
		Archive: source,
		SHA256:  sum,
	})
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		return InstallResult{}, err
	}
	temp, err := os.MkdirTemp(workspace, ".module-*")
	if err != nil {
		return InstallResult{}, err
	}
	defer os.RemoveAll(temp)
	if err := extractTGZ(source, temp); err != nil {
		return InstallResult{}, err
	}
	pkg, err := LoadDir(temp)
	if err != nil {
		return InstallResult{}, err
	}
	if _, err := pkg.SelectLaunch(opts.HostOS, opts.HostArch); err != nil {
		return InstallResult{}, err
	}
	dest := filepath.Join(workspace, "modules", pkg.Manifest.Metadata.Name, pkg.Manifest.Metadata.Version)
	lock, err := LoadLock(filepath.Join(workspace, "module-lock.yaml"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return InstallResult{}, err
	}
	if existing, ok := lock.find(pkg.Manifest.Metadata.Name, pkg.Manifest.Metadata.Version); ok && existing.SHA256 != "" && existing.SHA256 != sum && !opts.Replace {
		return InstallResult{}, fmt.Errorf("module %s@%s is already installed with a different sha256; use --replace", pkg.Manifest.Metadata.Name, pkg.Manifest.Metadata.Version)
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return InstallResult{}, err
	}
	var backup string
	var backupParent string
	if _, err := os.Stat(dest); err == nil {
		backupParent, err = os.MkdirTemp(filepath.Dir(dest), ".replace-*")
		if err != nil {
			return InstallResult{}, err
		}
		backup = filepath.Join(backupParent, filepath.Base(dest))
		if err := os.Rename(dest, backup); err != nil {
			_ = os.RemoveAll(backupParent)
			return InstallResult{}, err
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return InstallResult{}, err
	}
	if err := os.Rename(temp, dest); err != nil {
		restoreInstallBackup(dest, backup, backupParent)
		return InstallResult{}, err
	}
	pkg, err = LoadDir(dest)
	if err != nil {
		_ = os.RemoveAll(dest)
		restoreInstallBackup(dest, backup, backupParent)
		return InstallResult{}, err
	}
	if err := installPackage(pkg, workspace, dest, sum, false, opts); err != nil {
		_ = os.RemoveAll(dest)
		restoreInstallBackup(dest, backup, backupParent)
		return InstallResult{}, err
	}
	if backupParent != "" {
		_ = os.RemoveAll(backupParent)
	}
	reportInstallProgress(opts, InstallProgress{
		Stage:   InstallProgressArchiveComplete,
		Source:  source,
		Archive: source,
		Name:    pkg.Manifest.Metadata.Name,
		Version: pkg.Manifest.Metadata.Version,
		SHA256:  sum,
	})
	return InstallResult{Name: pkg.Manifest.Metadata.Name, Version: pkg.Manifest.Metadata.Version, Source: dest}, nil
}

func InstallURL(opts InstallOptions) (InstallResult, error) {
	source := strings.TrimSpace(opts.SourceURL)
	parsed, err := url.Parse(source)
	if err != nil {
		return InstallResult{}, err
	}
	if parsed.Scheme != "https" {
		return InstallResult{}, errors.New("module URL installs require https")
	}
	cacheDir, err := DownloadCacheDir(opts.CacheDir)
	if err != nil {
		return InstallResult{}, err
	}
	expected := strings.TrimSpace(opts.SHA256)
	if expected != "" && !opts.NoCache {
		cached := filepath.Join(cacheDir, strings.ToLower(expected)+".tgz")
		if _, err := os.Stat(cached); err == nil {
			reportInstallProgress(opts, InstallProgress{
				Stage:   InstallProgressDownloadCacheHit,
				Source:  source,
				Archive: cached,
				SHA256:  expected,
				Cached:  true,
			})
			opts.SourceArchive = cached
			return InstallArchive(opts)
		}
	}
	if opts.Offline {
		return InstallResult{}, errors.New("offline module URL install requires a cached --sha256 package")
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return InstallResult{}, err
	}
	temp, err := os.CreateTemp(cacheDir, "download-*.tgz")
	if err != nil {
		return InstallResult{}, err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	client := installHTTPClient(opts)
	resp, err := client.Get(source)
	if err != nil {
		_ = temp.Close()
		return InstallResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_ = temp.Close()
		return InstallResult{}, fmt.Errorf("download %s failed: %s", source, resp.Status)
	}
	total := resp.ContentLength
	reportInstallProgress(opts, InstallProgress{
		Stage:  InstallProgressDownloadStart,
		Source: source,
		Total:  total,
	})
	if _, err := copyWithInstallProgress(temp, resp.Body, opts, InstallProgress{
		Stage:  InstallProgressDownloadProgress,
		Source: source,
		Total:  total,
	}); err != nil {
		_ = temp.Close()
		return InstallResult{}, err
	}
	if err := temp.Close(); err != nil {
		return InstallResult{}, err
	}
	size, _ := fileSize(tempPath)
	reportInstallProgress(opts, InstallProgress{
		Stage:  InstallProgressDownloadComplete,
		Source: source,
		Bytes:  size,
		Total:  total,
	})
	sum, err := FileSHA256(tempPath)
	if err != nil {
		return InstallResult{}, err
	}
	if expected != "" && !strings.EqualFold(expected, sum) {
		return InstallResult{}, fmt.Errorf("sha256 mismatch for %s", source)
	}
	reportInstallProgress(opts, InstallProgress{
		Stage:  InstallProgressDownloadVerified,
		Source: source,
		Bytes:  size,
		Total:  total,
		SHA256: sum,
	})
	archive := tempPath
	if !opts.NoCache {
		cached := filepath.Join(cacheDir, sum+".tgz")
		if _, err := os.Stat(cached); errors.Is(err, os.ErrNotExist) {
			if err := os.Rename(tempPath, cached); err != nil {
				return InstallResult{}, err
			}
			archive = cached
			reportInstallProgress(opts, InstallProgress{
				Stage:   InstallProgressDownloadCached,
				Source:  source,
				Archive: cached,
				SHA256:  sum,
				Cached:  true,
			})
		} else if err != nil {
			return InstallResult{}, err
		} else {
			archive = cached
			reportInstallProgress(opts, InstallProgress{
				Stage:   InstallProgressDownloadCacheHit,
				Source:  source,
				Archive: cached,
				SHA256:  sum,
				Cached:  true,
			})
		}
	}
	opts.SourceArchive = archive
	opts.SHA256 = sum
	return InstallArchive(opts)
}

func restoreInstallBackup(dest, backup, backupParent string) {
	if backup == "" {
		return
	}
	_ = os.RemoveAll(dest)
	_ = os.Rename(backup, dest)
	if backupParent != "" {
		_ = os.RemoveAll(backupParent)
	}
}

func Uninstall(opts UninstallOptions) (UninstallResult, error) {
	workspace, err := requiredAbsPath(opts.Workspace, "workspace is required")
	if err != nil {
		return UninstallResult{}, err
	}
	name := strings.TrimSpace(opts.Name)
	version := strings.TrimSpace(opts.Version)
	if name == "" {
		return UninstallResult{}, errors.New("module name is required")
	}
	lockPath := filepath.Join(workspace, "module-lock.yaml")
	lock, err := LoadLock(lockPath)
	if err != nil {
		return UninstallResult{}, err
	}
	record, err := lock.selectRecord(name, version)
	if err != nil {
		return UninstallResult{}, err
	}
	if !opts.NoScripts {
		pkg, err := LoadDir(record.Source)
		if err != nil {
			return UninstallResult{}, err
		}
		env := scriptEnv(pkg.Root, workspace, opts.Offline)
		if err := runScript(pkg.Root, pkg.Manifest.Scripts.PreUninstall, env); err != nil {
			return UninstallResult{}, err
		}
		if err := runScript(pkg.Root, pkg.Manifest.Scripts.PostUninstall, env); err != nil {
			return UninstallResult{}, err
		}
	}
	if !record.Linked {
		if err := os.RemoveAll(record.Source); err != nil {
			return UninstallResult{}, err
		}
	}
	lock.remove(record.Name, record.Version)
	if err := WriteLock(lockPath, lock); err != nil {
		return UninstallResult{}, err
	}
	return UninstallResult{Name: record.Name, Version: record.Version, Source: record.Source, Linked: record.Linked}, nil
}

func requiredAbsPath(value, message string) (string, error) {
	path := filepath.Clean(strings.TrimSpace(value))
	if path == "." || path == "" {
		return "", errors.New(message)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func preparePackageRuntime(pkg Package, opts InstallOptions) error {
	launch, err := pkg.SelectLaunch(opts.HostOS, opts.HostArch)
	if err != nil {
		return err
	}
	if launch.Python == nil || launch.Python.Managed == nil {
		return nil
	}
	return ensureManagedPython(pkg, *launch.Python, opts)
}

func ensureManagedPython(pkg Package, py Python, opts InstallOptions) error {
	venvPython := managedVenvPython(pkg.Root, opts.HostOS)
	if _, err := os.Stat(venvPython); err == nil {
		return nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	basePython, err := ensurePBSInterpreter(py.Managed.Versions, opts)
	if err != nil {
		return err
	}
	venvDir := filepath.Dir(filepath.Dir(venvPython))
	if opts.HostOS == "windows" {
		venvDir = filepath.Dir(filepath.Dir(venvPython))
	}
	if err := os.RemoveAll(venvDir); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(venvDir), 0o755); err != nil {
		return err
	}
	cmd := exec.Command(basePython, "-m", "venv", venvDir)
	cmd.Dir = pkg.Root
	cmd.Env = os.Environ()
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("create managed python venv: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if py.Requirements != "" {
		if err := installPythonRequirements(pkg.Root, venvPython, py, opts.Offline); err != nil {
			return err
		}
	}
	return nil
}

func installPythonRequirements(root, python string, py Python, offline bool) error {
	requirements := py.Requirements
	if !filepath.IsAbs(requirements) {
		requirements = filepath.Join(root, requirements)
	}
	args := []string{"-m", "pip", "install"}
	wheelhouse := strings.TrimSpace(py.Wheelhouse)
	if wheelhouse != "" {
		if !filepath.IsAbs(wheelhouse) {
			wheelhouse = filepath.Join(root, wheelhouse)
		}
		args = append(args, "--find-links", wheelhouse)
	}
	if offline {
		args = append(args, "--no-index")
	}
	args = append(args, "-r", requirements)
	cmd := exec.Command(python, args...)
	cmd.Dir = root
	cmd.Env = os.Environ()
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("install managed python requirements: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func ensurePBSInterpreter(versions []string, opts InstallOptions) (string, error) {
	cacheRoot, err := pythonBuildStandaloneCacheDir(opts.PythonBuildStandaloneCacheDir)
	if err != nil {
		return "", err
	}
	if archive := strings.TrimSpace(opts.PythonBuildStandaloneArchive); archive != "" {
		sum, err := FileSHA256(archive)
		if err != nil {
			return "", err
		}
		root := filepath.Join(cacheRoot, "local", sum)
		return ensureExtractedPBS(archive, root, opts.HostOS)
	}
	release := strings.TrimSpace(opts.PythonBuildStandaloneRelease)
	if release == "" {
		release = DefaultPBSRelease
	}
	platform, err := pbsPlatform(opts.HostOS, opts.HostArch)
	if err != nil {
		return "", err
	}
	asset, err := selectPBSAsset(release, platform, versions, opts)
	if err != nil {
		return "", err
	}
	root := filepath.Join(cacheRoot, release, strings.TrimSuffix(strings.TrimSuffix(asset.Name, ".tar.gz"), ".tgz"))
	if python := pbsInterpreter(root, opts.HostOS); fileExists(python) {
		return python, nil
	}
	archivePath := filepath.Join(cacheRoot, "downloads", release, asset.Name)
	if !fileExists(archivePath) {
		if opts.Offline {
			return "", errors.New("managed python runtime is not cached and --offline was set")
		}
		if err := downloadFile(asset.URL, archivePath, opts.Client, opts); err != nil {
			return "", err
		}
	}
	return ensureExtractedPBS(archivePath, root, opts.HostOS)
}

func ensureExtractedPBS(archive, root, goos string) (string, error) {
	python := pbsInterpreter(root, goos)
	if fileExists(python) {
		return python, nil
	}
	if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
		return "", err
	}
	temp, err := os.MkdirTemp(filepath.Dir(root), ".pbs-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temp)
	if err := extractTGZ(archive, temp); err != nil {
		return "", err
	}
	if err := os.RemoveAll(root); err != nil {
		return "", err
	}
	if err := os.Rename(temp, root); err != nil {
		return "", err
	}
	python = pbsInterpreter(root, goos)
	if !fileExists(python) {
		return "", fmt.Errorf("python-build-standalone archive did not contain %s", filepath.ToSlash(strings.TrimPrefix(python, root+string(os.PathSeparator))))
	}
	return python, nil
}

func pythonBuildStandaloneCacheDir(configured string) (string, error) {
	if configured = strings.TrimSpace(configured); configured != "" {
		return configured, nil
	}
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "hovel", "python-build-standalone"), nil
}

func managedVenvPython(root, goos string) string {
	if goos == "windows" {
		return filepath.Join(root, ".hovel", "python", "Scripts", "python.exe")
	}
	return filepath.Join(root, ".hovel", "python", "bin", "python")
}

func pbsInterpreter(root, goos string) string {
	if goos == "windows" {
		return filepath.Join(root, "python", "python.exe")
	}
	return filepath.Join(root, "python", "bin", "python3")
}

func pbsPlatform(goos, goarch string) (string, error) {
	switch goos + "/" + goarch {
	case "linux/amd64":
		return "x86_64-unknown-linux-gnu", nil
	case "linux/arm64":
		return "aarch64-unknown-linux-gnu", nil
	case "darwin/amd64":
		return "x86_64-apple-darwin", nil
	case "darwin/arm64":
		return "aarch64-apple-darwin", nil
	case "windows/amd64":
		return "x86_64-pc-windows-msvc", nil
	case "windows/arm64":
		return "aarch64-pc-windows-msvc", nil
	default:
		return "", fmt.Errorf("managed python does not support host %s/%s", goos, goarch)
	}
}

type pbsAsset struct {
	Name string
	URL  string
}

type githubRelease struct {
	Assets []githubAsset `json:"assets"`
}

type githubAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
}

var pbsAssetPattern = regexp.MustCompile(`^cpython-([0-9]+\.[0-9]+\.[0-9]+)\+[^-]+-(.+)-install_only(_stripped)?\.tar\.gz$`)

func selectPBSAsset(release, platform string, versions []string, opts InstallOptions) (pbsAsset, error) {
	apiURL := "https://api.github.com/repos/astral-sh/python-build-standalone/releases/tags/" + release
	client := installHTTPClient(opts)
	if opts.Offline {
		return pbsAsset{}, errors.New("managed python asset metadata is not available offline")
	}
	resp, err := client.Get(apiURL)
	if err != nil {
		return pbsAsset{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return pbsAsset{}, fmt.Errorf("load python-build-standalone release %s failed: %s", release, resp.Status)
	}
	var releaseInfo githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&releaseInfo); err != nil {
		return pbsAsset{}, err
	}
	var best pbsAsset
	var bestVersion []int
	bestStripped := false
	for _, asset := range releaseInfo.Assets {
		match := pbsAssetPattern.FindStringSubmatch(asset.Name)
		if match == nil || match[2] != platform || !pythonVersionAllowed(match[1], versions) {
			continue
		}
		version := versionParts(match[1])
		stripped := match[3] != ""
		if best.Name == "" || compareVersionParts(version, bestVersion) > 0 || compareVersionParts(version, bestVersion) == 0 && stripped && !bestStripped {
			best = pbsAsset{Name: asset.Name, URL: asset.URL}
			bestVersion = version
			bestStripped = stripped
		}
	}
	if best.Name == "" {
		return pbsAsset{}, fmt.Errorf("no python-build-standalone asset for %s matching versions %s in release %s", platform, strings.Join(versions, ","), release)
	}
	return best, nil
}

func pythonVersionAllowed(version string, specs []string) bool {
	if len(specs) == 0 {
		return true
	}
	parts := versionParts(version)
	if len(parts) < 2 {
		return false
	}
	for _, spec := range specs {
		spec = strings.TrimSpace(spec)
		if spec == "" {
			continue
		}
		if left, right, ok := strings.Cut(spec, "-"); ok {
			if compareMajorMinor(parts, versionParts(left)) >= 0 && compareMajorMinor(parts, versionParts(right)) <= 0 {
				return true
			}
			continue
		}
		if compareMajorMinor(parts, versionParts(spec)) == 0 {
			return true
		}
	}
	return false
}

func versionParts(version string) []int {
	raw := strings.Split(version, ".")
	parts := make([]int, 0, len(raw))
	for _, part := range raw {
		value, err := strconv.Atoi(part)
		if err != nil {
			break
		}
		parts = append(parts, value)
	}
	return parts
}

func compareMajorMinor(left, right []int) int {
	if len(left) < 2 || len(right) < 2 {
		return -1
	}
	return compareVersionParts(left[:2], right[:2])
}

func compareVersionParts(left, right []int) int {
	for i := 0; i < len(left) || i < len(right); i++ {
		var l, r int
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		if l != r {
			return l - r
		}
	}
	return 0
}

func downloadFile(source, dest string, client *http.Client, opts InstallOptions) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	if client == nil {
		client = defaultInstallHTTPClient()
	}
	resp, err := client.Get(source)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("download %s failed: %s", source, resp.Status)
	}
	total := resp.ContentLength
	reportInstallProgress(opts, InstallProgress{
		Stage:  InstallProgressDownloadStart,
		Source: source,
		Total:  total,
	})
	temp, err := os.CreateTemp(filepath.Dir(dest), "download-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := copyWithInstallProgress(temp, resp.Body, opts, InstallProgress{
		Stage:  InstallProgressDownloadProgress,
		Source: source,
		Total:  total,
	}); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	size, _ := fileSize(tempPath)
	reportInstallProgress(opts, InstallProgress{
		Stage:  InstallProgressDownloadComplete,
		Source: source,
		Bytes:  size,
		Total:  total,
	})
	return os.Rename(tempPath, dest)
}

func installHTTPClient(opts InstallOptions) *http.Client {
	if opts.Client != nil {
		return opts.Client
	}
	return defaultInstallHTTPClient()
}

func defaultInstallHTTPClient() *http.Client {
	client := *http.DefaultClient
	if client.Timeout == 0 {
		client.Timeout = defaultHTTPTimeout
	}
	return &client
}

func reportInstallProgress(opts InstallOptions, event InstallProgress) {
	if opts.Progress != nil {
		opts.Progress(event)
	}
}

func copyWithInstallProgress(dst io.Writer, src io.Reader, opts InstallOptions, event InstallProgress) (int64, error) {
	var copied int64
	buf := make([]byte, 32*1024)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			written, writeErr := dst.Write(buf[:n])
			copied += int64(written)
			event.Bytes = copied
			reportInstallProgress(opts, event)
			if writeErr != nil {
				return copied, writeErr
			}
			if written != n {
				return copied, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return copied, nil
		}
		if readErr != nil {
			return copied, readErr
		}
	}
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func installPackage(pkg Package, workspace, source, sha string, linked bool, opts InstallOptions) error {
	if err := preparePackageRuntime(pkg, opts); err != nil {
		return err
	}
	if _, err := pkg.LaunchEntry(opts.HostOS, opts.HostArch); err != nil {
		return err
	}
	env := scriptEnv(pkg.Root, workspace, opts.Offline)
	if !opts.NoScripts {
		if err := runScript(pkg.Root, pkg.Manifest.Scripts.PreInstall, env); err != nil {
			return err
		}
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}
	lockPath := filepath.Join(workspace, "module-lock.yaml")
	lock, err := LoadLock(lockPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if existing, ok := lock.find(pkg.Manifest.Metadata.Name, pkg.Manifest.Metadata.Version); ok && existing.SHA256 != "" && existing.SHA256 != sha && !opts.Replace {
		return fmt.Errorf("module %s@%s is already installed with a different sha256; use --replace", pkg.Manifest.Metadata.Name, pkg.Manifest.Metadata.Version)
	}
	if !opts.NoScripts {
		if err := runScript(pkg.Root, pkg.Manifest.Scripts.PostInstall, env); err != nil {
			return err
		}
	}
	lock.APIVersion = APIVersion
	lock.Kind = LockKind
	lock.upsert(LockRecord{
		Name:        pkg.Manifest.Metadata.Name,
		Version:     pkg.Manifest.Metadata.Version,
		SHA256:      sha,
		Source:      source,
		Linked:      linked,
		InstalledAt: now.UTC().Format(time.RFC3339),
	})
	if err := WriteLock(lockPath, lock); err != nil {
		return err
	}
	return nil
}

func DownloadCacheDir(configured string) (string, error) {
	if configured = strings.TrimSpace(configured); configured != "" {
		return configured, nil
	}
	root, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "hovel", "modules", "downloads"), nil
}

func scriptEnv(moduleRoot, installRoot string, offline bool) []string {
	offlineValue := "0"
	if offline {
		offlineValue = "1"
	}
	return append(os.Environ(),
		"HOVEL_MODULE_ROOT="+moduleRoot,
		"HOVEL_INSTALL_ROOT="+installRoot,
		"HOVEL_WORKSPACE="+installRoot,
		"HOVEL_OFFLINE="+offlineValue,
	)
}

func runScript(root string, script *Script, env []string) error {
	if script == nil || len(script.Command) == 0 {
		return nil
	}
	cmd := exec.Command(script.Command[0], script.Command[1:]...)
	cmd.Dir = root
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("script %s failed: %w: %s", script.Command[0], err, strings.TrimSpace(string(output)))
	}
	return nil
}

func FileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func extractTGZ(path, root string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		target, err := safeArchivePath(root, header.Name)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode)&0o777)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(out, tr)
			closeErr := out.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
		case tar.TypeSymlink:
			linkTarget, err := safeSymlinkTarget(root, target, header.Linkname)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			if err := os.Symlink(linkTarget, target); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported archive entry %s", header.Name)
		}
	}
}

func safeArchivePath(root, name string) (string, error) {
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("archive entry escapes package root: %s", name)
	}
	clean := filepath.Clean(name)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive entry escapes package root: %s", name)
	}
	target := filepath.Join(root, clean)
	rel, err := filepath.Rel(root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive entry escapes package root: %s", name)
	}
	return target, nil
}

func safeSymlinkTarget(root, linkPath, target string) (string, error) {
	if filepath.IsAbs(target) {
		return "", fmt.Errorf("archive symlink escapes package root: %s", target)
	}
	resolved := filepath.Join(filepath.Dir(linkPath), target)
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("archive symlink escapes package root: %s", target)
	}
	return target, nil
}

const LockKind = "ModuleLock"

type Lock struct {
	APIVersion string       `yaml:"apiVersion"`
	Kind       string       `yaml:"kind"`
	Modules    []LockRecord `yaml:"modules"`
}

type LockRecord struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	SHA256      string `yaml:"sha256,omitempty"`
	Source      string `yaml:"source"`
	Linked      bool   `yaml:"linked,omitempty"`
	InstalledAt string `yaml:"installedAt"`
}

func LoadLock(path string) (Lock, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Lock{}, err
	}
	var lock Lock
	if err := yaml.Unmarshal(body, &lock); err != nil {
		return Lock{}, err
	}
	return lock, nil
}

func WriteLock(path string, lock Lock) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := yaml.Marshal(lock)
	if err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o644)
}

func (l *Lock) upsert(record LockRecord) {
	for i, existing := range l.Modules {
		if existing.Name == record.Name && existing.Version == record.Version {
			l.Modules[i] = record
			return
		}
	}
	l.Modules = append(l.Modules, record)
}

func (l Lock) find(name, version string) (LockRecord, bool) {
	for _, record := range l.Modules {
		if record.Name == name && record.Version == version {
			return record, true
		}
	}
	return LockRecord{}, false
}

func (l Lock) selectRecord(name, version string) (LockRecord, error) {
	if version != "" {
		if record, ok := l.find(name, version); ok {
			return record, nil
		}
		return LockRecord{}, fmt.Errorf("module %s@%s is not installed", name, version)
	}
	var matches []LockRecord
	for _, record := range l.Modules {
		if record.Name == name {
			matches = append(matches, record)
		}
	}
	switch len(matches) {
	case 0:
		return LockRecord{}, fmt.Errorf("module %s is not installed", name)
	case 1:
		return matches[0], nil
	default:
		return LockRecord{}, fmt.Errorf("module %s has multiple installed versions; specify name@version", name)
	}
}

func (l *Lock) remove(name, version string) {
	out := l.Modules[:0]
	for _, record := range l.Modules {
		if record.Name == name && record.Version == version {
			continue
		}
		out = append(out, record)
	}
	l.Modules = out
}
