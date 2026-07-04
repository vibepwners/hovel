package hovelconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	APIVersion = "hovel.dev/v1alpha1"
	Kind       = "HovelConfig"
)

type Config struct {
	APIVersion string        `yaml:"apiVersion"`
	Kind       string        `yaml:"kind"`
	Workspace  string        `yaml:"workspace,omitempty"`
	Modules    Modules       `yaml:"modules,omitempty"`
	Policy     Policy        `yaml:"policy,omitempty"`
	Cache      Cache         `yaml:"cache,omitempty"`
	Runtime    Runtime       `yaml:"runtime,omitempty"`
	Logging    LoggingConfig `yaml:"logging,omitempty"`
}

type Modules struct {
	SearchPaths []string `yaml:"searchPaths,omitempty"`
	Indexes     []string `yaml:"indexes,omitempty"`
}

type Cache struct {
	Enabled bool `yaml:"enabled"`
}

type Policy struct {
	LaunchKey LaunchKeyPolicy `yaml:"launchKey,omitempty"`
}

type LaunchKeyPolicy struct {
	Mode             string `yaml:"mode,omitempty"`
	Quorum           int    `yaml:"quorum,omitempty"`
	HeartbeatTimeout string `yaml:"heartbeatTimeout,omitempty"`
}

type Runtime struct {
	Python PythonRuntime `yaml:"python,omitempty"`
}

type PythonRuntime struct {
	PythonBuildStandalone PythonBuildStandalone `yaml:"pythonBuildStandalone,omitempty"`
}

type PythonBuildStandalone struct {
	Release string `yaml:"release,omitempty"`
}

type LoggingConfig struct {
	Level string `yaml:"level,omitempty"`
}

type Options struct {
	Workspace    string
	GlobalPath   string
	ExplicitPath string
}

type rawConfig struct {
	APIVersion *string     `yaml:"apiVersion"`
	Kind       *string     `yaml:"kind"`
	Workspace  *string     `yaml:"workspace"`
	Modules    *rawModules `yaml:"modules"`
	Policy     *rawPolicy  `yaml:"policy"`
	Cache      *rawCache   `yaml:"cache"`
	Runtime    *rawRuntime `yaml:"runtime"`
	Logging    *rawLogging `yaml:"logging"`
}

type rawModules struct {
	SearchPaths *[]string `yaml:"searchPaths"`
	Indexes     *[]string `yaml:"indexes"`
}

type rawCache struct {
	Enabled *bool `yaml:"enabled"`
}

type rawPolicy struct {
	LaunchKey *rawLaunchKeyPolicy `yaml:"launchKey"`
}

type rawLaunchKeyPolicy struct {
	Mode             *string `yaml:"mode"`
	Quorum           *int    `yaml:"quorum"`
	HeartbeatTimeout *string `yaml:"heartbeatTimeout"`
}

type rawRuntime struct {
	Python *rawPythonRuntime `yaml:"python"`
}

type rawPythonRuntime struct {
	PythonBuildStandalone *rawPythonBuildStandalone `yaml:"pythonBuildStandalone"`
}

type rawPythonBuildStandalone struct {
	Release *string `yaml:"release"`
}

type rawLogging struct {
	Level *string `yaml:"level"`
}

func Defaults() Config {
	return Config{
		APIVersion: APIVersion,
		Kind:       Kind,
		Policy:     Policy{LaunchKey: LaunchKeyPolicy{Mode: "anyone"}},
		Cache:      Cache{Enabled: true},
	}
}

func Load(opts Options) (Config, []string, error) {
	config := Defaults()
	var sources []string
	for _, path := range configPaths(opts) {
		if strings.TrimSpace(path) == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return Config{}, nil, err
		}
		raw, err := readRaw(path)
		if err != nil {
			return Config{}, nil, err
		}
		if err := validateIdentity(raw, path); err != nil {
			return Config{}, nil, err
		}
		mergeRaw(&config, raw)
		sources = append(sources, path)
	}
	return config, sources, nil
}

func configPaths(opts Options) []string {
	var paths []string
	if opts.GlobalPath != "" {
		paths = append(paths, opts.GlobalPath)
	} else {
		paths = append(paths, defaultGlobalPaths()...)
	}
	if opts.Workspace != "" {
		paths = append(paths, filepath.Join(opts.Workspace, "config.yaml"))
	}
	if opts.ExplicitPath != "" {
		paths = append(paths, opts.ExplicitPath)
	}
	return paths
}

func defaultGlobalPaths() []string {
	if configHome := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); configHome != "" {
		return []string{filepath.Join(configHome, "hovel", "config.yaml")}
	}
	home := strings.TrimSpace(os.Getenv("HOME"))
	if home == "" {
		return nil
	}
	return []string{filepath.Join(home, ".config", "hovel", "config.yaml")}
}

func readRaw(path string) (rawConfig, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return rawConfig{}, err
	}
	var raw rawConfig
	if err := yaml.Unmarshal(body, &raw); err != nil {
		return rawConfig{}, err
	}
	return raw, nil
}

func validateIdentity(raw rawConfig, path string) error {
	if raw.APIVersion != nil && strings.TrimSpace(*raw.APIVersion) != APIVersion {
		return errors.New(path + ": unsupported apiVersion")
	}
	if raw.Kind != nil && strings.TrimSpace(*raw.Kind) != Kind {
		return errors.New(path + ": unsupported kind")
	}
	return nil
}

func mergeRaw(config *Config, raw rawConfig) {
	if raw.APIVersion != nil {
		config.APIVersion = strings.TrimSpace(*raw.APIVersion)
	}
	if raw.Kind != nil {
		config.Kind = strings.TrimSpace(*raw.Kind)
	}
	if raw.Workspace != nil {
		config.Workspace = strings.TrimSpace(*raw.Workspace)
	}
	if raw.Modules != nil {
		if raw.Modules.SearchPaths != nil {
			config.Modules.SearchPaths = cleanStrings(*raw.Modules.SearchPaths)
		}
		if raw.Modules.Indexes != nil {
			config.Modules.Indexes = cleanStrings(*raw.Modules.Indexes)
		}
	}
	if raw.Policy != nil && raw.Policy.LaunchKey != nil {
		policy := raw.Policy.LaunchKey
		if policy.Mode != nil {
			config.Policy.LaunchKey.Mode = strings.TrimSpace(*policy.Mode)
		}
		if policy.Quorum != nil {
			config.Policy.LaunchKey.Quorum = *policy.Quorum
		}
		if policy.HeartbeatTimeout != nil {
			config.Policy.LaunchKey.HeartbeatTimeout = strings.TrimSpace(*policy.HeartbeatTimeout)
		}
	}
	if raw.Cache != nil && raw.Cache.Enabled != nil {
		config.Cache.Enabled = *raw.Cache.Enabled
	}
	if raw.Runtime != nil && raw.Runtime.Python != nil && raw.Runtime.Python.PythonBuildStandalone != nil {
		pbs := raw.Runtime.Python.PythonBuildStandalone
		if pbs.Release != nil {
			config.Runtime.Python.PythonBuildStandalone.Release = strings.TrimSpace(*pbs.Release)
		}
	}
	if raw.Logging != nil && raw.Logging.Level != nil {
		config.Logging.Level = strings.TrimSpace(*raw.Logging.Level)
	}
}

func cleanStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
