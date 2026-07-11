package commandmode

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	goRuntime "runtime"
	"strings"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/app/commands"
	"github.com/Vibe-Pwners/hovel/internal/app/modulecatalog"
	"github.com/Vibe-Pwners/hovel/internal/app/modulepackage"
	"github.com/Vibe-Pwners/hovel/internal/moduleruntime/pythonrpc"
)

type moduleChecker struct{}

type moduleInspector struct {
	runner pythonrpc.Runner
}

func (i moduleInspector) InspectPackage(ctx context.Context, pkg modulepackage.Package) (modulecatalog.Module, error) {
	entry, err := pkg.LaunchEntry(goRuntime.GOOS, goRuntime.GOARCH)
	if err != nil {
		return modulecatalog.Module{}, err
	}
	return i.runner.InspectEntry(ctx, pythonrpc.ModuleEntry{
		Runtime:    entry.Runtime,
		ProjectDir: entry.ProjectDir,
		Module:     entry.Module,
		Command:    append([]string(nil), entry.Command...),
	})
}

func (moduleChecker) CheckModule(ctx context.Context, request commands.ModuleCheckRequest) (commands.ModuleCheckReport, error) {
	if err := ctx.Err(); err != nil {
		return commands.ModuleCheckReport{}, err
	}
	reference := strings.TrimSpace(request.Reference)
	report := commands.ModuleCheckReport{Subject: reference, Status: commands.ModuleCheckPass}
	if reference == "" {
		addModuleCheck(&report, commands.ModuleCheckFail, "source", "module reference is required")
		return report, nil
	}
	if info, err := os.Stat(reference); err == nil {
		if info.IsDir() {
			return checkModulePackageDir(ctx, reference, report)
		}
		if strings.EqualFold(filepath.Ext(reference), ".tgz") {
			return checkModulePackageArchive(reference, report), nil
		}
		addModuleCheck(&report, commands.ModuleCheckFail, "source", "expected a module package directory, .tgz package, or module reference")
		return report, nil
	} else if looksLikeModulePath(reference) {
		addModuleCheck(&report, commands.ModuleCheckFail, "source", err.Error())
		return report, nil
	}
	return checkModuleReference(ctx, request, report), nil
}

func checkModuleReference(ctx context.Context, request commands.ModuleCheckRequest, report commands.ModuleCheckReport) commands.ModuleCheckReport {
	runner := pythonrpc.Runner{
		WorkspacePath: strings.TrimSpace(request.Workspace),
		HovelConfig:   strings.TrimSpace(request.Config),
		Timeout:       10 * time.Second,
	}
	module, err := runner.Inspect(ctx, report.Subject)
	if err != nil {
		addModuleCheck(&report, commands.ModuleCheckFail, "rpc discovery", err.Error())
		return report
	}
	report.Module = module.ID
	addModuleCheck(&report, commands.ModuleCheckPass, "rpc discovery", "handshake, schema, optional mesh/step discovery, and shutdown completed")
	addModuleContractChecks(&report, module)
	return report
}

func checkModulePackageDir(ctx context.Context, root string, report commands.ModuleCheckReport) (commands.ModuleCheckReport, error) {
	pkg, err := modulepackage.LoadDir(root)
	if err != nil {
		addModuleCheck(&report, commands.ModuleCheckFail, "manifest", err.Error())
		return report, nil
	}
	report.Module = modulecatalog.CanonicalID(pkg.Manifest.Metadata.Name, pkg.Manifest.Metadata.Version)
	addModuleCheck(&report, commands.ModuleCheckPass, "manifest", "hovel-module.yaml is valid")
	launch, err := pkg.SelectLaunch(goRuntime.GOOS, goRuntime.GOARCH)
	if err != nil {
		addModuleCheck(&report, commands.ModuleCheckFail, "host launch", err.Error())
		return report, nil
	}
	addModuleCheck(&report, commands.ModuleCheckPass, "host launch", fmt.Sprintf("selected %s/%s launcher", goRuntime.GOOS, goRuntime.GOARCH))
	entry, err := pkg.LaunchEntry(goRuntime.GOOS, goRuntime.GOARCH)
	if err != nil {
		addModuleCheck(&report, commands.ModuleCheckFail, "host launch", err.Error())
		return report, nil
	}
	rpcEntry := pythonrpc.ModuleEntry{
		ID:         report.Module,
		Runtime:    entry.Runtime,
		ProjectDir: entry.ProjectDir,
		Module:     entry.Module,
		Command:    append([]string(nil), entry.Command...),
	}
	if err := commandAvailable(rpcEntry.Command); err != nil {
		if launch.Python != nil && launch.Python.Managed != nil {
			addModuleCheck(&report, commands.ModuleCheckWarn, "rpc discovery", "managed Python is not installed; install or link the module before runtime discovery")
			return report, nil
		}
		addModuleCheck(&report, commands.ModuleCheckFail, "launch command", err.Error())
		return report, nil
	}
	addModuleCheck(&report, commands.ModuleCheckPass, "launch command", "selected launcher is runnable")
	module, err := (pythonrpc.Runner{Timeout: 10 * time.Second}).InspectEntry(ctx, rpcEntry)
	if err != nil {
		addModuleCheck(&report, commands.ModuleCheckFail, "rpc discovery", err.Error())
		return report, nil
	}
	report.Module = module.ID
	addModuleCheck(&report, commands.ModuleCheckPass, "rpc discovery", "handshake, schema, optional mesh/step discovery, and shutdown completed")
	addModuleContractChecks(&report, module)
	return report, nil
}

func checkModulePackageArchive(path string, report commands.ModuleCheckReport) commands.ModuleCheckReport {
	manifest, err := modulepackage.LoadManifestArchive(path)
	if err != nil {
		addModuleCheck(&report, commands.ModuleCheckFail, "manifest", err.Error())
		return report
	}
	report.Module = modulecatalog.CanonicalID(manifest.Metadata.Name, manifest.Metadata.Version)
	addModuleCheck(&report, commands.ModuleCheckPass, "manifest", "hovel-module.yaml is valid")
	pkg := modulepackage.Package{Manifest: manifest}
	if _, err := pkg.SelectLaunch(goRuntime.GOOS, goRuntime.GOARCH); err != nil {
		addModuleCheck(&report, commands.ModuleCheckFail, "host launch", err.Error())
		return report
	}
	addModuleCheck(&report, commands.ModuleCheckPass, "host launch", fmt.Sprintf("selected %s/%s launcher", goRuntime.GOOS, goRuntime.GOARCH))
	addModuleCheck(&report, commands.ModuleCheckWarn, "rpc discovery", "archive checks do not extract packages or run module code")
	return report
}

func addModuleCheck(report *commands.ModuleCheckReport, status commands.ModuleCheckStatus, name, message string) {
	report.Checks = append(report.Checks, commands.ModuleCheckItem{
		Name:    strings.TrimSpace(name),
		Status:  status,
		Message: strings.TrimSpace(message),
	})
	switch status {
	case commands.ModuleCheckFail:
		report.Status = commands.ModuleCheckFail
	case commands.ModuleCheckWarn:
		if report.Status != commands.ModuleCheckFail {
			report.Status = commands.ModuleCheckWarn
		}
	case commands.ModuleCheckPass:
		if report.Status == "" {
			report.Status = commands.ModuleCheckPass
		}
	}
}

func addModuleContractChecks(report *commands.ModuleCheckReport, module modulecatalog.Module) {
	addModuleCheck(report, commands.ModuleCheckPass, "runtime", module.RuntimeKind)
	metadataStatus := commands.ModuleCheckPass
	metadataMessage := fmt.Sprintf("%s %s %s", module.ID, module.Type, module.Version)
	if strings.TrimSpace(module.Summary) == "" {
		metadataStatus = commands.ModuleCheckWarn
		metadataMessage += "; metadata.summary is recommended"
	}
	addModuleCheck(report, metadataStatus, "metadata", metadataMessage)
	addModuleCheck(report, commands.ModuleCheckPass, "config schema", fmt.Sprintf("%d chain requirements, %d target requirements", len(module.ChainConfig), len(module.TargetConfig)))
	addModuleCheck(report, commands.ModuleCheckPass, "step contracts", fmt.Sprintf("%d provider steps", len(module.StepContracts.Steps)))
}

func looksLikeModulePath(reference string) bool {
	return filepath.IsAbs(reference) ||
		reference == "." ||
		strings.HasPrefix(reference, "."+string(os.PathSeparator)) ||
		strings.Contains(reference, "/") ||
		strings.Contains(reference, "\\") ||
		strings.EqualFold(filepath.Ext(reference), ".tgz")
}

func commandAvailable(command []string) error {
	if len(command) == 0 {
		return errors.New("launch command is required")
	}
	program := strings.TrimSpace(command[0])
	if program == "" {
		return errors.New("launch command is required")
	}
	if filepath.IsAbs(program) || strings.Contains(program, "/") || strings.Contains(program, "\\") {
		info, err := os.Stat(program)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("%s is a directory", program)
		}
		if goRuntime.GOOS != "windows" && info.Mode()&0o111 == 0 {
			return fmt.Errorf("%s is not executable", program)
		}
		return nil
	}
	if _, err := exec.LookPath(program); err != nil {
		return err
	}
	return nil
}
