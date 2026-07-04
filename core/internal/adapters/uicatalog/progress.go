package uicatalog

import (
	"context"
	"io"
	"time"

	"github.com/Vibe-Pwners/hovel/internal/adapters/progressview"
	"github.com/Vibe-Pwners/hovel/internal/app/modulepackage"
)

func downloadProgressDemo() Demo {
	return Demo{
		Name:     "download-progress",
		Summary:  "module download, verification, cache, and install progress",
		Animated: true,
		Render: func(ctx context.Context, opts Options, out io.Writer) error {
			return renderProgress(ctx, opts, out, "download")
		},
	}
}

func uploadProgressDemo() Demo {
	return Demo{
		Name:     "upload-progress",
		Summary:  "artifact upload progress using the shared terminal progress style",
		Animated: true,
		Render: func(ctx context.Context, opts Options, out io.Writer) error {
			return renderProgress(ctx, opts, out, "upload")
		},
	}
}

func renderProgress(ctx context.Context, opts Options, out io.Writer, mode string) error {
	if mode == "upload" {
		return renderUploadProgress(ctx, opts, out)
	}
	renderer := progressview.NewInstallRenderer(out, opts.Width, opts.Color)
	source := "https://modules.example.test/releases/mock-exploit-session.tgz"
	total := int64(8 * 1024 * 1024)
	renderer.Handle(modulepackage.InstallProgress{
		Stage:  modulepackage.InstallProgressDownloadStart,
		Source: source,
		Total:  total,
	})
	frames := opts.Frames
	if !opts.Animate {
		frames = 1
	}
	for i := 1; i <= frames; i++ {
		if err := wait(ctx, opts.Delay); err != nil {
			return err
		}
		bytes := total * int64(i) / int64(frames)
		renderer.Handle(modulepackage.InstallProgress{
			Stage:  modulepackage.InstallProgressDownloadProgress,
			Source: source,
			Bytes:  bytes,
			Total:  total,
		})
	}
	renderer.Handle(modulepackage.InstallProgress{
		Stage:  modulepackage.InstallProgressDownloadComplete,
		Source: source,
		Bytes:  total,
		Total:  total,
	})
	if mode == "download" {
		renderer.Handle(modulepackage.InstallProgress{
			Stage:  modulepackage.InstallProgressDownloadVerified,
			SHA256: "3a6eb0790f39ac87c94f3856b2dd2c5d110e6811602261a9a923d3bb23adc8b7",
		})
		renderer.Handle(modulepackage.InstallProgress{
			Stage:   modulepackage.InstallProgressArchiveComplete,
			Name:    "mock-exploit-session",
			Version: "v0.0.0-example",
		})
	}
	return nil
}

func renderUploadProgress(ctx context.Context, opts Options, out io.Writer) error {
	renderer := progressview.NewTransferRenderer(out, progressview.TransferOptions{
		Label:     "upload",
		DoneLabel: "uploaded",
		Width:     opts.Width,
		Color:     opts.Color,
	})
	source := "artifacts/mock-survey-report.json"
	total := int64(3 * 1024 * 1024)
	renderer.Start(source, total)
	frames := opts.Frames
	if !opts.Animate {
		frames = 1
	}
	for i := 1; i <= frames; i++ {
		if err := wait(ctx, opts.Delay); err != nil {
			return err
		}
		bytes := total * int64(i) / int64(frames)
		renderer.Progress(source, bytes, total)
	}
	renderer.Complete(source, total, total)
	return nil
}

func wait(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			return nil
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
