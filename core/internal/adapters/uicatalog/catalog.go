package uicatalog

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vibepwners/hovel/internal/adapters/clistyle"
)

type Options struct {
	Width    int
	Color    bool
	Frames   int
	Delay    time.Duration
	DelaySet bool
	Animate  bool
}

type Demo struct {
	Name     string
	Summary  string
	Animated bool
	Render   func(context.Context, Options, io.Writer) error
}

func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	registry := demos()
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		writeText(stdout, usage(registry))
		return 0
	}

	switch args[0] {
	case "list":
		opts, ok := parseOptions(args[1:], stderr)
		if !ok {
			return 2
		}
		writeText(stdout, renderList(registry, opts))
		return 0
	case "show":
		if len(args) < 2 {
			writeLine(stderr, "demo name is required")
			return 2
		}
		name := args[1]
		opts, ok := parseOptions(args[2:], stderr)
		if !ok {
			return 2
		}
		if name == "all" {
			return runAll(ctx, registry, opts, stdout, stderr)
		}
		demo, ok := registry[name]
		if !ok {
			writeLine(stderr, fmt.Sprintf("unknown demo %q", name))
			return 2
		}
		if err := demo.Render(ctx, opts, colorWriter{out: stdout, color: opts.Color}); err != nil {
			writeLine(stderr, err)
			return 1
		}
		return 0
	default:
		writeLine(stderr, fmt.Sprintf("unknown command %q", args[0]))
		return 2
	}
}

func parseOptions(args []string, stderr io.Writer) (Options, bool) {
	opts := Options{
		Width:   clistyle.DefaultWidth,
		Color:   true,
		Frames:  24,
		Delay:   40 * time.Millisecond,
		Animate: true,
	}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--width":
			i++
			if i >= len(args) {
				writeLine(stderr, "--width requires a value")
				return Options{}, false
			}
			width, err := strconv.Atoi(args[i])
			if err != nil || width <= 0 {
				writeLine(stderr, "--width must be a positive integer")
				return Options{}, false
			}
			opts.Width = width
		case "--no-color":
			opts.Color = false
		case "--frames":
			i++
			if i >= len(args) {
				writeLine(stderr, "--frames requires a value")
				return Options{}, false
			}
			frames, err := strconv.Atoi(args[i])
			if err != nil || frames <= 0 {
				writeLine(stderr, "--frames must be a positive integer")
				return Options{}, false
			}
			opts.Frames = frames
		case "--delay":
			i++
			if i >= len(args) {
				writeLine(stderr, "--delay requires a value")
				return Options{}, false
			}
			delay, err := time.ParseDuration(args[i])
			if err != nil || delay < 0 {
				writeLine(stderr, "--delay must be a non-negative duration")
				return Options{}, false
			}
			opts.Delay = delay
			opts.DelaySet = true
		case "--static":
			opts.Animate = false
		case "--animate":
			opts.Animate = true
		default:
			writeLine(stderr, fmt.Sprintf("unknown option %q", args[i]))
			return Options{}, false
		}
	}
	return opts, true
}

func runAll(ctx context.Context, registry map[string]Demo, opts Options, stdout, stderr io.Writer) int {
	names := demoNames(registry)
	writer := colorWriter{out: stdout, color: opts.Color}
	for i, name := range names {
		demo := registry[name]
		if i > 0 {
			writeLine(stdout)
		}
		writeLine(writer, "== "+demo.Name+" ==")
		if err := demo.Render(ctx, opts, writer); err != nil {
			writeLine(stderr, err)
			return 1
		}
	}
	return 0
}

func usage(registry map[string]Demo) string {
	return strings.TrimSpace(`Usage:
  hovel-ui-catalog list [--no-color]
  hovel-ui-catalog show <demo|all> [--width 96] [--frames 24] [--delay 40ms] [--no-color]

Animated transfer demos default to --delay 40ms. The logs demo defaults to --delay 500ms so entries are readable.

Demos:
`+"\n"+renderList(registry, Options{Width: clistyle.DefaultWidth, Color: false})) + "\n"
}

func renderList(registry map[string]Demo, opts Options) string {
	styles := clistyle.Default()
	if !opts.Color {
		styles = clistyle.Styles{}
	}
	rows := make([][]string, 0, len(registry))
	for _, name := range demoNames(registry) {
		demo := registry[name]
		mode := "static"
		if demo.Animated {
			mode = "animated"
		}
		rows = append(rows, []string{name, mode, demo.Summary})
	}
	return styles.Table([]string{"DEMO", "MODE", "SUMMARY"}, rows, opts.Width)
}

func demoNames(registry map[string]Demo) []string {
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func demos() map[string]Demo {
	items := []Demo{
		logsDemo(),
		downloadProgressDemo(),
		uploadProgressDemo(),
		moduleCardDemo(),
		commandTableDemo(),
		statusPanelDemo(),
	}
	registry := make(map[string]Demo, len(items))
	for _, item := range items {
		registry[item.Name] = item
	}
	return registry
}

type colorWriter struct {
	out   io.Writer
	color bool
}

func (w colorWriter) Write(p []byte) (int, error) {
	if w.color {
		return w.out.Write(p)
	}
	stripped := stripANSI(p)
	if _, err := w.out.Write(stripped); err != nil {
		return 0, err
	}
	return len(p), nil
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)

func stripANSI(value []byte) []byte {
	return []byte(ansiPattern.ReplaceAllString(string(value), ""))
}
