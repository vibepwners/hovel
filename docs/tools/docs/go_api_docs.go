package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/doc"
	"go/format"
	"go/parser"
	"go/token"
	"html"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type packageSpec struct {
	title      string
	importPath string
	sourceDir  string
	outputPath string
}

type packageFlags []packageSpec

func (values *packageFlags) String() string { return fmt.Sprint(*values) }

func (values *packageFlags) Set(raw string) error {
	parts := strings.Split(raw, "|")
	if len(parts) != 4 {
		return fmt.Errorf("package must be TITLE|IMPORT_PATH|SOURCE_DIR|OUTPUT_PATH: %q", raw)
	}
	*values = append(*values, packageSpec{
		title:      parts[0],
		importPath: parts[1],
		sourceDir:  parts[2],
		outputPath: parts[3],
	})
	return nil
}

func main() {
	output := flag.String("output", "", "directory receiving generated Go API documentation")
	var packages packageFlags
	flag.Var(&packages, "package", "TITLE|IMPORT_PATH|SOURCE_DIR|OUTPUT_PATH")
	flag.Parse()
	if *output == "" || len(packages) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	for _, spec := range packages {
		if err := renderPackage(*output, spec); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func renderPackage(outputRoot string, spec packageSpec) error {
	fset := token.NewFileSet()
	buildContext := build.Default
	buildContext.GOOS = "linux"
	buildContext.GOARCH = "amd64"
	buildContext.CgoEnabled = false
	entries, err := os.ReadDir(spec.sourceDir)
	if err != nil {
		return fmt.Errorf("read %s: %w", spec.sourceDir, err)
	}
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		matches, matchErr := buildContext.MatchFile(spec.sourceDir, name)
		if matchErr != nil {
			return fmt.Errorf("evaluate build tags for %s: %w", name, matchErr)
		}
		if !matches {
			continue
		}
		file, parseErr := parser.ParseFile(fset, filepath.Join(spec.sourceDir, name), nil, parser.ParseComments)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", name, parseErr)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		return fmt.Errorf("no buildable Go sources in %s", spec.sourceDir)
	}
	pkg, err := doc.NewFromFiles(fset, files, spec.importPath, doc.PreserveAST)
	if err != nil {
		return fmt.Errorf("document %s: %w", spec.importPath, err)
	}

	var body strings.Builder
	body.WriteString("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
	body.WriteString("<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">")
	body.WriteString("<title>" + html.EscapeString(spec.title) + "</title><style>" + stylesheet + "</style></head><body>")
	body.WriteString("<header><span>Go package</span><h1>" + html.EscapeString(pkg.Name) + "</h1>")
	body.WriteString("<code>" + html.EscapeString(spec.importPath) + "</code></header><main>")
	writeDoc(&body, pkg.Doc)
	writeIndex(&body, pkg)
	writeValues(&body, "Constants", pkg.Consts, fset)
	writeValues(&body, "Variables", pkg.Vars, fset)
	writeFuncs(&body, "Functions", pkg.Funcs, fset)
	if len(pkg.Types) > 0 {
		body.WriteString("<section><h2>Types</h2>")
		for _, typ := range pkg.Types {
			body.WriteString("<article id=\"" + html.EscapeString(typ.Name) + "\"><h3>type " + html.EscapeString(typ.Name) + "</h3>")
			writeCode(&body, formatNode(fset, typ.Decl))
			writeDoc(&body, typ.Doc)
			writeValues(&body, "Constants", typ.Consts, fset)
			writeValues(&body, "Variables", typ.Vars, fset)
			writeFuncs(&body, "Constructors", typ.Funcs, fset)
			writeFuncs(&body, "Methods", typ.Methods, fset)
			body.WriteString("</article>")
		}
		body.WriteString("</section>")
	}
	body.WriteString("</main></body></html>\n")

	path := filepath.Join(outputRoot, filepath.FromSlash(spec.outputPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(body.String()), 0o644)
}

func writeIndex(body *strings.Builder, pkg *doc.Package) {
	var entries []string
	for _, fn := range pkg.Funcs {
		entries = append(entries, fn.Name)
	}
	for _, typ := range pkg.Types {
		entries = append(entries, typ.Name)
	}
	if len(entries) == 0 {
		return
	}
	sort.Strings(entries)
	body.WriteString("<nav aria-label=\"Package index\"><strong>Index</strong><ul>")
	for _, name := range entries {
		body.WriteString("<li><a href=\"#" + html.EscapeString(name) + "\">" + html.EscapeString(name) + "</a></li>")
	}
	body.WriteString("</ul></nav>")
}

func writeValues(body *strings.Builder, heading string, values []*doc.Value, fset *token.FileSet) {
	if len(values) == 0 {
		return
	}
	body.WriteString("<section><h4>" + heading + "</h4>")
	for _, value := range values {
		writeCode(body, formatNode(fset, value.Decl))
		writeDoc(body, value.Doc)
	}
	body.WriteString("</section>")
}

func writeFuncs(body *strings.Builder, heading string, functions []*doc.Func, fset *token.FileSet) {
	if len(functions) == 0 {
		return
	}
	body.WriteString("<section><h4>" + heading + "</h4>")
	for _, function := range functions {
		declaration := *function.Decl
		declaration.Body = nil
		body.WriteString("<div class=\"member\" id=\"" + html.EscapeString(function.Name) + "\">")
		writeCode(body, formatNode(fset, &declaration))
		writeDoc(body, function.Doc)
		body.WriteString("</div>")
	}
	body.WriteString("</section>")
}

func writeDoc(body *strings.Builder, raw string) {
	for _, paragraph := range strings.Split(strings.TrimSpace(raw), "\n\n") {
		paragraph = strings.TrimSpace(paragraph)
		if paragraph != "" {
			body.WriteString("<p>" + html.EscapeString(strings.Join(strings.Fields(paragraph), " ")) + "</p>")
		}
	}
}

func writeCode(body *strings.Builder, code string) {
	if code != "" {
		body.WriteString("<pre><code>" + html.EscapeString(code) + "</code></pre>")
	}
}

func formatNode(fset *token.FileSet, node any) string {
	var buffer bytes.Buffer
	if err := format.Node(&buffer, fset, node); err != nil {
		return fmt.Sprint(node)
	}
	return buffer.String()
}

const stylesheet = `
:root{color-scheme:dark;--bg:#0a0818;--surface:#120d24;--border:#2a1f52;--text:#ece6ff;--muted:#8a83bf;--cyan:#52f0ff;--magenta:#ff3ee0}
*{box-sizing:border-box}body{max-width:1120px;margin:0 auto;padding:2rem;background:var(--bg);color:var(--text);font:16px/1.6 system-ui,sans-serif}
header{padding-bottom:1.5rem;border-bottom:1px solid var(--border)}header span,h2,h4{color:var(--cyan)}h1{margin:.15rem 0;font-size:2.5rem}header code{color:var(--muted)}
main{display:grid;gap:1.5rem;margin-top:1.5rem}nav,article,.member{padding:1rem;border:1px solid var(--border);background:var(--surface)}nav ul{columns:3;list-style:none;padding:0}
a{color:var(--cyan)}h2{margin-top:0}h3{color:var(--magenta)}h4{font-size:.8rem;text-transform:uppercase;letter-spacing:.08em}pre{overflow:auto;padding:.8rem;background:#07041a;color:#b8e7ff}
.member{margin:.75rem 0}@media(max-width:640px){body{padding:1rem}nav ul{columns:1}h1{font-size:2rem}}
`
