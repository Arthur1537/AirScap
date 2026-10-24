package scanner

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Source-level scan path policy for cmd/ and internal/ (production code):
// the data channel's scan commands are only reachable through
// Scanner.StartScan, which obtains the grant first. Anything else that
// starts a scan (vens.DataChannel.StartScan/RunScan, or the scan packet
// marshalers outside vens) would bypass the authorization.

var scanCommands = map[string]bool{
	"MarshalPrepareScan": true, "MarshalWaitForScan": true, "MarshalScanConfig": true,
	"MarshalPageTransfer": true, "MarshalWriteToneCurve": true,
}

type scanPathViolation struct {
	pos  token.Position
	call string
}

func scanPathViolations(t *testing.T, root string) (violations []scanPathViolation, checked int) {
	t.Helper()
	fset := token.NewFileSet()
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			inVens := filepath.Base(filepath.Dir(path)) == "vens"
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				checkpoint := fn.Name.Name == "StartScan" && fn.Recv != nil &&
					filepath.Base(path) == "scanner.go" && !inVens
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					var name string
					if ok {
						name = sel.Sel.Name
					} else if id, ok := call.Fun.(*ast.Ident); ok {
						name = id.Name
					}
					checked++
					switch {
					case inVens:
						// The protocol implementation itself.
					case name == "RunScan" || scanCommands[name]:
						violations = append(violations, scanPathViolation{fset.Position(call.Pos()), name})
					case name == "StartScan" && len(call.Args) == 1 && !checkpoint:
						// vens.DataChannel.StartScan(cfg); the authorized
						// Scanner.StartScan takes (ctx, source, cfg).
						violations = append(violations, scanPathViolation{fset.Position(call.Pos()), name})
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return violations, checked
}

func TestScanCommandsOnlyBehindCheckpoint(t *testing.T) {
	violations, checked := scanPathViolations(t, filepath.Join("..", ".."))
	for _, v := range violations {
		t.Errorf("%s: %s bypasses Scanner.StartScan (scan authorization)", v.pos, v.call)
	}
	if checked < 500 {
		t.Fatalf("only %d calls checked; source walk broken?", checked)
	}
}

func TestScanPathPolicyDetectsBypass(t *testing.T) {
	root := t.TempDir()
	write := func(rel, src string) {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("cmd/airscap/main.go", "package main\n")
	write("internal/webui/bypass.go", `package webui
func a(d dc, cfg int) { d.StartScan(cfg) }
func b(d dc, cfg int) { d.RunScan(cfg, nil) }
func c() { vens.MarshalPrepareScan(tok) }
`)
	write("internal/scanner/other.go", `package scanner
func (s *Scanner) Preview(cfg int) { vens.NewDataChannel(h, p, t).StartScan(cfg) }
`)
	write("internal/scanner/scanner.go", `package scanner
func (s *Scanner) StartScan(ctx, src, cfg int) { open(cfg); dc.StartScan(cfg) }
func (s *Scanner) Scan(ctx, src, cfg int) { s.StartScan(ctx, src, cfg) }
`)
	violations, _ := scanPathViolations(t, root)
	if len(violations) != 4 {
		t.Fatalf("violations = %v, want 4 (bypass.go x3, other.go x1)", violations)
	}
}
