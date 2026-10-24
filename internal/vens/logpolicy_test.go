package vens

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Source-level log policy for cmd/ and internal/ (production code only):
//
//   - no raw packet dumps (encoding/hex, %x of byte data) in slog calls;
//   - no secret-bearing value (password, identity, token, serial, FTP
//     password, Paperless token) in slog calls or fmt.Errorf, except a
//     serial wrapped in RedactSerial.
//
// The dynamic tests prove the redaction on real code paths; this test keeps
// new log statements from reintroducing a leak.

var sensitiveNames = map[string]bool{
	"password": true, "identity": true, "token": true, "serial": true,
	"secret": true, "ftppassword": true, "paperlesstoken": true,
}

// Calls that redact their argument.
var redactingCalls = map[string]bool{
	"RedactSerial": true, "vens.RedactSerial": true, "PacketSummary": true,
	"vens.PacketSummary": true, "ScrubSecrets": true, "vens.ScrubSecrets": true,
	"errorBody": true, "redactURL": true,
}

// "0x%04X" formats a number; a bare %x is a byte dump.
var byteDumpFormat = regexp.MustCompile(`(^|[^x])%[-+# 0-9]*[xX]`)

func sensitive(name string) bool {
	return sensitiveNames[strings.ToLower(name)]
}

func callName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.SelectorExpr:
		if pkg, ok := fun.X.(*ast.Ident); ok {
			return pkg.Name + "." + fun.Sel.Name
		}
		return fun.Sel.Name
	case *ast.Ident:
		return fun.Name
	}
	return ""
}

// secretValue reports an expression that carries a secret unredacted.
func secretValue(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		if sensitive(e.Name) {
			return e.Name
		}
	case *ast.SelectorExpr:
		if sensitive(e.Sel.Name) {
			return e.Sel.Name
		}
	case *ast.CallExpr:
		name := callName(e)
		if redactingCalls[name] || name == "len" {
			return ""
		}
		if strings.HasPrefix(name, "hex.") {
			return name
		}
		// string(packet) dumps raw bytes into the log.
		if name == "string" && len(e.Args) == 1 {
			if _, isCall := e.Args[0].(*ast.CallExpr); !isCall {
				return "string(...)"
			}
		}
		if name == "fmt.Sprintf" && len(e.Args) > 0 {
			if lit, ok := e.Args[0].(*ast.BasicLit); ok {
				format, _ := strconv.Unquote(lit.Value)
				if byteDumpFormat.MatchString(format) {
					return "fmt.Sprintf(" + lit.Value + ")"
				}
			}
		}
		for _, arg := range e.Args {
			if found := secretValue(arg); found != "" {
				return found
			}
		}
	case *ast.BinaryExpr:
		if found := secretValue(e.X); found != "" {
			return found
		}
		return secretValue(e.Y)
	}
	return ""
}

func isSlogCall(name string) bool {
	switch name {
	case "slog.Debug", "slog.Info", "slog.Warn", "slog.Error", "slog.Log",
		"slog.DebugContext", "slog.InfoContext", "slog.WarnContext", "slog.ErrorContext":
		return true
	}
	return false
}

func TestLogPolicy(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	checked := 0

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
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := callName(call)
				switch {
				case isSlogCall(name):
					checked++
					for i, arg := range call.Args {
						if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING && i > 0 {
							key, _ := strconv.Unquote(lit.Value)
							if sensitive(key) && i+1 < len(call.Args) {
								next := call.Args[i+1]
								if c, ok := next.(*ast.CallExpr); !ok || !strings.HasSuffix(callName(c), "RedactSerial") {
									t.Errorf("%s: %s logs key %q without redaction", fset.Position(arg.Pos()), name, key)
								}
							}
							continue
						}
						if found := secretValue(arg); found != "" {
							t.Errorf("%s: %s logs %s", fset.Position(arg.Pos()), name, found)
						}
					}
				case name == "fmt.Errorf":
					for _, arg := range call.Args[1:] {
						if found := secretValue(arg); found != "" {
							t.Errorf("%s: fmt.Errorf includes %s", fset.Position(arg.Pos()), found)
						}
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 100 {
		t.Fatalf("only %d slog calls checked; source walk broken?", checked)
	}
}

func TestLogPolicyDetectsLeaks(t *testing.T) {
	// The checker itself: each of these must be reported.
	for _, src := range []string{
		`slog.Debug("x", "hex", hex.EncodeToString(b))`,
		`slog.Info("x", "serial", info.Serial)`,
		`slog.Info("x", "v", password)`,
		`slog.Debug("x", "token", fmt.Sprintf("%x", token))`,
		`slog.Debug("x", "v", fmt.Sprintf("%x", data))`,
		`slog.Info("x", "id", s.identity)`,
		`slog.Debug("x", "packet", string(req))`,
	} {
		expr, err := parser.ParseExpr(src)
		if err != nil {
			t.Fatal(err)
		}
		call := expr.(*ast.CallExpr)
		reported := false
		for i, arg := range call.Args {
			if lit, ok := arg.(*ast.BasicLit); ok && i > 0 {
				key, _ := strconv.Unquote(lit.Value)
				if sensitive(key) {
					if c, ok := call.Args[i+1].(*ast.CallExpr); !ok || !strings.HasSuffix(callName(c), "RedactSerial") {
						reported = true
					}
				}
				continue
			}
			if secretValue(arg) != "" {
				reported = true
			}
		}
		if !reported {
			t.Errorf("not detected: %s", src)
		}
	}
	// Allowed: redacted serial, lengths, numeric hex, packet summaries.
	for _, src := range []string{
		`slog.Info("x", "serial", vens.RedactSerial(info.Serial))`,
		`slog.Debug("x", "identity_len", len(identity))`,
		`slog.Info("x", "status", fmt.Sprintf("0x%08X", status))`,
		`slog.Debug("x", "packet", PacketSummary(req))`,
	} {
		expr, _ := parser.ParseExpr(src)
		call := expr.(*ast.CallExpr)
		for i, arg := range call.Args {
			if _, ok := arg.(*ast.BasicLit); ok && i > 0 {
				continue
			}
			if found := secretValue(arg); found != "" {
				t.Errorf("false positive %q in %s", found, src)
			}
		}
	}
}
