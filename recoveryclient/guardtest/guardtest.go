// Package guardtest pins the decrypt boundary of a product: nothing in the server may open a
// capsule sealed to the suite key, combine shares or rebuild the key from a seed, except the
// functions the product names. Products call NoDecryptOutside from one test.
package guardtest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// forbidden maps the last path element of a watched import to the selectors that decrypt.
// recoveryclient.Drill is not here: it opens only a capsule sealed to a key it generated and
// dropped inside the call.
var forbidden = map[string]map[string]bool{
	"capsule":        {"Open": true},
	"recoverykey":    {"Combine": true, "FromSeed": true},
	"recoveryclient": {"Restore": true},
}

const importPrefix = "github.com/Busness-app/ky-primitives/"

// MinFiles is how many Go files a walk must see before its verdict counts. A guard that
// walked nothing passes vacuously, which the first draft of this test did.
const MinFiles = 10

// NoDecryptOutside walks every non-test Go file under repoRoot (absolute) and fails t for
// each call of a forbidden selector outside allowed, which maps a repo-relative file path to
// the names of functions inside it that may make such calls.
func NoDecryptOutside(t testing.TB, repoRoot string, allowed map[string][]string) {
	t.Helper()
	if !filepath.IsAbs(repoRoot) {
		t.Fatalf("guardtest: repo root must be absolute, got %q", repoRoot)
	}
	seen := 0
	fset := token.NewFileSet()
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != repoRoot && (strings.HasPrefix(name, ".") || name == "node_modules" || name == "web" || name == "dist" || name == "vendor") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		seen++
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		aliases := map[string]string{} // local name -> package key
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if !strings.HasPrefix(p, importPrefix) {
				continue
			}
			key := p[strings.LastIndex(p, "/")+1:]
			if _, watched := forbidden[key]; !watched {
				continue
			}
			local := key
			if imp.Name != nil {
				local = imp.Name.Name
			}
			aliases[local] = key
		}
		if len(aliases) == 0 {
			return nil
		}
		rel, _ := filepath.Rel(repoRoot, path)
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				key, watched := aliases[id.Name]
				if !watched || !forbidden[key][sel.Sel.Name] {
					return true
				}
				if slices.Contains(allowed[rel], fn.Name.Name) {
					return true
				}
				t.Errorf("guardtest: %s calls %s.%s inside %s, which is not allowed to decrypt", fset.Position(sel.Pos()), key, sel.Sel.Name, fn.Name.Name)
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("guardtest: walking %s: %v", repoRoot, err)
	}
	if seen < MinFiles {
		t.Fatalf("guardtest: walked only %d Go files under %s; the guard is not looking at the repository", seen, repoRoot)
	}
}
