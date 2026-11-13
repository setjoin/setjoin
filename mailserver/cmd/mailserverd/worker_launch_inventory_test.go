package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type workerSemantic struct {
	Name               string `json:"name"`
	Owner              string `json:"owner"`
	LaunchSite         string `json:"launchSite"`
	ReturnType         string `json:"returnType"`
	InternalGoroutines string `json:"internalGoroutines"`
	StartupFailure     string `json:"startupFailure"`
	RetryPolicy        string `json:"retryPolicy"`
	DrainObligation    string `json:"drainObligation"`
	Residue            string `json:"residue"`
	Cancellation       string `json:"cancellation"`
	ShutdownBound      string `json:"shutdownBound"`
}

type workerSemanticsFile struct {
	SchemaVersion int              `json:"schemaVersion"`
	Workers       []workerSemantic `json:"workers"`
	Exclusions    []struct {
		Category string `json:"category"`
		Owners   string `json:"owners"`
		Reason   string `json:"reason"`
	} `json:"exclusions"`
}

func renderNode(fset *token.FileSet, node any) string {
	var out bytes.Buffer
	if err := printer.Fprint(&out, fset, node); err != nil {
		return fmt.Sprintf("<print-error:%v>", err)
	}
	return strings.Join(strings.Fields(out.String()), " ")
}

func callName(fset *token.FileSet, expr ast.Expr) string {
	switch fun := expr.(type) {
	case *ast.FuncLit:
		seen := map[string]bool{}
		var names []string
		ast.Inspect(fun.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || call.Fun == fun {
				return true
			}
			name := renderNode(fset, call.Fun)
			if !seen[name] && len(names) < 4 {
				seen[name] = true
				names = append(names, name)
			}
			return true
		})
		return "func{" + strings.Join(names, ",") + "}"
	default:
		return renderNode(fset, expr)
	}
}

func collectWorkerLaunchInventory(t *testing.T) (string, []string) {
	t.Helper()
	fset := token.NewFileSet()
	mainPath := os.Getenv("WORKER_LAUNCH_MAIN")
	if mainPath == "" {
		mainPath = "main.go"
	}
	file, err := parser.ParseFile(fset, mainPath, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	var names []string
	ast.Inspect(file, func(node ast.Node) bool {
		switch n := node.(type) {
		case *ast.CallExpr:
			ident, ok := n.Fun.(*ast.Ident)
			if ok && ident.Name == "startWorker" && len(n.Args) == 3 {
				name, err := strconv.Unquote(renderNode(fset, n.Args[1]))
				if err != nil {
					t.Fatal(err)
				}
				names = append(names, name)
				lines = append(lines, "managed|"+name+"|"+renderNode(fset, n.Args[2]))
				return true
			}
			if ok && ident.Name == "workerEnabled" && len(n.Args) == 1 {
				if value, ok := n.Args[0].(*ast.BasicLit); ok {
					name, err := strconv.Unquote(value.Value)
					if err != nil {
						t.Fatal(err)
					}
					names = append(names, name)
					lines = append(lines, "gated|"+name)
				}
				return true
			}
			if !ok || ident.Name != "launchWorker" || len(n.Args) != 4 {
				return true
			}
			name, err := strconv.Unquote(renderNode(fset, n.Args[2]))
			if err != nil {
				t.Fatalf("launchWorker name must be a string literal: %s", renderNode(fset, n.Args[2]))
			}
			names = append(names, name)
			lines = append(lines, "named|"+name+"|"+renderNode(fset, n.Args[3]))
		case *ast.GoStmt:
			call := callName(fset, n.Call.Fun)
			if call == "func{httpServer.Shutdown,logger.Error,logger.Info,close}" {
				// Teardown is named for inventory completeness, but must
				// always run even when every background worker is transferred.
				lines = append(lines, "teardown|http-shutdown|"+call)
			} else {
				lines = append(lines, "direct|"+call)
			}
		}
		return true
	})
	// Cron tasks transfer independently of the foundation scheduler (#244).
	tasks, err := parser.ParseFile(fset, "../../internal/cron/tasks.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	ast.Inspect(tasks, func(node ast.Node) bool {
		field, ok := node.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := field.Key.(*ast.Ident)
		if !ok || key.Name != "Name" {
			return true
		}
		name, err := strconv.Unquote(renderNode(fset, field.Value))
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, "cron-task|cron:"+name)
		return true
	})
	return "schema=1\n" + strings.Join(lines, "\n") + "\n", names
}

func TestWorkerLaunchInventoryGolden(t *testing.T) {
	actual, _ := collectWorkerLaunchInventory(t)
	goldenPath := os.Getenv("WORKER_LAUNCH_GOLDEN")
	if goldenPath == "" {
		goldenPath = filepath.Join("testdata", "worker_launch_inventory.golden")
	}
	if os.Getenv("UPDATE_GOLDEN") == "1" && os.Getenv("WORKER_LAUNCH_MAIN") == "" {
		if err := os.WriteFile(goldenPath, []byte(actual), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read worker launch golden: %v\nactual:\n%s", err, actual)
	}
	if actual != string(want) {
		t.Fatalf("worker launch inventory drifted; review every named/direct lifecycle before accepting\nactual:\n%s\nwant:\n%s", actual, want)
	}
}

func TestWorkerSemanticsCoversNamedLaunches(t *testing.T) {
	_, launchNames := collectWorkerLaunchInventory(t)
	semanticsPath := os.Getenv("WORKER_SEMANTICS")
	if semanticsPath == "" {
		semanticsPath = filepath.Join("testdata", "worker_semantics.json")
	}
	raw, err := os.ReadFile(semanticsPath)
	if err != nil {
		t.Fatal(err)
	}
	var semantics workerSemanticsFile
	if err := json.Unmarshal(raw, &semantics); err != nil {
		t.Fatal(err)
	}
	if semantics.SchemaVersion != 1 || len(semantics.Exclusions) == 0 {
		t.Fatal("worker semantics must use schema 1 and retain explicit exclusions")
	}
	rows := make(map[string]workerSemantic, len(semantics.Workers))
	for _, row := range semantics.Workers {
		if _, exists := rows[row.Name]; exists {
			t.Fatalf("duplicate worker semantics row %q", row.Name)
		}
		if row.Owner == "" || row.LaunchSite == "" || row.ReturnType == "" || row.InternalGoroutines == "" ||
			row.StartupFailure == "" || row.RetryPolicy == "" || row.DrainObligation == "" || row.Residue == "" ||
			row.Cancellation == "" || row.ShutdownBound == "" {
			t.Fatalf("worker semantics row %q has an empty required field", row.Name)
		}
		rows[row.Name] = row
	}
	if len(rows) != len(launchNames) {
		t.Fatalf("semantics rows=%d named launches=%d", len(rows), len(launchNames))
	}
	for _, name := range launchNames {
		if _, ok := rows[name]; !ok {
			t.Fatalf("named launch %q has no reviewed semantics row", name)
		}
	}
}

func TestWorkerLaunchInventoryNamesUserRisk(t *testing.T) {
	_, names := collectWorkerLaunchInventory(t)
	seen := map[string]bool{}
	for _, name := range names {
		if name == "" || seen[name] {
			t.Fatalf("worker name %q is empty or duplicated", name)
		}
		seen[name] = true
	}
	if !seen["user-risk"] {
		t.Fatal("user-risk worker must have a switchable name")
	}
}

func TestWorkerLaunchInventoryNamesDirectWorkers(t *testing.T) {
	actual, _ := collectWorkerLaunchInventory(t)
	for _, line := range strings.Split(actual, "\n") {
		if strings.HasPrefix(line, "direct|") {
			t.Errorf("worker bypasses GO_WORKERS_OFF: %s", line)
		}
	}
}

func TestWorkerLaunchInventoryNamesManagedWorkers(t *testing.T) {
	_, names := collectWorkerLaunchInventory(t)
	seen := map[string]bool{}
	for _, name := range names {
		seen[name] = true
	}
	for _, name := range []string{"webhook-retry", "blob-cleanup", "ad-sync", "ldap-sync", "identity-source-runtime", "acme-renewal"} {
		if !seen[name] {
			t.Errorf("self-starting worker %q bypasses GO_WORKERS_OFF", name)
		}
	}
}
