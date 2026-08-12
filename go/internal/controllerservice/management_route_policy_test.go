package controllerservice

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"laneway.dev/laneway/internal/adminauth"
)

func TestManagementRoutePoliciesCoverEveryRegisteredAdminHandler(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	serviceFile := filepath.Join(filepath.Dir(currentFile), "service.go")
	parsed, err := parser.ParseFile(token.NewFileSet(), serviceFile, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	registered := make(map[routePolicyKey]struct{})
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "HandleFunc" {
			return true
		}
		patternLiteral, ok := call.Args[0].(*ast.BasicLit)
		if !ok || patternLiteral.Kind != token.STRING {
			return true
		}
		pattern, unquoteErr := strconv.Unquote(patternLiteral.Value)
		if unquoteErr != nil {
			t.Errorf("unquote route pattern %s: %v", patternLiteral.Value, unquoteErr)
			return true
		}
		method, path, found := strings.Cut(pattern, " ")
		if !found || path != "/v1/admin" && !strings.HasPrefix(path, "/v1/admin/") {
			return true
		}
		registered[routePolicyKey{method: method, pattern: path}] = struct{}{}
		return true
	})

	policies := ManagementRoutePolicies()
	if len(registered) != len(policies) {
		t.Errorf("registered admin routes=%d policy routes=%d", len(registered), len(policies))
	}
	for _, policy := range policies {
		key := routePolicyKey{method: policy.Method, pattern: policy.Pattern}
		if _, ok := registered[key]; !ok {
			t.Errorf("policy has no registered handler: %s %s", policy.Method, policy.Pattern)
		}
		resolved, ok := ManagementRoutePolicy(policy.Method, policy.Pattern)
		if !ok || resolved != policy {
			t.Errorf("policy lookup for %s %s = (%+v,%t)", policy.Method, policy.Pattern, resolved, ok)
		}
	}
	for key := range registered {
		if _, ok := ManagementRoutePolicy(key.method, key.pattern); !ok {
			t.Errorf("registered handler has no policy: %s %s", key.method, key.pattern)
		}
	}

	policies[0].Pattern = "/changed"
	if _, ok := ManagementRoutePolicy(http.MethodPost, "/v1/admin/enrollment-tokens"); !ok {
		t.Fatal("caller mutated the management policy registry")
	}
	if _, ok := ManagementRoutePolicy(http.MethodGet, "/v1/admin/enrollment-tokens"); ok {
		t.Fatal("route policy lookup ignored the HTTP method")
	}
}

func TestRoutePolicyRegistryRejectsInvalidAndDuplicatePolicies(t *testing.T) {
	valid := adminauth.ManagementRoutes()[0]
	if _, err := newRoutePolicyRegistry([]adminauth.RoutePolicy{valid}); err != nil {
		t.Fatalf("valid registry rejected: %v", err)
	}
	if _, err := newRoutePolicyRegistry([]adminauth.RoutePolicy{valid, valid}); err == nil {
		t.Fatal("duplicate route policy accepted")
	}
	invalidPrefix := valid
	invalidPrefix.Pattern = "/v1/not-admin"
	if _, err := newRoutePolicyRegistry([]adminauth.RoutePolicy{invalidPrefix}); err == nil {
		t.Fatal("non-management route policy accepted")
	}
	invalidOperation := valid
	invalidOperation.Operation = "unknown"
	if _, err := newRoutePolicyRegistry([]adminauth.RoutePolicy{invalidOperation}); err == nil {
		t.Fatal("unknown operation policy accepted")
	}
}
