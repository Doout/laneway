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

	"github.com/Doout/laneway/go/internal/adminauth"
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
		if !ok || len(call.Args) < 3 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "registerManagementRoute" {
			return true
		}
		methodSelector, ok := call.Args[1].(*ast.SelectorExpr)
		if !ok {
			t.Errorf("management method is not an http.Method constant")
			return true
		}
		method := map[string]string{
			"MethodGet": http.MethodGet, "MethodPost": http.MethodPost, "MethodPut": http.MethodPut,
			"MethodPatch": http.MethodPatch, "MethodDelete": http.MethodDelete,
		}[methodSelector.Sel.Name]
		if method == "" {
			t.Errorf("unknown management method constant %s", methodSelector.Sel.Name)
			return true
		}
		patternLiteral, ok := call.Args[2].(*ast.BasicLit)
		if !ok || patternLiteral.Kind != token.STRING {
			return true
		}
		path, unquoteErr := strconv.Unquote(patternLiteral.Value)
		if unquoteErr != nil {
			t.Errorf("unquote route pattern %s: %v", patternLiteral.Value, unquoteErr)
			return true
		}
		if path != "/v1/admin" && !strings.HasPrefix(path, "/v1/admin/") {
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

func TestManagementHandlersDoNotCallLegacyAdministratorStoreMethods(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	directory := filepath.Dir(currentFile)
	serviceSource, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, "service.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	managementHandlers := map[string]struct{}{
		// Decision-bound helpers called only from registered management handlers.
		"issueRecoveryGrant": {}, "auditRootTokenRotation": {},
	}
	ast.Inspect(serviceSource, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 4 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "registerManagementRoute" {
			return true
		}
		handler, ok := call.Args[3].(*ast.SelectorExpr)
		if !ok {
			t.Errorf("management route handler is not a service method")
			return true
		}
		managementHandlers[handler.Sel.Name] = struct{}{}
		return true
	})
	if len(managementHandlers) != len(ManagementRoutePolicies())+2 {
		t.Fatalf("management handlers=%d policies=%d", len(managementHandlers)-2, len(ManagementRoutePolicies()))
	}
	for _, name := range []string{"service.go", "management.go", "bootstrap_bundles.go", "administrator_management_http.go"} {
		parsed, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, name), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			if _, ok := managementHandlers[function.Name.Name]; !ok {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !isServiceStoreSelector(selector.X) {
					return true
				}
				method := selector.Sel.Name
				if strings.HasPrefix(method, "Administrator") || strings.HasPrefix(method, "AuditRootAdministrator") ||
					method == "CreateAdministrator" || method == "UpdateAdministrator" ||
					method == "ReplaceAdministratorPassword" || method == "RevokeAdministratorSessionByDecision" ||
					method == "IssueAdministratorRecoveryGrant" {
					return true
				}
				t.Errorf("%s.%s calls legacy Store method %s", name, function.Name.Name, method)
				return true
			})
		}
	}
}

func isServiceStoreSelector(expression ast.Expr) bool {
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "store" {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && identifier.Name == "s"
}
