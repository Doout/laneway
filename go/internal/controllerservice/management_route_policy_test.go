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

func TestManagementHandlersUseOnlyDecisionBoundStoreMethods(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	directory := filepath.Dir(currentFile)
	serviceSource, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, "service.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	managementHandlers := make(map[string]struct{})
	registrations := 0
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
		receiver, ok := handler.X.(*ast.Ident)
		if !ok || receiver.Name != "s" {
			t.Errorf("management route handler %s is not selected from the Service receiver", handler.Sel.Name)
			return true
		}
		registrations++
		managementHandlers[handler.Sel.Name] = struct{}{}
		return true
	})
	if registrations != len(ManagementRoutePolicies()) {
		t.Fatalf("management registrations=%d policies=%d", registrations, len(ManagementRoutePolicies()))
	}

	type serviceMethod struct {
		file     string
		receiver string
		function *ast.FuncDecl
	}
	serviceMethods := make(map[string]serviceMethod)
	files, err := filepath.Glob(filepath.Join(directory, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			receiver, ok := serviceReceiverName(function)
			if !ok || function.Body == nil {
				continue
			}
			if previous, exists := serviceMethods[function.Name.Name]; exists {
				t.Fatalf("duplicate Service method %s in %s and %s", function.Name.Name, previous.file, file)
			}
			serviceMethods[function.Name.Name] = serviceMethod{file: filepath.Base(file), receiver: receiver, function: function}
		}
	}

	decisionBoundStoreMethods := map[string]struct{}{
		"AdministratorIssueEnrollmentTokenWithOptions": {},
		"AdministratorAddACLRule":                      {}, "AdministratorApproveRoute": {},
		"AdministratorAssignRoute": {}, "AdministratorAuditEvents": {},
		"AdministratorCreateNetworkDualStack": {}, "AdministratorCreateNetworkDualStackWithID": {},
		"AdministratorDeleteACLRule": {}, "AdministratorDisableRelay": {},
		"AdministratorNetwork": {}, "AdministratorNetworkACLRules": {},
		"AdministratorNetworkCertificates": {}, "AdministratorNetworkNodes": {},
		"AdministratorNetworkRelays": {}, "AdministratorNetworkRoutes": {}, "AdministratorNetworks": {},
		"AdministratorRegisterRelay": {}, "AdministratorRevokeCertificateBySerial": {},
		"AdministratorRevokeNode": {}, "AdministratorSetNodeCapabilities": {},
		"AdministratorUpdateACLRule": {}, "AdministratorUpdateRelay": {}, "AdministratorWithdrawRoute": {},
		"AdministratorAccessInventory": {}, "AdministratorCreateAccessGrant": {},
		"AdministratorCreateAccessTeam": {}, "AdministratorCreateAccessUser": {},
		"AdministratorDeleteAccessGrant": {}, "AdministratorSetAccessTeamMember": {},
		"AdministratorCreateAccessResource": {}, "AdministratorSetAccessResourceEnabled": {},
		"AdministratorCreateAccessService": {}, "AdministratorSetAccessServiceEnabled": {},
		"AdministratorCreateAccessResourceGrant": {}, "AdministratorDeleteAccessResourceGrant": {},
		"AdministratorSetAccessUserEnabled": {}, "AdministratorAuditMutation": {},
		"AdministratorGlobalAuditEvents": {}, "AdministratorGlobalAuditEventsPage": {},
		"AdministratorAuditEventsPage": {}, "AdministratorNetworkEndpointStatuses": {},
		"AdministratorPrincipalAuthorized": {},
		"AdministratorPrincipalByUsername": {}, "AdministratorPrincipals": {}, "AdministratorSessions": {},
		"AuditRootAdministratorTokenRotationBegin": {}, "AuditRootAdministratorTokenRotationComplete": {},
		"CreateAdministrator": {}, "IssueAdministratorRecoveryGrant": {}, "ReplaceAdministratorPassword": {},
		"RevokeAdministratorSessionByDecision": {}, "UpdateAdministrator": {},
		"CreateServicePrincipal": {}, "ServicePrincipals": {}, "DisableServicePrincipal": {},
		"IssueServiceAccessToken": {}, "ServiceAccessTokens": {}, "RevokeServiceAccessToken": {},
	}

	pending := make([]string, 0, len(managementHandlers))
	for handler := range managementHandlers {
		pending = append(pending, handler)
	}
	visited := make(map[string]struct{})
	for len(pending) != 0 {
		name := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		if _, done := visited[name]; done {
			continue
		}
		method, exists := serviceMethods[name]
		if !exists {
			t.Errorf("registered or reachable Service method %s has no declaration", name)
			continue
		}
		visited[name] = struct{}{}
		directStoreReferences := make(map[*ast.SelectorExpr]struct{})
		ast.Inspect(method.function.Body, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.CallExpr:
				selector, ok := value.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if receiver, ok := selector.X.(*ast.Ident); ok && receiver.Name == method.receiver {
					if _, exists := serviceMethods[selector.Sel.Name]; exists {
						pending = append(pending, selector.Sel.Name)
					}
				}
			case *ast.SelectorExpr:
				if storeReference, ok := value.X.(*ast.SelectorExpr); ok &&
					isServiceStoreSelector(storeReference, method.receiver) {
					directStoreReferences[storeReference] = struct{}{}
					if _, allowed := decisionBoundStoreMethods[value.Sel.Name]; !allowed {
						t.Errorf("%s.%s references non-decision-bound Store method %s", method.file, name, value.Sel.Name)
					}
					return true
				}
				if isServiceStoreSelector(value, method.receiver) {
					if _, direct := directStoreReferences[value]; !direct {
						t.Errorf("%s.%s aliases or passes the Store outside a checked direct call", method.file, name)
					}
				}
			}
			return true
		})
	}
}

func serviceReceiverName(function *ast.FuncDecl) (string, bool) {
	if function == nil || function.Recv == nil || len(function.Recv.List) != 1 ||
		len(function.Recv.List[0].Names) != 1 {
		return "", false
	}
	receiverType := function.Recv.List[0].Type
	if pointer, ok := receiverType.(*ast.StarExpr); ok {
		receiverType = pointer.X
	}
	typeName, ok := receiverType.(*ast.Ident)
	if !ok || typeName.Name != "Service" {
		return "", false
	}
	return function.Recv.List[0].Names[0].Name, true
}

func isServiceStoreSelector(selector *ast.SelectorExpr, receiverName string) bool {
	if selector == nil || selector.Sel.Name != "store" {
		return false
	}
	identifier, ok := selector.X.(*ast.Ident)
	return ok && identifier.Name == receiverName
}
