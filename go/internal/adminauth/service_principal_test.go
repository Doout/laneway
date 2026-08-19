package adminauth

import (
	"bytes"
	"testing"

	"github.com/Doout/laneway/go/internal/identity"
)

func TestServiceAccessTokenIsSelfIdentifyingPurposeSeparatedAndStrict(t *testing.T) {
	tokenID := identity.ID{1}
	bearer, digest, err := NewServiceAccessToken(tokenID, bytes.NewReader(bytes.Repeat([]byte{7}, secretBytes)))
	if err != nil {
		t.Fatal(err)
	}
	parsedID, parsedDigest, err := ParseServiceAccessToken(bearer)
	if err != nil || parsedID != tokenID || parsedDigest != digest {
		t.Fatalf("parsed token id=%s digest=%x err=%v", parsedID, parsedDigest, err)
	}
	otherID := identity.ID{2}
	_, otherDigest, err := NewServiceAccessToken(otherID, bytes.NewReader(bytes.Repeat([]byte{7}, secretBytes)))
	if err != nil || otherDigest == digest {
		t.Fatalf("token ID was not bound into digest: %x %x err=%v", digest, otherDigest, err)
	}
	for _, malformed := range []string{"", bearer + ".extra", "lnw_spat_v0." + tokenID.String() + ".bad", " " + bearer, bearer + " "} {
		if _, _, err := ParseServiceAccessToken(malformed); err == nil {
			t.Errorf("malformed token accepted: %q", malformed)
		}
	}
}

func TestServicePrincipalAuthorizationRequiresExplicitOperationAndScope(t *testing.T) {
	principalID, tokenID := identity.ID{1}, identity.ID{2}
	networkOne, networkTwo := identity.NetworkID{3}, identity.NetworkID{4}
	principal := ServicePrincipal{ID: principalID, Name: "deploy-bot", Enabled: true,
		NetworkIDs:  []identity.NetworkID{networkOne},
		Permissions: []Operation{OperationNetworkList, OperationNetworkRead, OperationACLManage}}
	if !principal.Valid() {
		t.Fatal("valid scoped service principal rejected")
	}
	if !AuthorizeServicePrincipal(principal, OperationNetworkRead, &networkOne) ||
		AuthorizeServicePrincipal(principal, OperationNetworkRead, &networkTwo) ||
		AuthorizeServicePrincipal(principal, OperationNodeManage, &networkOne) ||
		AuthorizeServicePrincipal(principal, OperationNetworkRead, nil) {
		t.Fatal("service principal operation or network scope was not enforced")
	}
	proof := [32]byte{9}
	subject := ServicePrincipalTokenSubject(principalID, tokenID, proof)
	readPolicy := managementPolicyForTest(t, "GET", "/v1/admin/networks/{network_id}")
	if !AuthorizeServicePrincipalEarly(subject, &principal, readPolicy, NetworkTarget(networkOne)) ||
		AuthorizeServicePrincipalEarly(subject, &principal, readPolicy, NetworkTarget(networkTwo)) {
		t.Fatal("early service-principal scope authorization failed")
	}
	managePrincipals := managementPolicyForTest(t, "POST", "/v1/admin/service-principals")
	if AuthorizeServicePrincipalEarly(subject, &principal, managePrincipals, GlobalTarget()) ||
		AutomationGrantable(OperationServicePrincipalManage) || AutomationGrantable(OperationRootTokenRotate) {
		t.Fatal("automation identity could administer credentials or root state")
	}
	if got := VisibleServicePrincipalNetworkIDs(principal, []identity.NetworkID{networkTwo, networkOne}); len(got) != 1 || got[0] != networkOne {
		t.Fatalf("visible networks=%v", got)
	}
}

func TestServicePrincipalValidationRejectsImplicitOrAmbiguousGrants(t *testing.T) {
	principalID := identity.ID{1}
	networkID := identity.NetworkID{2}
	for _, principal := range []ServicePrincipal{
		{},
		{ID: principalID, Name: "deploy-bot", Enabled: true},
		{ID: principalID, Name: "DeployBot", Enabled: true, Permissions: []Operation{OperationNetworkCreate}},
		{ID: principalID, Name: "deploy-bot", Enabled: true, Permissions: []Operation{OperationNetworkRead}},
		{ID: principalID, Name: "deploy-bot", Enabled: true, NetworkIDs: []identity.NetworkID{networkID}, Permissions: []Operation{OperationNetworkCreate}},
		{ID: principalID, Name: "deploy-bot", Enabled: true, AllNetworks: true, NetworkIDs: []identity.NetworkID{networkID}, Permissions: []Operation{OperationNetworkRead}},
		{ID: principalID, Name: "deploy-bot", Enabled: true, Permissions: []Operation{OperationPrincipalManage}},
		{ID: principalID, Name: "deploy-bot", Enabled: true, Permissions: []Operation{OperationNetworkRead, OperationNetworkRead}},
	} {
		if principal.Valid() {
			t.Fatalf("invalid service principal accepted: %+v", principal)
		}
	}
}
