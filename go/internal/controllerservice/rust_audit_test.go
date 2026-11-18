//go:build rustinterop

package controllerservice

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/Doout/laneway/go/internal/controller"
	"github.com/Doout/laneway/go/internal/identity"
)

func testRustAudit(t *testing.T, f fixture, client *http.Client, goURL, rustURL, session, csrf string) {
	t.Helper()
	ctx := t.Context()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	foreign, err := f.store.CreateNetwork(ctx, "audit-foreign", netip.MustParsePrefix("10.222.0.0/24"))
	must(err)
	db, err := sql.Open("sqlite", f.dbPath)
	must(err)
	defer db.Close()
	send := labManagementHTTP(t, client)
	root := labCredentials{bearer: testRootBearer}
	owner := labCredentials{session: session, csrf: csrf}
	candidate, err := f.store.AdministratorPasswordCandidate(ctx, "web-auditor")
	must(err)
	_, token, proof, err := f.store.CreateAdministratorSessionAfterPassword(ctx, candidate, controller.AdministratorSessionOptions{})
	must(err)
	auditor := labCredentials{session: token, csrf: proof}
	bot := func(permission, networks string) labCredentials {
		t.Helper()
		form := fmt.Sprintf(`{"name":%q,"permissions":[%q],"network_ids":%s}`, permission, permission, networks)
		id := send(goURL, "POST", "/v1/admin/service-principals", form, root, 201)["principal_id"].(string)
		form = fmt.Sprintf(`{"label":"lab","expires_at_unix_seconds":%d}`, time.Now().Add(time.Hour).Unix())
		return labCredentials{bearer: send(goURL, "POST", "/v1/admin/service-principals/"+id+"/tokens", form, root, 201)["access_token"].(string)}
	}
	scoped := bot("audit.read", fmt.Sprintf("[%q]", foreign.ID))
	global := bot("audit.read_global", "[]")

	const detail = `{"counter":18446744073709551615,"nested":{"status":"recorded"}}`
	stamp := time.Now().Add(time.Hour).Unix()
	add := func(i int, net any, kind string, who []byte) string {
		t.Helper()
		id := fmt.Sprintf("%032x", i)
		raw, err := hex.DecodeString(id)
		must(err)
		var actor any
		if len(who) != 0 {
			actor = who
		}
		_, err = db.Exec(`INSERT INTO audit_events(id,network_id,actor_kind,actor_id,action,target_type,
			target_id,details_json,created_at) VALUES(?,?,?,?,'lab.audit','test',NULL,?,?)`,
			raw, net, kind, actor, detail, stamp)
		must(err)
		return id
	}
	actor := identity.ID{7}
	ids := []string{
		add(1, foreign.ID[:], "system", nil),
		add(2, foreign.ID[:], "legacy_unknown", nil),
		add(3, foreign.ID[:], "node", actor[:]),
		add(4, foreign.ID[:], "administrator", actor[:]),
	}
	glob := add(11, nil, "unauthenticated", nil)
	my := add(12, f.network.ID[:], "service_principal", actor[:])
	list := "/v1/admin/networks/" + foreign.ID.String() + "/audit"
	myList := "/v1/admin/networks/" + f.network.ID.String() + "/audit"
	compare := func(path string, auth labCredentials, want int) map[string]any {
		t.Helper()
		goResult := send(goURL, "GET", path, "", auth, want)
		rustResult := send(rustURL, "GET", path, "", auth, want)
		if !reflect.DeepEqual(goResult, rustResult) {
			t.Fatalf("audit parity for %s: Go=%#v Rust=%#v", path, goResult, rustResult)
		}
		return rustResult
	}
	pageIDs := func(page map[string]any) []string {
		t.Helper()
		rows := page["events"].([]any)
		out := make([]string, 0, len(rows))
		for _, row := range rows {
			out = append(out, row.(map[string]any)["event_id"].(string))
		}
		return out
	}
	expectIDs := func(page map[string]any, expect ...string) {
		t.Helper()
		if got := pageIDs(page); !reflect.DeepEqual(got, expect) {
			t.Fatalf("event IDs=%v want=%v", got, expect)
		}
	}
	compare(myList+"?limit=1", auditor, 200)
	compare(list, auditor, 403)
	compare(myList, scoped, 403)
	compare(list, global, 403)
	compare("/v1/admin/audit", auditor, 403)
	compare("/v1/admin/audit/page", scoped, 403)
	compare("/v1/admin/audit/page?limit=1", owner, 200)
	compare("/v1/admin/audit/page?limit=1", labCredentials{session: "not-a-session"}, 401)
	compare("/v1/admin/networks/000000000000000000000000000000ee/audit", root, 404)
	expectIDs(compare("/v1/admin/audit?limit=2", global, 200), my, glob)
	expectIDs(compare(list+"?limit=2", scoped, 200), ids[3], ids[2])

	first := compare(list+"/page?limit=2", scoped, 200)
	expectIDs(first, ids[3], ids[2])
	row := first["events"].([]any)[1].(map[string]any)
	if row["actor_node_id"] != actor.String() || row["actor_id"] != actor.String() {
		t.Fatal("legacy actor_node_id was not preserved")
	}
	cursor := first["next_cursor"].(string)
	globalCursor := compare("/v1/admin/audit/page?limit=2", global, 200)["next_cursor"].(string)
	for _, suffix := range []string{"?limit=1&limit=2", "?%6cimit=2&limit=3", "?cursor=", "?cursor",
		"?cursor=not-a-cursor", "?cursor=" + cursor + "=", "?cursor=" + cursor + "&cursor=" + cursor,
		"?cursor=" + cursor + ";limit=2", "?limit=%gg", "?limit=0", "?limit=1001", "?unrecognized=1",
		"?cursor=" + globalCursor} {
		compare(list+"/page"+suffix, root, 400)
	}
	compare(myList+"/page?cursor="+cursor, root, 400)
	compare("/v1/admin/audit/page?cursor="+cursor, root, 400)
	compare(list+"/page?cursor=invalid", labCredentials{}, 401)
	compare(list+"/page?limit=", root, 200)

	newer := add(20, foreign.ID[:], "system", nil)
	expectIDs(compare("/v1/admin/audit/page?limit=2&cursor="+globalCursor, global, 200), ids[3], ids[2])
	next := send(rustURL, "GET", list+"/page?limit=1&cursor="+cursor, "", scoped, 200)
	expectIDs(next, ids[1])
	last := send(goURL, "GET", list+"/page?limit=1&cursor="+next["next_cursor"].(string), "", scoped, 200)
	expectIDs(last, ids[0])
	finished := compare(list+"/page?limit=20&cursor="+next["next_cursor"].(string), scoped, 200)
	if _, ok := finished["next_cursor"]; ok {
		t.Fatal("final audit page unexpectedly offered another page")
	}
	expectIDs(compare(list+"/page?limit=1", scoped, 200), newer)

	req, err := http.NewRequestWithContext(ctx, "GET", rustURL+list+"?limit=1", nil)
	must(err)
	req.Header.Set("Authorization", "Bearer "+scoped.bearer)
	resp, err := client.Do(req)
	must(err)
	defer resp.Body.Close()
	wire, err := io.ReadAll(resp.Body)
	must(err)
	if resp.StatusCode != 200 || !bytes.Contains(wire, []byte(detail)) {
		t.Fatal("audit details lost numeric precision or raw JSON representation")
	}
}
