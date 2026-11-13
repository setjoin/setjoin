package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/reducererr"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

func guestViewClaims(userID int64) *auth.Claims {
	return &auth.Claims{UserID: userID, Permissions: []string{permissions.PermGuestsView}}
}

func TestGuestProfilesHandler_ToggleFirstAndStrictJSON(t *testing.T) {
	off := NewGuestProfilesHandler(nil,
		toggle.NewTestFlags(map[string]bool{toggle.FeatureGuestAccounts: false}), nil)
	called := false
	wrapped := off.Gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, guestAdminRequest(http.MethodGet, "/admin/guest-profiles", "", guestViewClaims(1)))
	if rr.Code != http.StatusNotFound || called {
		t.Fatalf("toggle OFF must return 404 before permission/handler path: code=%d called=%v", rr.Code, called)
	}
	updateReq := guestAdminRequest(http.MethodPut, "/admin/guest-profiles/not-an-id", `{}`, guestManageClaims(1))
	updateReq.SetPathValue("id", "not-an-id")
	updateRR := httptest.NewRecorder()
	off.Update(updateRR, updateReq)
	if updateRR.Code != http.StatusNotFound {
		t.Fatalf("toggle OFF must precede path validation, got %d: %s", updateRR.Code, updateRR.Body.String())
	}

	on := NewGuestProfilesHandler(nil, guestsOnFlags(), nil)
	t.Run("view cannot write", func(t *testing.T) {
		rr := httptest.NewRecorder()
		on.Create(rr, guestAdminRequest(http.MethodPost, "/admin/guest-profiles", `{}`, guestViewClaims(1)))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("want 403 without guests.manage, got %d: %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("unknown profile field", func(t *testing.T) {
		rr := httptest.NewRecorder()
		on.Create(rr, guestAdminRequest(http.MethodPost, "/admin/guest-profiles",
			`{"hostDomainId":1,"name":"Guest","unknown":true}`, guestManageClaims(1)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for unknown JSON field, got %d: %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("required booleans distinguish omitted from false", func(t *testing.T) {
		base := map[string]any{
			"hostDomainId": 1, "name": "Restrictive", "canPost": false,
			"historyFromJoin": false, "allowDownload": false, "allowMeetCreate": false,
			"allowMeetHost": false, "canInitiateDm": false, "allowNativeShell": false,
			"defaultExpiryDays": nil, "apps": []string{},
		}
		for _, field := range []string{
			"canPost", "historyFromJoin", "allowDownload", "allowMeetCreate",
			"allowMeetHost", "canInitiateDm", "allowNativeShell",
		} {
			t.Run(field, func(t *testing.T) {
				body := make(map[string]any, len(base)-1)
				for key, value := range base {
					if key != field {
						body[key] = value
					}
				}
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				rr := httptest.NewRecorder()
				on.Create(rr, guestAdminRequest(http.MethodPost, "/admin/guest-profiles",
					string(raw), guestManageClaims(1)))
				if rr.Code != http.StatusBadRequest {
					t.Fatalf("omitted %s: want 400 before DB mutation, got %d: %s", field, rr.Code, rr.Body.String())
				}
			})
		}
		for _, field := range []string{"defaultExpiryDays", "apps"} {
			t.Run("omitted "+field, func(t *testing.T) {
				body := make(map[string]any, len(base)-1)
				for key, value := range base {
					if key != field {
						body[key] = value
					}
				}
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				rr := httptest.NewRecorder()
				on.Create(rr, guestAdminRequest(http.MethodPost, "/admin/guest-profiles",
					string(raw), guestManageClaims(1)))
				if rr.Code != http.StatusBadRequest {
					t.Fatalf("omitted %s: want 400 before DB mutation, got %d: %s", field, rr.Code, rr.Body.String())
				}
			})
		}
		for name, apps := range map[string]any{"null": nil, "scalar": "chat"} {
			t.Run("apps "+name, func(t *testing.T) {
				body := make(map[string]any, len(base))
				for key, value := range base {
					body[key] = value
				}
				body["apps"] = apps
				raw, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				rr := httptest.NewRecorder()
				on.Create(rr, guestAdminRequest(http.MethodPost, "/admin/guest-profiles",
					string(raw), guestManageClaims(1)))
				if rr.Code != http.StatusBadRequest {
					t.Fatalf("apps %s: want 400, got %d: %s", name, rr.Code, rr.Body.String())
				}
			})
		}
		raw, err := json.Marshal(base)
		if err != nil {
			t.Fatal(err)
		}
		req := guestAdminRequest(http.MethodPost, "/admin/guest-profiles", string(raw), guestManageClaims(1))
		var decoded guestProfileInput
		if err := decodeGuestJSON(httptest.NewRecorder(), req, &decoded); err != nil {
			t.Fatalf("all-false body with apps:[] and defaultExpiryDays:null must decode: %v", err)
		}
		defaultExpiryDays, apps, err := decoded.decodeRequiredPolicyFields()
		if err != nil {
			t.Fatalf("decode required policy fields: %v", err)
		}
		if !decoded.hasRequiredBooleans() || defaultExpiryDays != nil || len(apps) != 0 {
			t.Fatalf("decoded restrictive body lost presence/null/empty distinctions: %+v", decoded)
		}
	})
	t.Run("unknown assignment field", func(t *testing.T) {
		h := NewGuestsHandler(nil, guestsOnFlags(), nil, "", nil)
		req := guestAdminRequest(http.MethodPut, "/admin/guests/9/profile",
			`{"profileId":null,"unknown":true}`, guestManageClaims(1))
		req.SetPathValue("id", "9")
		rr := httptest.NewRecorder()
		h.AssignProfile(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for unknown JSON field, got %d: %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("extend requires expiresAt", func(t *testing.T) {
		h := NewGuestsHandler(nil, guestsOnFlags(), nil, "", nil)
		req := guestAdminRequest(http.MethodPost, "/admin/guests/9/extend", `{}`, guestManageClaims(1))
		req.SetPathValue("id", "9")
		rr := httptest.NewRecorder()
		h.Extend(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("want 400 for missing expiresAt, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestGuestProfileReducerErrorProjection(t *testing.T) {
	for _, tc := range []struct {
		code string
		want int
	}{
		{"BZ224", http.StatusUnprocessableEntity},
		{"BZ225", http.StatusConflict},
		{"BZ226", http.StatusConflict},
	} {
		t.Run(tc.code, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/admin/guest-profiles", nil)
			if !reducererr.WriteClassified(rr, req, &pgconn.PgError{Code: tc.code}) {
				t.Fatalf("%s must be classified", tc.code)
			}
			if rr.Code != tc.want {
				t.Fatalf("%s: want %d, got %d", tc.code, tc.want, rr.Code)
			}
		})
	}
}

type guestProfileFixture struct {
	pool          *pgxpool.Pool
	profiles      *GuestProfilesHandler
	guests        *GuestsHandler
	manageActorID int64
	viewActorID   int64
	otherActorID  int64
	hostDomainID  int64
	otherDomainID int64
	guestID       int64
	roleIDs       []int64
}

func newGuestProfileFixture(t *testing.T) *guestProfileFixture {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()
	suffix := rolesTestRandomSuffix(t)
	hostDomainID := ensureScopeTestDomain(t, pool, "g2-api-"+suffix+".example")
	otherDomainID := ensureScopeTestDomain(t, pool, "g2-api-other-"+suffix+".example")
	insertUser := func(label string, domainID int64) int64 {
		t.Helper()
		var id int64
		email := fmt.Sprintf("%s-%s@example.test", label, suffix)
		if err := pool.QueryRow(ctx,
			`INSERT INTO users(username,domain_id,email,display_name,enabled)
			 VALUES($1,$2,$3,$4,TRUE) RETURNING id`, email, domainID, email, label).Scan(&id); err != nil {
			t.Fatalf("insert %s: %v", label, err)
		}
		return id
	}
	manageActorID := insertUser("g2-manage", hostDomainID)
	viewActorID := insertUser("g2-view", hostDomainID)
	otherActorID := insertUser("g2-other", otherDomainID)
	var guestDomainID int64
	if err := pool.QueryRow(ctx, `SELECT id FROM domains WHERE name='guest.invalid'`).Scan(&guestDomainID); err != nil {
		t.Fatalf("resolve guest.invalid: %v", err)
	}
	guestID := insertUser("g2-guest", guestDomainID)
	if _, err := pool.Exec(ctx,
		`INSERT INTO guest_accounts(user_id,invited_email,invited_by,invited_by_email,
		 host_domain_id,status,expires_at)
		 VALUES($1,$2,$3,$4,$5,'active',now()+interval '7 days')`,
		guestID, "outside-"+suffix+"@external.example", manageActorID,
		"g2-manage-"+suffix+"@example.test", hostDomainID); err != nil {
		t.Fatalf("insert guest account: %v", err)
	}

	var roleIDs []int64
	assign := func(actorID, domainID int64, perms []string) {
		t.Helper()
		var roleID int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO admin_role_groups(name,permissions,domain_scope)
			 VALUES($1,$2,$3) RETURNING id`, "g2-api-role-"+rolesTestRandomSuffix(t), perms, domainID).Scan(&roleID); err != nil {
			t.Fatalf("insert role: %v", err)
		}
		roleIDs = append(roleIDs, roleID)
		if _, err := pool.Exec(ctx,
			`INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by)
			 VALUES($1,$2,$1)`, actorID, roleID); err != nil {
			t.Fatalf("assign role: %v", err)
		}
	}
	assign(manageActorID, hostDomainID, []string{permissions.PermGuestsView, permissions.PermGuestsManage})
	assign(viewActorID, hostDomainID, []string{permissions.PermGuestsView})
	assign(otherActorID, otherDomainID, []string{permissions.PermGuestsView, permissions.PermGuestsManage})

	f := &guestProfileFixture{
		pool: pool, profiles: NewGuestProfilesHandler(pool, guestsOnFlags(), testsupport.TestLogger()),
		guests:        NewGuestsHandler(pool, guestsOnFlags(), nil, "", testsupport.TestLogger()),
		manageActorID: manageActorID, viewActorID: viewActorID, otherActorID: otherActorID,
		hostDomainID: hostDomainID, otherDomainID: otherDomainID, guestID: guestID, roleIDs: roleIDs,
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM user_app_entitlements WHERE user_id=$1`, guestID)
		pool.Exec(c, `DELETE FROM users WHERE id=$1`, guestID)
		pool.Exec(c, `DELETE FROM guest_profiles WHERE host_domain_id IN ($1,$2)`, hostDomainID, otherDomainID)
		for _, roleID := range roleIDs {
			pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id=$1`, roleID)
			pool.Exec(c, `DELETE FROM admin_role_groups WHERE id=$1`, roleID)
		}
		pool.Exec(c, `DELETE FROM users WHERE id=ANY($1)`, []int64{manageActorID, viewActorID, otherActorID})
		pool.Exec(c, `DELETE FROM domains WHERE id IN ($1,$2)`, hostDomainID, otherDomainID)
	})
	return f
}

func (f *guestProfileFixture) profileRequest(method, target, body string, claims *auth.Claims) *http.Request {
	return guestAdminRequest(method, target, body, claims)
}

func (f *guestProfileFixture) createProfile(t *testing.T, name string) int64 {
	t.Helper()
	body := fmt.Sprintf(`{"hostDomainId":%d,"name":%q,"canPost":true,"historyFromJoin":true,`+
		`"allowDownload":true,"allowMeetCreate":false,"allowMeetHost":false,`+
		`"canInitiateDm":false,"allowNativeShell":true,"defaultExpiryDays":30,"apps":["chat","drive"]}`,
		f.hostDomainID, name)
	rr := httptest.NewRecorder()
	f.profiles.Create(rr, f.profileRequest(http.MethodPost, "/admin/guest-profiles", body, guestManageClaims(f.manageActorID)))
	if rr.Code != http.StatusCreated {
		t.Fatalf("create profile: want 201, got %d: %s", rr.Code, rr.Body.String())
	}
	var out struct {
		ID int64 `json:"id"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || out.ID <= 0 {
		t.Fatalf("decode created profile: id=%d err=%v body=%s", out.ID, err, rr.Body.String())
	}
	return out.ID
}

func TestGuestProfilesHandler_CRUDAssignmentAndScope(t *testing.T) {
	f := newGuestProfileFixture(t)
	profileID := f.createProfile(t, "Collaborator")

	t.Run("view list", func(t *testing.T) {
		rr := httptest.NewRecorder()
		f.profiles.List(rr, f.profileRequest(http.MethodGet, "/admin/guest-profiles", "", guestViewClaims(f.viewActorID)))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"name":"Collaborator"`) {
			t.Fatalf("view list: got %d: %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("view lists only reachable local profile domains", func(t *testing.T) {
		rr := httptest.NewRecorder()
		f.profiles.Domains(rr, f.profileRequest(http.MethodGet, "/admin/guest-profile-domains", "", guestViewClaims(f.viewActorID)))
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), fmt.Sprintf(`"id":%d`, f.hostDomainID)) ||
			strings.Contains(rr.Body.String(), fmt.Sprintf(`"id":%d`, f.otherDomainID)) {
			t.Fatalf("domain scope list: got %d: %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("cross-domain profile is 404", func(t *testing.T) {
		req := f.profileRequest(http.MethodGet, fmt.Sprintf("/admin/guest-profiles/%d", profileID), "", guestManageClaims(f.otherActorID))
		req.SetPathValue("id", fmt.Sprint(profileID))
		rr := httptest.NewRecorder()
		f.profiles.Get(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("want cross-domain 404, got %d: %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("BZ224 is 422", func(t *testing.T) {
		body := fmt.Sprintf(`{"hostDomainId":%d,"name":" ","canPost":false,"historyFromJoin":false,`+
			`"allowDownload":false,"allowMeetCreate":false,"allowMeetHost":false,`+
			`"canInitiateDm":false,"allowNativeShell":false,"defaultExpiryDays":null,"apps":[]}`, f.hostDomainID)
		rr := httptest.NewRecorder()
		f.profiles.Create(rr, f.profileRequest(http.MethodPost, "/admin/guest-profiles", body, guestManageClaims(f.manageActorID)))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("want 422, got %d: %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("all-false profile with empty apps and null expiry is valid", func(t *testing.T) {
		body := fmt.Sprintf(`{"hostDomainId":%d,"name":"Restrictive","canPost":false,`+
			`"historyFromJoin":false,"allowDownload":false,"allowMeetCreate":false,`+
			`"allowMeetHost":false,"canInitiateDm":false,"allowNativeShell":false,`+
			`"defaultExpiryDays":null,"apps":[]}`, f.hostDomainID)
		rr := httptest.NewRecorder()
		f.profiles.Create(rr, f.profileRequest(http.MethodPost, "/admin/guest-profiles", body, guestManageClaims(f.manageActorID)))
		if rr.Code != http.StatusCreated {
			t.Fatalf("restrictive profile: want 201, got %d: %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("update", func(t *testing.T) {
		body := fmt.Sprintf(`{"hostDomainId":%d,"name":"Collaborator updated","canPost":false,`+
			`"historyFromJoin":true,"allowDownload":false,"allowMeetCreate":false,`+
			`"allowMeetHost":false,"canInitiateDm":false,"allowNativeShell":true,`+
			`"defaultExpiryDays":60,"apps":["chat","drive"]}`, f.hostDomainID)
		req := f.profileRequest(http.MethodPut, fmt.Sprintf("/admin/guest-profiles/%d", profileID),
			body, guestManageClaims(f.manageActorID))
		req.SetPathValue("id", fmt.Sprint(profileID))
		rr := httptest.NewRecorder()
		f.profiles.Update(rr, req)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"name":"Collaborator updated"`) {
			t.Fatalf("update: got %d: %s", rr.Code, rr.Body.String())
		}
	})
	t.Run("assign and detail", func(t *testing.T) {
		req := f.profileRequest(http.MethodPut, fmt.Sprintf("/admin/guests/%d/profile", f.guestID),
			fmt.Sprintf(`{"profileId":%d}`, profileID), guestManageClaims(f.manageActorID))
		req.SetPathValue("id", fmt.Sprint(f.guestID))
		rr := httptest.NewRecorder()
		f.guests.AssignProfile(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("assign: want 204, got %d: %s", rr.Code, rr.Body.String())
		}
		get := f.profileRequest(http.MethodGet, fmt.Sprintf("/admin/guests/%d", f.guestID), "", guestViewClaims(f.viewActorID))
		get.SetPathValue("id", fmt.Sprint(f.guestID))
		getRR := httptest.NewRecorder()
		f.guests.Get(getRR, get)
		if getRR.Code != http.StatusOK || !strings.Contains(getRR.Body.String(), fmt.Sprintf(`"profileId":%d`, profileID)) ||
			!strings.Contains(getRR.Body.String(), `"chat":true`) || !strings.Contains(getRR.Body.String(), `"drive":true`) {
			t.Fatalf("detail after assign: got %d: %s", getRR.Code, getRR.Body.String())
		}
	})
	t.Run("assigned delete is BZ225 conflict", func(t *testing.T) {
		req := f.profileRequest(http.MethodDelete, fmt.Sprintf("/admin/guest-profiles/%d", profileID), "", guestManageClaims(f.manageActorID))
		req.SetPathValue("id", fmt.Sprint(profileID))
		rr := httptest.NewRecorder()
		f.profiles.Delete(rr, req)
		if rr.Code != http.StatusConflict {
			t.Fatalf("want 409, got %d: %s", rr.Code, rr.Body.String())
		}
	})
}

func TestGuestProfileCreate_LocalDomainLockSerializesFlip(t *testing.T) {
	f := newGuestProfileFixture(t)
	ctx := context.Background()
	profileName := "Domain lock " + rolesTestRandomSuffix(t)

	createTx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin profile create: %v", err)
	}
	var profileID int64
	if err := createTx.QueryRow(ctx,
		`SELECT guest_profile_set($1,NULL,$2,$3,false,true,false,false,false,false,false,NULL,ARRAY[]::text[])`,
		f.manageActorID, f.hostDomainID, profileName).Scan(&profileID); err != nil {
		_ = createTx.Rollback(ctx)
		t.Fatalf("create profile under domain lock: %v", err)
	}

	flipper, err := f.pool.Acquire(ctx)
	if err != nil {
		_ = createTx.Rollback(ctx)
		t.Fatalf("acquire domain flipper: %v", err)
	}
	flipDone := make(chan error, 1)
	go func() {
		_, flipErr := flipper.Exec(context.Background(),
			`UPDATE domains SET is_local=FALSE WHERE id=$1`, f.hostDomainID)
		flipDone <- flipErr
	}()
	doneConsumed := false
	defer func() {
		_ = createTx.Rollback(context.Background())
		if !doneConsumed {
			select {
			case <-flipDone:
			case <-time.After(3 * time.Second):
			}
		}
		flipper.Release()
		_, _ = f.pool.Exec(context.Background(), `UPDATE domains SET is_local=TRUE WHERE id=$1`, f.hostDomainID)
	}()
	waitForBackendBlock(t, f.pool, flipper.Conn().PgConn().PID(), flipDone)

	if err := createTx.Commit(ctx); err != nil {
		t.Fatalf("commit create-first ordering: %v", err)
	}
	if err := <-flipDone; err != nil {
		doneConsumed = true
		t.Fatalf("complete local-domain flip: %v", err)
	}
	doneConsumed = true
	var exists, isLocal bool
	if err := f.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM guest_profiles WHERE id=$1),
		        (SELECT is_local FROM domains WHERE id=$2)`, profileID, f.hostDomainID).
		Scan(&exists, &isLocal); err != nil {
		t.Fatalf("read create-first final state: %v", err)
	}
	if !exists || isLocal {
		t.Fatalf("create-first ordering not preserved: profileExists=%v isLocal=%v", exists, isLocal)
	}

	if _, err := f.pool.Exec(ctx, `UPDATE domains SET is_local=FALSE WHERE id=$1`, f.hostDomainID); err != nil {
		t.Fatalf("prepare flip-first ordering: %v", err)
	}
	var rejectedID int64
	err = f.pool.QueryRow(ctx,
		`SELECT guest_profile_set($1,NULL,$2,$3,false,true,false,false,false,false,false,NULL,ARRAY[]::text[])`,
		f.manageActorID, f.hostDomainID, profileName+" rejected").Scan(&rejectedID)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "BZ170" {
		t.Fatalf("flip-first create: want BZ170, got id=%d err=%v", rejectedID, err)
	}
	var rejectedCount int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM guest_profiles WHERE name=$1`,
		profileName+" rejected").Scan(&rejectedCount); err != nil || rejectedCount != 0 {
		t.Fatalf("flip-first left profile count=%d err=%v", rejectedCount, err)
	}
}

func TestGuestsHandler_ListDetailStatusAndScope(t *testing.T) {
	f := newGuestProfileFixture(t)

	rr := httptest.NewRecorder()
	f.guests.List(rr, f.profileRequest(http.MethodGet, "/admin/guests", "", guestViewClaims(f.viewActorID)))
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), fmt.Sprintf(`"id":%d`, f.guestID)) ||
		!strings.Contains(rr.Body.String(), `"effectiveStatus":"active"`) {
		t.Fatalf("list: got %d: %s", rr.Code, rr.Body.String())
	}

	cross := f.profileRequest(http.MethodPost, fmt.Sprintf("/admin/guests/%d/disable", f.guestID), "", guestManageClaims(f.otherActorID))
	cross.SetPathValue("id", fmt.Sprint(f.guestID))
	crossRR := httptest.NewRecorder()
	f.guests.Disable(crossRR, cross)
	if crossRR.Code != http.StatusNotFound {
		t.Fatalf("cross-domain disable: want 404, got %d: %s", crossRR.Code, crossRR.Body.String())
	}

	disable := f.profileRequest(http.MethodPost, fmt.Sprintf("/admin/guests/%d/disable", f.guestID), "", guestManageClaims(f.manageActorID))
	disable.SetPathValue("id", fmt.Sprint(f.guestID))
	disableRR := httptest.NewRecorder()
	f.guests.Disable(disableRR, disable)
	if disableRR.Code != http.StatusNoContent {
		t.Fatalf("disable: want 204, got %d: %s", disableRR.Code, disableRR.Body.String())
	}

	enable := f.profileRequest(http.MethodPost, fmt.Sprintf("/admin/guests/%d/enable", f.guestID), "", guestManageClaims(f.manageActorID))
	enable.SetPathValue("id", fmt.Sprint(f.guestID))
	enableRR := httptest.NewRecorder()
	f.guests.Enable(enableRR, enable)
	if enableRR.Code != http.StatusNoContent {
		t.Fatalf("enable: want 204, got %d: %s", enableRR.Code, enableRR.Body.String())
	}

	wantExpiry := time.Now().UTC().Add(90 * 24 * time.Hour).Truncate(time.Second)
	extend := f.profileRequest(http.MethodPost, fmt.Sprintf("/admin/guests/%d/extend", f.guestID),
		fmt.Sprintf(`{"expiresAt":%q}`, wantExpiry.Format(time.RFC3339)), guestManageClaims(f.manageActorID))
	extend.SetPathValue("id", fmt.Sprint(f.guestID))
	extendRR := httptest.NewRecorder()
	f.guests.Extend(extendRR, extend)
	if extendRR.Code != http.StatusNoContent {
		t.Fatalf("extend: want 204, got %d: %s", extendRR.Code, extendRR.Body.String())
	}
	var gotExpiry time.Time
	if err := f.pool.QueryRow(context.Background(), `SELECT expires_at FROM guest_accounts WHERE user_id=$1`, f.guestID).Scan(&gotExpiry); err != nil {
		t.Fatalf("read extended expiry: %v", err)
	}
	if !gotExpiry.Equal(wantExpiry) {
		t.Fatalf("expiry mismatch: got %s want %s", gotExpiry, wantExpiry)
	}
}

func TestGuestsHandler_RequiresPersistedPermissionAndScopeOnSameAssignment(t *testing.T) {
	f := newGuestProfileFixture(t)
	ctx := context.Background()
	suffix := rolesTestRandomSuffix(t)

	var actorIDs []int64
	var roleIDs []int64
	createActor := func(label string) int64 {
		t.Helper()
		email := fmt.Sprintf("%s-%s@example.test", label, suffix)
		var id int64
		if err := f.pool.QueryRow(ctx,
			`INSERT INTO users(username,domain_id,email,display_name,enabled)
			 VALUES($1,$2,$1,$3,TRUE) RETURNING id`, email, f.hostDomainID, label).Scan(&id); err != nil {
			t.Fatalf("insert %s actor: %v", label, err)
		}
		actorIDs = append(actorIDs, id)
		return id
	}
	assign := func(actorID, domainID int64, permissions []string) {
		t.Helper()
		var roleID int64
		if err := f.pool.QueryRow(ctx,
			`INSERT INTO admin_role_groups(name,permissions,domain_scope)
			 VALUES($1,$2,$3) RETURNING id`,
			"g2-same-assignment-"+rolesTestRandomSuffix(t), permissions, domainID).Scan(&roleID); err != nil {
			t.Fatalf("insert split role: %v", err)
		}
		roleIDs = append(roleIDs, roleID)
		if _, err := f.pool.Exec(ctx,
			`INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by)
			 VALUES($1,$2,$1)`, actorID, roleID); err != nil {
			t.Fatalf("assign split role: %v", err)
		}
	}
	t.Cleanup(func() {
		c := context.Background()
		for _, roleID := range roleIDs {
			_, _ = f.pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id=$1`, roleID)
			_, _ = f.pool.Exec(c, `DELETE FROM admin_role_groups WHERE id=$1`, roleID)
		}
		_, _ = f.pool.Exec(c, `DELETE FROM users WHERE id=ANY($1)`, actorIDs)
	})

	// One assignment reaches the host domain but lacks guest permissions; the
	// other carries guest permissions but reaches only a foreign domain. JWT
	// claims alone must not compose those two insufficient persisted rows.
	splitActorID := createActor("g2-split")
	assign(splitActorID, f.hostDomainID, []string{permissions.PermUsersRead})
	assign(splitActorID, f.otherDomainID, []string{permissions.PermGuestsView, permissions.PermGuestsManage})

	// A claims-bearing actor with no persisted assignment is the revoked-role
	// shape: BYPASSRLS reads must still return no guest data.
	noRowActorID := createActor("g2-no-row")

	assertHidden := func(t *testing.T, actorID int64) {
		t.Helper()
		claims := guestManageClaims(actorID)

		listRR := httptest.NewRecorder()
		f.guests.List(listRR, f.profileRequest(http.MethodGet, "/admin/guests", "", claims))
		if listRR.Code != http.StatusOK {
			t.Fatalf("list status=%d body=%s", listRR.Code, listRR.Body.String())
		}
		var listed []json.RawMessage
		if err := json.Unmarshal(listRR.Body.Bytes(), &listed); err != nil {
			t.Fatalf("decode hidden list: %v", err)
		}
		if len(listed) != 0 {
			t.Fatalf("persistently unauthorized actor listed guest: %s", listRR.Body.String())
		}

		getReq := f.profileRequest(http.MethodGet, fmt.Sprintf("/admin/guests/%d", f.guestID), "", claims)
		getReq.SetPathValue("id", fmt.Sprint(f.guestID))
		getRR := httptest.NewRecorder()
		f.guests.Get(getRR, getReq)
		if getRR.Code != http.StatusNotFound {
			t.Fatalf("get status=%d, want 404; body=%s", getRR.Code, getRR.Body.String())
		}

		disableReq := f.profileRequest(http.MethodPost, fmt.Sprintf("/admin/guests/%d/disable", f.guestID), "", claims)
		disableReq.SetPathValue("id", fmt.Sprint(f.guestID))
		disableRR := httptest.NewRecorder()
		f.guests.Disable(disableRR, disableReq)
		if disableRR.Code != http.StatusNotFound {
			t.Fatalf("disable status=%d, want 404; body=%s", disableRR.Code, disableRR.Body.String())
		}
	}

	t.Run("permission and reach cannot compose across assignments", func(t *testing.T) {
		assertHidden(t, splitActorID)
	})
	t.Run("claims without a live persisted assignment read nothing", func(t *testing.T) {
		assertHidden(t, noRowActorID)
	})

	var status string
	if err := f.pool.QueryRow(ctx, `SELECT status FROM guest_accounts WHERE user_id=$1`, f.guestID).Scan(&status); err != nil {
		t.Fatalf("read guest status: %v", err)
	}
	if status != "active" {
		t.Fatalf("unauthorized status prechecks mutated guest: %s", status)
	}
}

func TestGuestsHandler_LifecycleRejectsElapsedExpiryWithoutMutation(t *testing.T) {
	f := newGuestProfileFixture(t)
	ctx := context.Background()
	past := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)

	beforeStatus := "active"
	var beforeExpiry time.Time
	if err := f.pool.QueryRow(ctx, `SELECT status,expires_at FROM guest_accounts WHERE user_id=$1`, f.guestID).
		Scan(&beforeStatus, &beforeExpiry); err != nil {
		t.Fatalf("read before extend: %v", err)
	}
	extend := f.profileRequest(http.MethodPost, fmt.Sprintf("/admin/guests/%d/extend", f.guestID),
		fmt.Sprintf(`{"expiresAt":%q}`, past.Format(time.RFC3339)), guestManageClaims(f.manageActorID))
	extend.SetPathValue("id", fmt.Sprint(f.guestID))
	extendRR := httptest.NewRecorder()
	f.guests.Extend(extendRR, extend)
	if extendRR.Code != http.StatusUnprocessableEntity {
		t.Fatalf("elapsed extend: want 422, got %d: %s", extendRR.Code, extendRR.Body.String())
	}
	var afterStatus string
	var afterExpiry time.Time
	if err := f.pool.QueryRow(ctx, `SELECT status,expires_at FROM guest_accounts WHERE user_id=$1`, f.guestID).
		Scan(&afterStatus, &afterExpiry); err != nil {
		t.Fatalf("read after extend: %v", err)
	}
	if afterStatus != beforeStatus || !afterExpiry.Equal(beforeExpiry) {
		t.Fatalf("elapsed extend mutated guest: before=(%s,%s) after=(%s,%s)", beforeStatus, beforeExpiry, afterStatus, afterExpiry)
	}

	if _, err := f.pool.Exec(ctx, `UPDATE guest_accounts SET status='disabled',expires_at=$2 WHERE user_id=$1`,
		f.guestID, past); err != nil {
		t.Fatalf("prepare elapsed enable: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE users SET enabled=FALSE WHERE id=$1`, f.guestID); err != nil {
		t.Fatalf("prepare elapsed enable user: %v", err)
	}
	enable := f.profileRequest(http.MethodPost, fmt.Sprintf("/admin/guests/%d/enable", f.guestID), "", guestManageClaims(f.manageActorID))
	enable.SetPathValue("id", fmt.Sprint(f.guestID))
	enableRR := httptest.NewRecorder()
	f.guests.Enable(enableRR, enable)
	if enableRR.Code != http.StatusUnprocessableEntity {
		t.Fatalf("elapsed enable: want 422, got %d: %s", enableRR.Code, enableRR.Body.String())
	}
	var enabled bool
	if err := f.pool.QueryRow(ctx, `SELECT g.status,u.enabled FROM guest_accounts g JOIN users u ON u.id=g.user_id WHERE g.user_id=$1`, f.guestID).
		Scan(&afterStatus, &enabled); err != nil {
		t.Fatalf("read after enable: %v", err)
	}
	if afterStatus != "disabled" || enabled {
		t.Fatalf("elapsed enable mutated guest: status=%s enabled=%v", afterStatus, enabled)
	}
}
