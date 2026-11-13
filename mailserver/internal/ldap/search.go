package ldap

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	message "github.com/vjeantet/goldap/message"
	ldapserver "github.com/vjeantet/ldapserver"
	"setjoin.com/shared/identity"
)

// addAttr adds an attribute to a search result entry, respecting typesOnly.
// When typesOnly is true, attribute values are omitted per RFC 4511 §4.5.1.
func addAttr(e *message.SearchResultEntry, typesOnly bool, name string, values ...string) {
	dn := message.AttributeDescription(name)
	if typesOnly {
		e.AddAttribute(dn)
		return
	}
	vals := make([]message.AttributeValue, len(values))
	for i, v := range values {
		vals[i] = message.AttributeValue(v)
	}
	e.AddAttribute(dn, vals...)
}

// addAttrIf adds an attribute subject to the attribute filter list and typesOnly.
func addAttrIf(e *message.SearchResultEntry, typesOnly bool, hasFilter bool, attrs []string, name string, values ...string) {
	if hasFilter && !hasAttr(attrs, name) {
		return
	}
	addAttr(e, typesOnly, name, values...)
}

// findPagedResultsControl looks through request controls for a SimplePagedResultsControl
// (RFC 2696, OID 1.2.840.113556.1.4.319). Returns the parsed control or nil if not present.
func findPagedResultsControl(msg *ldapserver.Message) *pagedResultsControl {
	controls := msg.Controls()
	if controls == nil {
		return nil
	}
	for _, c := range *controls {
		if string(c.ControlType()) == pagedResultsOID {
			val := c.ControlValue()
			if val == nil {
				return nil
			}
			parsed, err := parsePagedResultsControl([]byte(*val))
			if err != nil {
				return nil
			}
			return parsed
		}
	}
	return nil
}

// decodeCookie decodes a pagingCookie from raw bytes (JSON).
func decodeCookie(raw []byte) pagingCookie {
	var c pagingCookie
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &c)
	}
	return c
}

// boundPrincipal returns the typed identity minted only by handleBind after a
// successful password check. A bool-only marker is deliberately not accepted.
func boundPrincipal(m *ldapserver.Message) (BoundPrincipal, bool) {
	principal, ok := m.Client.GetData().(BoundPrincipal)
	return principal, ok && principal.UserID > 0
}

// isBound reports whether this connection completed a successful Bind.
func isBound(m *ldapserver.Message) bool {
	_, ok := boundPrincipal(m)
	return ok
}

func (s *Server) boundMailboxID(ctx context.Context, m *ldapserver.Message) (int64, error) {
	principal, ok := boundPrincipal(m)
	if !ok {
		return 0, identity.ErrNoPrimaryMailbox
	}
	return identity.ResolvePrimaryMailbox(ctx, s.pool, principal.UserID)
}

// handleSearch routes LDAP search requests to the appropriate handler.
func (s *Server) handleSearch(w ldapserver.ResponseWriter, msg *ldapserver.Message) {
	if !isBound(msg) {
		s.logger.Warn("ldap search rejected: no authenticated bind on this connection")
		res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultInsufficientAccessRights)
		w.Write(res)
		return
	}

	r := msg.GetSearchRequest()
	baseDN := string(r.BaseObject())
	scope := int(r.Scope())
	filter := r.FilterString()
	attrs := []string{}
	for _, a := range r.Attributes() {
		attrs = append(attrs, string(a))
	}
	if len(attrs) == 0 {
		attrs = []string{"cn", "mail", "displayName", "objectClass"}
	}
	typesOnly := bool(r.TypesOnly())

	sizeLimit := effectivePageSize(int(r.SizeLimit()))

	// RFC 2696 Simple Paged Results — if client sent a paged results control,
	// use its pageSize and cookie to resume the paged search. The control's
	// pageSize is CLIENT-OWNED input: it runs through the SAME
	// effectivePageSize cap as the SizeLimit field, so a paged control can
	// never lift the enforced 1000-entry search cap (a pre-fix handler copied
	// the control's raw int32 pageSize into sizeLimit, letting one control
	// value turn every capped search into a full-directory scan).
	pageCtrl := findPagedResultsControl(msg)
	var pageCookie pagingCookie
	if pageCtrl != nil {
		sizeLimit = effectivePageSize(int(pageCtrl.pageSize))
		pageCookie = sanitizePagingCookie(decodeCookie(pageCtrl.cookie))
		s.logger.Debug("ldap paged results control",
			"pageSize", pageCtrl.pageSize,
			"cookieOffset", pageCookie.Offset,
		)
	}

	if r.DerefAliases() > 0 {
		s.logger.Debug("ldap derefAliases requested but not supported (no alias entries)", "deref", r.DerefAliases())
	}

	ou, _ := dnToFilter(baseDN, s.baseDN)
	ctx, cancel := requestContext(s.baseCtx, msg, 30*time.Second)
	defer cancel()
	if tl := r.TimeLimit(); tl > 0 && tl < 30 {
		ctx, cancel = requestContext(s.baseCtx, msg, time.Duration(tl)*time.Second)
		defer cancel()
	}

	switch ou {
	case "root":
		s.searchRoot(w, baseDN, scope, attrs, typesOnly)
	case "people":
		deptPath := ""
		if scope == 2 { //nolint:staticcheck
			deptPath = extractDeptPath(baseDN, s.baseDN, "people")
		}
		s.searchPeople(ctx, w, msg, baseDN, scope, filter, attrs, typesOnly, sizeLimit, deptPath, pageCookie)
	case "groups":
		s.searchGroups(ctx, w, msg, baseDN, scope, filter, attrs, typesOnly, sizeLimit, pageCookie)
	case "resources":
		s.searchResources(ctx, w, msg, baseDN, scope, filter, attrs, typesOnly, sizeLimit, pageCookie)
	case "contacts":
		s.searchContacts(ctx, w, msg, baseDN, scope, filter, attrs, typesOnly, sizeLimit, pageCookie)
	default:
		e := ldapserver.NewSearchResultEntry(baseDN)
		w.Write(e)
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
	}
}

func (s *Server) searchRoot(w ldapserver.ResponseWriter, baseDN string, scope int, attrs []string, typesOnly bool) {
	if scope == 0 { //nolint:staticcheck // baseObject (int scope, tagged switch not clearer)
		e := ldapserver.NewSearchResultEntry(baseDN)
		addAttr(&e, typesOnly, "objectClass", "top", "dcObject", "organization")
		addAttr(&e, typesOnly, "dc", strings.TrimPrefix(strings.Split(baseDN, ",")[0], "dc="))
		addAttr(&e, typesOnly, "o", s.domain)
		w.Write(e)
	} else if scope == 1 { // singleLevel
		for _, ou := range []string{"People", "Groups", "Resources", "Contacts"} {
			e := ldapserver.NewSearchResultEntry(fmt.Sprintf("ou=%s,%s", ou, baseDN))
			addAttr(&e, typesOnly, "objectClass", "top", "organizationalUnit")
			addAttr(&e, typesOnly, "ou", ou)
			w.Write(e)
		}
	}
	w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
}

// pagedSearch runs the shared subtree-search loop for every OU: abandon
// (msg.Done) checks, RFC 2696 size-limit enforcement, rows.Err logging, and the
// final Done response — ctx-deadline → TimeLimitExceeded, else Success.
// buildEntry scans one row and builds its SearchResultEntry (the one real
// per-OU difference: which columns and which attr mapping); a non-nil error
// skips that row. Owns closing rows.
//
// Folded-in bug fix (house rule): searchPeople previously omitted the
// ctx.DeadlineExceeded → TimeLimitExceeded check that groups/resources/contacts
// had, so a People search that hit its time limit mid-scan returned a bare
// Success. Routing all four through this one helper fixes that drift.
func (s *Server) pagedSearch(ctx context.Context, w ldapserver.ResponseWriter, msg *ldapserver.Message, limit int, rows pgx.Rows, buildEntry func(pgx.Rows) (message.SearchResultEntry, error)) {
	defer rows.Close()
	count := 0
	for rows.Next() {
		select {
		case <-msg.Done:
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
			return
		default:
		}
		e, err := buildEntry(rows)
		if err != nil {
			continue
		}
		count++
		if count > limit {
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSizeLimitExceeded))
			return
		}
		w.Write(e)
	}
	if err := rows.Err(); err != nil {
		s.logger.Error("ldap search rows error", "error", err)
	}
	if ctx.Err() == context.DeadlineExceeded {
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultTimeLimitExceeded))
		return
	}
	w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
}

// singleEntrySearch runs a scope==0 (base-object, by-CN) lookup: at most one
// matching row, written if buildEntry returns ok, then a Success Done. A query
// error yields OperationsError. buildEntry scans and builds the entry for the
// OU (its scope==0 attribute set is a subset of the subtree set, so it is a
// distinct closure from the pagedSearch one).
func (s *Server) singleEntrySearch(ctx context.Context, w ldapserver.ResponseWriter, query string, args []interface{}, buildEntry func(pgx.Rows) (message.SearchResultEntry, bool, error)) {
	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultOperationsError))
		return
	}
	defer rows.Close()
	for rows.Next() {
		e, ok, err := buildEntry(rows)
		if err != nil || !ok {
			continue
		}
		w.Write(e)
	}
	w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
}

func (s *Server) searchPeople(ctx context.Context, w ldapserver.ResponseWriter, msg *ldapserver.Message, baseDN string, scope int, filter string, attrs []string, typesOnly bool, limit int, deptPath string, cookie pagingCookie) {
	hasAttrFilter := len(attrs) > 0
	callerMailboxID, err := s.boundMailboxID(ctx, msg)
	if err != nil {
		principal, _ := boundPrincipal(msg)
		s.logger.Error("ldap people search caller scope resolution failed", "user_id", principal.UserID, "error", err)
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultOperationsError))
		return
	}

	if scope == 0 {
		cn := extractRDNValue(baseDN, "cn")
		if cn == "" {
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
			return
		}
		q := `SELECT v.id, v.email, v.display_name, COALESCE(v.first_name, ''), COALESCE(v.last_name, ''),
			 COALESCE(v.phone, ''), COALESCE(v.job_title, ''), COALESCE(v.dept_name, ''), COALESCE(v.avatar_sha256, '')
			 FROM directory_visible_users($1) v
			 WHERE (LOWER(v.display_name) = LOWER($2)
			    OR EXISTS (SELECT 1 FROM jsonb_array_elements(v.addresses) address
			               WHERE LOWER(SPLIT_PART(address->>'email', '@', 1)) = LOWER($2)
			                  OR LOWER(address->>'email') = LOWER($2)))
			 LIMIT 1`
		s.singleEntrySearch(ctx, w, q, []interface{}{callerMailboxID, cn}, func(rows pgx.Rows) (message.SearchResultEntry, bool, error) {
			var id int64
			var email, displayName, firstName, lastName, phone, jobTitle, deptName, avatarSHA256 string
			if err := rows.Scan(&id, &email, &displayName, &firstName, &lastName, &phone, &jobTitle, &deptName, &avatarSHA256); err != nil {
				return message.SearchResultEntry{}, false, err
			}
			e := ldapserver.NewSearchResultEntry(userToDN(id, email, deptName, s.baseDN))
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "cn", strings.Split(email, "@")[0])
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "mail", email)
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "displayname", displayName)
			return e, true, nil
		})
		return
	}

	q := `SELECT v.id, v.email, v.display_name, COALESCE(v.first_name, ''), COALESCE(v.last_name, ''),
		 COALESCE(v.phone, ''), COALESCE(v.job_title, ''), COALESCE(v.dept_name, ''), COALESCE(v.avatar_sha256, '')
		 FROM directory_visible_users($1) v
		 LEFT JOIN departments d ON d.id = v.department_id
		 WHERE TRUE`
	args := []interface{}{callerMailboxID}
	argIdx := 1

	// Subtree scope: filter by department path
	if deptPath != "" {
		argIdx++
		q += fmt.Sprintf(" AND (d.path = $%d OR d.path LIKE $%d)", argIdx, argIdx+1)
		args = append(args, deptPath, deptPath+"/%")
		argIdx++
	}

	filterSQL, filterArgs := applyFilter(filter, argIdx, "people")
	if filterSQL != "" {
		q += " AND (" + filterSQL + ")"
		args = append(args, filterArgs...)
	}

	args = append(args, limit+1, cookie.Offset)
	q += fmt.Sprintf(" ORDER BY v.display_name LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ldap people search failed", "error", err)
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultOperationsError))
		return
	}
	s.pagedSearch(ctx, w, msg, limit, rows, func(rows pgx.Rows) (message.SearchResultEntry, error) {
		var id int64
		var email, displayName, firstName, lastName, phone, jobTitle, deptName, avatarSHA256 string
		if err := rows.Scan(&id, &email, &displayName, &firstName, &lastName, &phone, &jobTitle, &deptName, &avatarSHA256); err != nil {
			return message.SearchResultEntry{}, err
		}
		e := ldapserver.NewSearchResultEntry(userToDN(id, email, deptName, s.baseDN))
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "cn", strings.Split(email, "@")[0])
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "displayname", displayName)
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "givenname", firstName)
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "sn", lastName)
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "mail", email)
		if phone != "" {
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "telephonenumber", phone)
		}
		if jobTitle != "" {
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "title", jobTitle)
		}
		if deptName != "" {
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "ou", deptName)
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "department", deptName)
		}
		if avatarSHA256 != "" {
			addAttrIf(&e, typesOnly, false, nil, "jpegPhoto", fmt.Sprintf("/blobs/%s", avatarSHA256))
		}
		return e, nil
	})
}

func hasAttr(attrs []string, name string) bool {
	for _, a := range attrs {
		if strings.EqualFold(a, name) {
			return true
		}
	}
	return false
}

func (s *Server) searchGroups(ctx context.Context, w ldapserver.ResponseWriter, msg *ldapserver.Message, baseDN string, scope int, filter string, attrs []string, typesOnly bool, limit int, cookie pagingCookie) {
	hasAttrFilter := len(attrs) > 0

	if scope == 0 {
		cn := extractRDNValue(baseDN, "cn")
		if cn == "" {
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
			return
		}
		// distribution_groups carries no name/email of its own — the group's
		// identity lives on its mailbox (mailbox_id FK), so join mailboxes for
		// display_name (name) and email.
		q := `SELECT dg.id, m.display_name, m.email
			 FROM distribution_groups dg
			 JOIN mailboxes m ON m.id = dg.mailbox_id
			 WHERE m.display_name ILIKE $1 LIMIT 1`
		s.singleEntrySearch(ctx, w, q, []interface{}{cn}, func(rows pgx.Rows) (message.SearchResultEntry, bool, error) {
			var id int64
			var name, email string
			if err := rows.Scan(&id, &name, &email); err != nil {
				return message.SearchResultEntry{}, false, err
			}
			e := ldapserver.NewSearchResultEntry(groupToDN(id, name, s.baseDN))
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "objectClass", "top", "groupOfNames")
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "cn", name)
			if email != "" {
				addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "mail", email)
			}
			return e, true, nil
		})
		return
	}
	q := `SELECT dg.id, m.display_name, m.email
		 FROM distribution_groups dg
		 JOIN mailboxes m ON m.id = dg.mailbox_id
		 WHERE 1=1`
	args := []interface{}{}

	filterSQL, filterArgs := applyFilter(filter, 0, "groups")
	if filterSQL != "" {
		q += " AND (" + filterSQL + ")"
		args = append(args, filterArgs...)
	}
	args = append(args, limit+1, cookie.Offset)
	q += fmt.Sprintf(" ORDER BY m.display_name LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ldap groups search failed", "error", err)
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultOperationsError))
		return
	}
	s.pagedSearch(ctx, w, msg, limit, rows, func(rows pgx.Rows) (message.SearchResultEntry, error) {
		var id int64
		var name, email string
		if err := rows.Scan(&id, &name, &email); err != nil {
			return message.SearchResultEntry{}, err
		}
		e := ldapserver.NewSearchResultEntry(groupToDN(id, name, s.baseDN))
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "objectClass", "top", "groupOfNames")
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "cn", name)
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "displayname", name)
		if email != "" {
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "mail", email)
		}
		return e, nil
	})
}

func (s *Server) searchResources(ctx context.Context, w ldapserver.ResponseWriter, msg *ldapserver.Message, baseDN string, scope int, filter string, attrs []string, typesOnly bool, limit int, cookie pagingCookie) {
	hasAttrFilter := len(attrs) > 0

	if scope == 0 {
		cn := extractRDNValue(baseDN, "cn")
		if cn == "" {
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
			return
		}
		q := `SELECT id, display_name, email FROM mailboxes WHERE resource_type IS NOT NULL AND enabled = TRUE AND display_name ILIKE $1 LIMIT 1`
		s.singleEntrySearch(ctx, w, q, []interface{}{cn}, func(rows pgx.Rows) (message.SearchResultEntry, bool, error) {
			var id int64
			var name, email string
			if err := rows.Scan(&id, &name, &email); err != nil {
				return message.SearchResultEntry{}, false, err
			}
			e := ldapserver.NewSearchResultEntry(resourceToDN(id, name, s.baseDN))
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "objectClass", "top", "room", "inetOrgPerson")
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "cn", name)
			if email != "" {
				addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "mail", email)
			}
			return e, true, nil
		})
		return
	}
	q := `SELECT id, display_name, email FROM mailboxes WHERE resource_type IS NOT NULL AND enabled = TRUE`
	args := []interface{}{}

	filterSQL, filterArgs := applyFilter(filter, 0, "resources")
	if filterSQL != "" {
		q += " AND (" + filterSQL + ")"
		args = append(args, filterArgs...)
	}
	args = append(args, limit+1, cookie.Offset)
	q += fmt.Sprintf(" ORDER BY display_name LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ldap resources search failed", "error", err)
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultOperationsError))
		return
	}
	s.pagedSearch(ctx, w, msg, limit, rows, func(rows pgx.Rows) (message.SearchResultEntry, error) {
		var id int64
		var name, email string
		if err := rows.Scan(&id, &name, &email); err != nil {
			return message.SearchResultEntry{}, err
		}
		e := ldapserver.NewSearchResultEntry(resourceToDN(id, name, s.baseDN))
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "objectClass", "top", "room", "inetOrgPerson")
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "cn", name)
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "displayname", name)
		if email != "" {
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "mail", email)
		}
		return e, nil
	})
}

func (s *Server) searchContacts(ctx context.Context, w ldapserver.ResponseWriter, msg *ldapserver.Message, baseDN string, scope int, filter string, attrs []string, typesOnly bool, limit int, cookie pagingCookie) {
	hasAttrFilter := len(attrs) > 0

	if scope == 0 {
		cn := extractRDNValue(baseDN, "cn")
		if cn == "" {
			w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess))
			return
		}
		q := `SELECT c.id, c.display_name, COALESCE(c.first_name, ''), COALESCE(c.last_name, ''),
		 COALESCE(c.company, ''), COALESCE(c.job_title, ''), COALESCE(c.department, ''), COALESCE(c.avatar_sha256, '')
		 FROM contacts c JOIN addressbooks ab ON ab.id = c.addressbook_id JOIN mailboxes m ON m.id = ab.mailbox_id
		 WHERE c.display_name ILIKE $1 AND ab.is_shared = TRUE LIMIT 1`
		s.singleEntrySearch(ctx, w, q, []interface{}{cn}, func(rows pgx.Rows) (message.SearchResultEntry, bool, error) {
			var id int64
			var displayName, firstName, lastName, company, jobTitle, department, avatarSHA256 string
			if err := rows.Scan(&id, &displayName, &firstName, &lastName, &company, &jobTitle, &department, &avatarSHA256); err != nil {
				return message.SearchResultEntry{}, false, err
			}
			e := ldapserver.NewSearchResultEntry(contactToDN(id, displayName, s.baseDN))
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "cn", displayName)
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "displayname", displayName)
			return e, true, nil
		})
		return
	}
	q := `SELECT c.id, c.display_name, COALESCE(c.first_name, ''), COALESCE(c.last_name, ''), COALESCE(c.company, ''),
		 COALESCE(c.job_title, ''), COALESCE(c.department, ''), COALESCE(c.avatar_sha256, '')
		 FROM contacts c
		 JOIN addressbooks ab ON ab.id = c.addressbook_id
		 JOIN mailboxes m ON m.id = ab.mailbox_id
		 WHERE ab.is_shared = TRUE`
	args := []interface{}{}

	filterSQL, filterArgs := applyFilter(filter, 0, "contacts")
	if filterSQL != "" {
		q += " AND (" + filterSQL + ")"
		args = append(args, filterArgs...)
	}
	args = append(args, limit+1, cookie.Offset)
	q += fmt.Sprintf(" ORDER BY c.display_name LIMIT $%d OFFSET $%d", len(args)-1, len(args))

	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		s.logger.Error("ldap contacts search failed", "error", err)
		w.Write(ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultOperationsError))
		return
	}
	s.pagedSearch(ctx, w, msg, limit, rows, func(rows pgx.Rows) (message.SearchResultEntry, error) {
		var id int64
		var displayName, firstName, lastName, company, jobTitle, department, avatarSHA256 string
		if err := rows.Scan(&id, &displayName, &firstName, &lastName, &company, &jobTitle, &department, &avatarSHA256); err != nil {
			return message.SearchResultEntry{}, err
		}
		e := ldapserver.NewSearchResultEntry(contactToDN(id, displayName, s.baseDN))
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "objectClass", "top", "person", "organizationalPerson", "inetOrgPerson")
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "cn", displayName)
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "displayname", displayName)
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "givenname", firstName)
		addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "sn", lastName)
		if company != "" {
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "o", company)
		}
		if jobTitle != "" {
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "title", jobTitle)
		}
		if department != "" {
			addAttrIf(&e, typesOnly, hasAttrFilter, attrs, "department", department)
		}
		if avatarSHA256 != "" {
			addAttrIf(&e, typesOnly, false, nil, "jpegPhoto", fmt.Sprintf("/blobs/%s", avatarSHA256))
		}
		return e, nil
	})
}

// requestContext derives the work context for one LDAP operation: bounded by
// the server base context and the operation timeout, and — critically —
// cancelled as soon as the operation is abandoned or its connection tears
// down. The library signals msg.Done from client.close for every registered
// request (and from client.serve's abandon path), so a search whose connection
// dies releases its SQL work at cancellation speed instead of running to the
// SQL context timeout: the timeout is not the bound.
func requestContext(base context.Context, m *ldapserver.Message, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(base, timeout)
	go func() {
		select {
		case <-m.Done:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// handleCompare processes LDAP Compare requests (RFC 4511 §4.10).
func (s *Server) handleCompare(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	if !isBound(m) {
		s.logger.Warn("ldap compare rejected: no authenticated bind on this connection")
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultInsufficientAccessRights)
		w.Write(res)
		return
	}

	r := m.GetCompareRequest()
	dn := string(r.Entry())

	ou, _ := dnToFilter(dn, s.baseDN)
	ctx, cancel := requestContext(s.baseCtx, m, 15*time.Second)
	defer cancel()

	cn := extractRDNValue(dn, "cn")
	if cn == "" {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	ava := r.Ava()
	attrName := strings.ToLower(string(ava.AttributeDesc()))
	assertValue := string(ava.AssertionValue())

	var dbValue string
	var peopleMailMatch *bool
	var err error
	switch ou {
	case "people":
		callerMailboxID, scopeErr := s.boundMailboxID(ctx, m)
		if scopeErr != nil {
			principal, _ := boundPrincipal(m)
			s.logger.Error("ldap people compare caller scope resolution failed", "user_id", principal.UserID, "error", scopeErr)
			w.Write(ldapserver.NewCompareResponse(ldapserver.LDAPResultOperationsError))
			return
		}
		q := `SELECT LOWER(v.display_name), LOWER(v.email), COALESCE(LOWER(v.last_name), ''), COALESCE(LOWER(v.first_name), ''),
			COALESCE(LOWER(v.phone), ''), COALESCE(LOWER(v.job_title), ''),
			EXISTS (SELECT 1 FROM jsonb_array_elements(v.addresses) asserted
			        WHERE LOWER(asserted->>'email') = LOWER($3))
			FROM directory_visible_users($1) v
			WHERE LOWER(v.display_name) = LOWER($2)
			   OR EXISTS (SELECT 1 FROM jsonb_array_elements(v.addresses) address
			              WHERE LOWER(SPLIT_PART(address->>'email', '@', 1)) = LOWER($2)
			                 OR LOWER(address->>'email') = LOWER($2))
			LIMIT 1`
		var dsp, em, sn, gn, phone, title string
		var mailMatch bool
		err = s.pool.QueryRow(ctx, q, callerMailboxID, cn, assertValue).Scan(&dsp, &em, &sn, &gn, &phone, &title, &mailMatch)
		dbValue = lkpAttr(attrName, dsp, em, sn, gn, phone, title)
		if attrName == "mail" {
			peopleMailMatch = &mailMatch
		}
	case "groups":
		q := `SELECT LOWER(m.display_name), LOWER(m.email)
			FROM distribution_groups dg
			JOIN mailboxes m ON m.id = dg.mailbox_id
			WHERE m.display_name ILIKE $1 LIMIT 1`
		var name, em string
		err = s.pool.QueryRow(ctx, q, cn).Scan(&name, &em)
		dbValue = lkpAttr(attrName, name, em, "", "", "", "")
	case "resources":
		q := `SELECT LOWER(display_name), LOWER(email) FROM mailboxes WHERE resource_type IS NOT NULL AND enabled = TRUE AND display_name ILIKE $1 LIMIT 1`
		var name, em string
		err = s.pool.QueryRow(ctx, q, cn).Scan(&name, &em)
		dbValue = lkpAttr(attrName, name, em, "", "", "", "")
	case "contacts":
		q := `SELECT LOWER(c.display_name), '', COALESCE(LOWER(c.last_name), ''), COALESCE(LOWER(c.first_name), ''),
			COALESCE(LOWER(c.company), ''), COALESCE(LOWER(c.job_title), '')
			FROM contacts c JOIN addressbooks ab ON ab.id = c.addressbook_id
			WHERE c.display_name ILIKE $1 AND ab.is_shared = TRUE LIMIT 1`
		var dsp, em, sn, gn, comp, title string
		err = s.pool.QueryRow(ctx, q, cn).Scan(&dsp, &em, &sn, &gn, &comp, &title)
		dbValue = lkpAttr(attrName, dsp, em, sn, gn, comp, title)
	default:
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultNoSuchObject)
		w.Write(res)
		return
	}

	if err != nil || (dbValue == "" && peopleMailMatch == nil) {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultNoSuchAttribute)
		w.Write(res)
		return
	}

	if peopleMailMatch != nil && *peopleMailMatch {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
		w.Write(res)
	} else if peopleMailMatch != nil {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareFalse)
		w.Write(res)
	} else if dbValue == strings.ToLower(assertValue) {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareTrue)
		w.Write(res)
	} else {
		res := ldapserver.NewCompareResponse(ldapserver.LDAPResultCompareFalse)
		w.Write(res)
	}
}

func lkpAttr(attr string, cn, mail, sn, givenName, phone, title string) string {
	switch attr {
	case "cn":
		return cn
	case "mail":
		return mail
	case "sn":
		return sn
	case "givenname":
		return givenName
	case "displayname":
		return cn
	case "telephonenumber":
		return phone
	case "title":
		return title
	default:
		return cn
	}
}

// ── Filter parsing (unchanged below) ──

// FilterNode represents a node in the LDAP filter tree (RFC 4511 §4.5.1).
type FilterNode struct {
	Kind     string // "and", "or", "not", "equality", "substring", "present", "approxMatch"
	Attr     string
	Value    string
	Children []FilterNode
}

// parseFilter parses an RFC 4515 filter string into a tree. A nil node means
// "match everything" (empty filter or (objectClass=*)).
//
// Filter-byte bounds: length and paren nesting are pre-validated in one linear
// pass BEFORE any structural parsing, so attacker-controlled filter bytes can
// never drive parseFilterExpr/matchParen through O(n·depth) rescans or
// unbounded recursion (CWE-400). The bounds are surfaced ops tunables sized
// far above every documented client shape (Outlook/Thunderbird GAL queries
// nest ≤ 4 levels and stay well under 1 KiB). Over-limit and malformed filters
// follow the package's existing error semantics: applyFilter drops the term
// and the search matches everything (visibility-scoped and size-limit-bounded
// exactly like the (objectClass=*) wildcard).
const (
	maxLDAPFilterBytes = 8192
	maxLDAPFilterDepth = 32
)

func parseFilter(filter string) (*FilterNode, error) {
	filter = strings.TrimSpace(filter)
	if len(filter) == 0 || filter == "(objectClass=*)" {
		return nil, nil // wildcard: return everything
	}
	if filter[0] != '(' { // tolerate a bare assertion without the outer parens
		filter = "(" + filter + ")"
	}
	if len(filter) > maxLDAPFilterBytes {
		return nil, fmt.Errorf("filter exceeds %d bytes", maxLDAPFilterBytes)
	}
	// One linear pass rejects over-deep or unbalanced bytes before any
	// structural parsing; the scan exits at the first violation, so adversarial
	// input costs time proportional to the bytes read so far, never the parse.
	depth := 0
	for i := 0; i < len(filter); i++ {
		switch filter[i] {
		case '(':
			depth++
			if depth > maxLDAPFilterDepth {
				return nil, fmt.Errorf("filter nesting exceeds %d levels", maxLDAPFilterDepth)
			}
		case ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("unbalanced parentheses: %q", filter)
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("unbalanced parentheses: %q", filter)
	}
	node, _, err := parseFilterExpr(filter)
	return node, err
}

// matchParen returns the index of the ')' that closes the '(' at s[0], or -1 if
// the parentheses are unbalanced. It runs only on filter bytes already
// validated by parseFilter (length ≤ maxLDAPFilterBytes, nesting ≤
// maxLDAPFilterDepth), so the per-node rescan is bounded at
// maxLDAPFilterBytes × maxLDAPFilterDepth — the O(n·depth) unbounded case on
// attacker bytes is unreachable.
func matchParen(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// parseFilterExpr parses one parenthesized filter item beginning at expr[0]=='('
// and returns the node plus the number of bytes consumed (including both
// parens). It handles nested boolean groups (&/|/!) by recursing on each
// already-parenthesized child — the shape real Outlook/Thunderbird GAL queries
// use, e.g. (&(objectClass=*)(|(cn=jo*)(mail=jo*))).
func parseFilterExpr(expr string) (*FilterNode, int, error) {
	if len(expr) < 2 || expr[0] != '(' {
		return nil, 0, fmt.Errorf("expected '(' at start of filter item: %q", expr)
	}
	end := matchParen(expr)
	if end < 0 {
		return nil, 0, fmt.Errorf("unbalanced parentheses: %q", expr)
	}
	consumed := end + 1
	inner := strings.TrimSpace(expr[1:end])
	if len(inner) == 0 {
		return nil, 0, fmt.Errorf("empty filter item: %q", expr)
	}

	if inner[0] == '&' || inner[0] == '|' || inner[0] == '!' {
		kind := "and"
		switch inner[0] {
		case '|':
			kind = "or"
		case '!':
			kind = "not"
		}
		node := &FilterNode{Kind: kind}
		rest := strings.TrimSpace(inner[1:])
		for len(rest) > 0 && rest[0] == '(' {
			child, n, err := parseFilterExpr(rest)
			if err != nil {
				return nil, 0, err
			}
			node.Children = append(node.Children, *child)
			rest = strings.TrimSpace(rest[n:])
		}
		if len(node.Children) == 0 {
			return nil, 0, fmt.Errorf("boolean operator with no children: %q", inner)
		}
		return node, consumed, nil
	}

	return parseAssertion(inner), consumed, nil
}

// parseAssertion parses a single attribute assertion with no surrounding parens,
// e.g. "cn=jo*", "mail=a@b", "title>=5", or a bare "cn".
func parseAssertion(assertion string) *FilterNode {
	node := &FilterNode{Kind: "present"}
	for _, op := range []string{">=", "<=", "~=", "="} {
		parts := strings.SplitN(assertion, op, 2)
		if len(parts) != 2 {
			continue
		}
		node.Attr = strings.ToLower(strings.TrimSpace(parts[0]))
		node.Value = stripAsterisks(strings.TrimSpace(parts[1]))
		switch {
		case op == "~=":
			node.Kind = "approxMatch"
		case op == ">=":
			node.Kind = "greaterOrEqual"
		case op == "<=":
			node.Kind = "lessOrEqual"
		case strings.Contains(parts[1], "*") && parts[1] != "*":
			node.Kind = "substring"
		case parts[1] == "*":
			node.Kind = "presence"
		default:
			node.Kind = "equality"
		}
		return node
	}
	node.Attr = strings.ToLower(strings.TrimSpace(assertion))
	return node
}

func stripAsterisks(s string) string { return strings.ReplaceAll(s, "*", "") }

// filterToSQL converts a parsed filter tree to SQL WHERE clauses for the given
// OU's table (ou selects the per-table column map; see attrToColumn).
func filterToSQL(node *FilterNode, baseIdx int, ou string) (string, []interface{}) {
	if node == nil {
		return "", nil
	}
	switch node.Kind {
	case "and", "or":
		joiner := " AND "
		if node.Kind == "or" {
			joiner = " OR "
		}
		var parts []string
		var allArgs []interface{}
		for _, child := range node.Children {
			childSQL, childArgs := filterToSQL(&child, baseIdx+len(allArgs), ou)
			if childSQL != "" {
				parts = append(parts, "("+childSQL+")")
				allArgs = append(allArgs, childArgs...)
			}
		}
		if len(parts) == 0 {
			return "", nil
		}
		return strings.Join(parts, joiner), allArgs
	case "not":
		if len(node.Children) == 0 {
			return "", nil
		}
		childSQL, childArgs := filterToSQL(&node.Children[0], baseIdx, ou)
		if childSQL == "" {
			return "", nil
		}
		return fmt.Sprintf("NOT (%s)", childSQL), childArgs
	case "equality", "present", "substring", "approxMatch":
		return attrSQL(ou, node.Attr, node.Value, node.Kind, baseIdx)
	}
	return "", nil
}

// attrSQL maps a single LDAP attribute assertion to a parameterized SQL
// condition for the given OU's table. It returns ("", nil) when the attribute
// has no column on that table (e.g. objectClass, or mail on contacts), so the
// term is dropped — treated as matching everything — instead of emitting a
// reference to a non-existent column that would fail the whole query.
func attrSQL(ou, attr, value, kind string, baseIdx int) (string, []interface{}) {
	if ou == "people" && attr == "mail" {
		if value == "" {
			return "COALESCE(v.address_blob, '') <> ''", nil
		}
		idx := baseIdx + 1
		if kind == "substring" || kind == "approxMatch" {
			return fmt.Sprintf("v.address_blob ILIKE $%d", idx), []interface{}{"%" + value + "%"}
		}
		return fmt.Sprintf("EXISTS (SELECT 1 FROM jsonb_array_elements(v.addresses) address WHERE LOWER(address->>'email') = LOWER($%d))", idx), []interface{}{value}
	}
	col, isLike, ok := attrToColumn(ou, attr)
	if !ok {
		return "", nil
	}
	if value == "" { // presence filter
		return col + " IS NOT NULL", nil
	}
	if isLike || kind == "substring" {
		idx := baseIdx + 1
		return fmt.Sprintf("%s ILIKE $%d", col, idx), []interface{}{"%" + value + "%"}
	}
	idx := baseIdx + 1
	return fmt.Sprintf("LOWER(%s) = LOWER($%d)", col, idx), []interface{}{value}
}

type ldapCol struct {
	col  string
	like bool // matched with ILIKE %v% rather than exact LOWER()=LOWER()
}

// attrColsByOU maps an LDAP attribute (lowercased) to its real SQL column,
// per OU. Each OU searches a different table with a different shape, so a single
// flat map would reference columns absent from the target table. Columns are
// table-qualified to match the FROM/JOIN aliases in each search query. An
// attribute with no entry for an OU is dropped by attrToColumn (ok=false):
// objectClass exists on no table, and contacts have no scalar email column
// (contacts.emails is jsonb), so those terms match everything rather than error.
var attrColsByOU = map[string]map[string]ldapCol{
	"people": { // FROM directory_visible_users($1) v LEFT JOIN departments d
		"cn":              {"v.display_name", true},
		"displayname":     {"v.display_name", true},
		"sn":              {"v.last_name", true},
		"givenname":       {"v.first_name", true},
		"telephonenumber": {"v.phone", true},
		"title":           {"v.job_title", true},
		"ou":              {"d.name", true},
		"department":      {"d.name", true},
	},
	"groups": { // FROM distribution_groups dg JOIN mailboxes m
		"cn":          {"m.display_name", true},
		"displayname": {"m.display_name", true},
		"mail":        {"m.email", false},
	},
	"resources": { // FROM mailboxes (no alias)
		"cn":          {"display_name", true},
		"displayname": {"display_name", true},
		"mail":        {"email", false},
	},
	"contacts": { // FROM contacts c JOIN addressbooks ab JOIN mailboxes m
		"cn":          {"c.display_name", true},
		"displayname": {"c.display_name", true},
		"sn":          {"c.last_name", true},
		"givenname":   {"c.first_name", true},
		"title":       {"c.job_title", true},
		"o":           {"c.company", true},
		"company":     {"c.company", true},
		"ou":          {"c.department", true},
		"department":  {"c.department", true},
	},
}

// attrToColumn maps an LDAP attribute to a SQL column for the given OU's table.
// ok=false means the attribute has no column there (the caller drops the term).
func attrToColumn(ou, attr string) (col string, isLike, ok bool) {
	c, found := attrColsByOU[ou][attr]
	if !found {
		return "", false, false
	}
	return c.col, c.like, true
}

// ── RFC 2696 Simple Paged Results — deferred (goldap library no control support) ──

type pagingCookie struct {
	Offset int    `json:"o"`
	LastDN string `json:"dn,omitempty"`
}

// maxLDAPSearchSizeLimit is the enforced per-search entry cap. It bounds both
// the client's SizeLimit field and the RFC 2696 paged-results control's
// pageSize (see effectivePageSize): one server-wide cap no client-controlled
// field can lift.
const maxLDAPSearchSizeLimit = 1000

// effectivePageSize clamps a client-supplied page/size request to
// [1, maxLDAPSearchSizeLimit]. Zero, negative, and over-cap requests all
// resolve to the server cap (the pre-control behavior for SizeLimit), so a
// paged-results control or SizeLimit field can never widen a search beyond
// maxLDAPSearchSizeLimit entries.
func effectivePageSize(requested int) int {
	if requested <= 0 || requested > maxLDAPSearchSizeLimit {
		return maxLDAPSearchSizeLimit
	}
	return requested
}

// sanitizePagingCookie normalizes a client-supplied paging cookie. The Offset
// reaches SQL as a bound OFFSET parameter: a negative value is a query error
// (OperationsError per search), so it is clamped to 0 — a hostile cookie
// degrades to "resume from the start", never to a failing query.
func sanitizePagingCookie(c pagingCookie) pagingCookie {
	if c.Offset < 0 {
		c.Offset = 0
	}
	return c
}

// applyFilter adds filter SQL to an existing query for the given OU's table.
func applyFilter(filter string, baseIdx int, ou string) (string, []interface{}) {
	tree, err := parseFilter(filter)
	if err != nil || tree == nil {
		return "", nil
	}
	return filterToSQL(tree, baseIdx, ou)
}
