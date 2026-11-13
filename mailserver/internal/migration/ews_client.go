package migration

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/go-ntlmssp"
	"setjoin.com/shared/ssrf"
)

// errInvalidEWSScheme is returned when the EWS server URL is not HTTPS.
var errInvalidEWSScheme = errors.New("EWS server URL must use https scheme")

var errInvalidEWSSyncState = errors.New("EWS SyncState is invalid or expired")

var errEWSResponseTooLarge = errors.New("EWS response exceeds 16 MiB limit")

const ewsResponseMaxBytes int64 = 16 << 20

// validateEWSServerURL checks only that the EWS server URL is a well-formed
// http(s) URL with a host. It deliberately does NOT reject internal/private
// IPs: the EWS source host is an ADMIN-TRUSTED, internal-allowed migration
// source — on-prem Exchange is frequently on a private IP behind the firewall,
// so a blanket SSRF internal-IP guard (e.g. ssrf.ValidateURL) would break real
// on-prem EWS migration. We therefore reuse only the cheap scheme check to
// reject non-http(s) URLs (file://, ftp://, gopher://, …) that could otherwise
// be smuggled through the admin-set `ews.global` system_config value, and
// intentionally diverge from the SSRF dialer guard used by the
// newsletter/discover/webhook/JWKS/SAML paths. This divergence is deliberate,
// not an oversight.
func validateEWSServerURL(raw string, policy *ssrf.PrivatePolicy) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errInvalidEWSScheme
	}
	if u.Scheme != "https" {
		return errInvalidEWSScheme
	}
	if u.Hostname() == "" {
		return errInvalidEWSScheme
	}
	return ssrf.ValidateURLWithPrivatePolicy(raw, policy)
}

// EWSConfig holds connection parameters for an Exchange Web Services server.
type EWSConfig struct {
	ServerURL          string // https://exchange.example.com/EWS/Exchange.asmx
	Username           string // DOMAIN\user for NTLM
	Password           string
	ImpersonateAs      string // target SMTP for ExchangeImpersonation (empty = own mailbox)
	InsecureSkipVerify bool   // true = skip TLS verification (self-signed Exchange certs)
	PrivateHosts       []string
	PrivateCIDRs       []string
}

// distinguishedFolders lists all well-known Exchange folders to migrate.
var distinguishedFolders = []struct {
	ID       string
	ItemType SourceItemType
}{
	{"inbox", ItemMail},
	{"sentitems", ItemMail},
	{"drafts", ItemMail},
	{"deleteditems", ItemMail},
	{"junkemail", ItemMail},
	{"calendar", ItemCalendar},
	{"contacts", ItemContact},
}

type ewsFolder struct {
	ID          string
	DisplayName string
	ItemType    SourceItemType
	TotalCount  int
}

type ewsDeltaItem struct {
	MimeContent []byte
	ItemID      string
	ChangeKey   string
	IsDelete    bool
}

// EWSConnector fetches mail, calendar, and contacts from Exchange via EWS.
type EWSConnector struct {
	serverURL     string
	username      string
	password      string
	impersonateAs string
	httpClient    *http.Client
	syncStates    map[string]string
	legacyStates  map[string]string
	initErr       error
}

// NewEWSConnector creates an EWS connector with NTLM auth support.
//
// SSRF note: the httpClient below is a raw *http.Client with NO ssrf dialer
// guard, by design. The EWS server URL (EWSConfig.ServerURL, sourced from the
// admin-set `ews.global` system_config value) is an ADMIN-TRUSTED, internal-
// allowed migration source — on-prem Exchange usually lives on a private IP
// behind the firewall, so the post-DNS IP guard used by the newsletter/
// discover/webhook/JWKS/SAML paths would break legitimate on-prem migration.
// The construction-time defense is validateEWSServerURL (scheme-only check),
// applied where the untrusted config enters in the ewsFactory. InsecureSkipVerify
// is an explicit admin opt-in (default false).
func NewEWSConnector(cfg EWSConfig) *EWSConnector {
	policy, policyErr := ssrf.CompilePrivatePolicy(cfg.PrivateHosts, cfg.PrivateCIDRs)
	base := ssrf.SafeHTTPClientWithPrivatePolicy(5*time.Minute, policy)
	baseTransport := base.Transport.(*http.Transport).Clone()
	// NTLM is connection-oriented and Exchange rejects the multi-round handshake
	// when it is attempted over HTTP/2. Keep this connector on HTTP/1.1; the
	// shared safe transport remains HTTP/2-capable for other providers.
	baseTransport.ForceAttemptHTTP2 = false
	baseTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // explicit administrator profile opt-in
	baseTransport.ResponseHeaderTimeout = 60 * time.Second
	transport := &ntlmssp.Negotiator{
		RoundTripper: baseTransport,
	}
	return &EWSConnector{
		serverURL:     cfg.ServerURL,
		username:      cfg.Username,
		password:      cfg.Password,
		impersonateAs: cfg.ImpersonateAs,
		initErr:       policyErr,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   5 * time.Minute,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (e *EWSConnector) ResolveSourceIdentity(context.Context) (SourceIdentity, error) {
	selector := strings.TrimSpace(e.impersonateAs)
	if selector == "" {
		selector = strings.TrimSpace(e.username)
	}
	if selector == "" {
		return SourceIdentity{}, fmt.Errorf("EWS source mailbox selector is required")
	}
	digest := hashSourcePayload([]byte("ews\x00" + strings.ToLower(e.serverURL) + "\x00" + strings.ToLower(selector)))
	return SourceIdentity{SourceType: "ews", MailboxKey: "ews:" + digest, SelectorDigest: digest, SourceGeneration: 1}, nil
}

// TestConnection verifies connectivity by fetching the root inbox folder.
func (e *EWSConnector) TestConnection(ctx context.Context) error {
	_, err := e.soapRequest(ctx, e.buildGetFolderEnvelope("inbox"))
	return err
}

// FetchItems streams SourceItems from all folders.
func (e *EWSConnector) FetchItems(ctx context.Context, progress func(done, total int)) (<-chan SourceItem, <-chan error) {
	return e.FetchDeltaItems(ctx, nil, progress)
}

// FetchItemsCursor resumes from a previous cursor position.
func (e *EWSConnector) FetchItemsCursor(ctx context.Context, cursor map[string]int) (<-chan SourceItem, <-chan error) {
	if len(e.syncStates) > 0 {
		return e.FetchDeltaItems(ctx, e.syncStates, nil)
	}
	return e.FetchDeltaItems(ctx, nil, nil)
}

func (e *EWSConnector) SetDeltaLinks(links map[string]string) {
	e.syncStates = make(map[string]string, len(links))
	for k, v := range links {
		e.syncStates[k] = v
	}
}

func (e *EWSConnector) GetDeltaLinks() map[string]string {
	out := make(map[string]string, len(e.syncStates))
	for k, v := range e.syncStates {
		out[k] = v
	}
	return out
}

func (e *EWSConnector) RestoreSourceState(state SourceResumeState) error {
	links := make(map[string]string)
	for _, candidate := range state.Durable {
		if candidate.Kind != "ews_sync_state" {
			return rejectCheckpointKind(candidate, "ews_sync_state")
		}
		var value string
		if err := json.Unmarshal(candidate.Value, &value); err != nil || value == "" {
			return fmt.Errorf("restore EWS checkpoint %q: invalid sync state", candidate.Scope)
		}
		links[candidate.Scope] = value
	}
	e.SetDeltaLinks(links)
	e.legacyStates = cloneStringMap(state.LegacyDelta)
	return nil
}

func (e *EWSConnector) IterateSource(ctx context.Context) *SourceBatchStream {
	return newSourceBatchStream(ctx, e.iterateEWSBatches)
}

func ewsBatchSnapshot(scope, syncState string) SourceCheckpointSnapshot {
	return SourceCheckpointSnapshot{
		Candidates: []SourceCheckpointCandidate{{
			Scope: scope, LegacyScope: scope, Kind: "ews_sync_state", Value: jsonMarshal(syncState),
		}},
		LegacyPatch: map[string]any{"delta": map[string]string{scope: syncState}},
	}
}

func (e *EWSConnector) iterateEWSBatches(ctx context.Context, emit sourceBatchEmitter) error {
	folders, err := e.discoverFolders(ctx)
	if err != nil {
		return err
	}
	resumeByID, err := e.resolveEWSResumeStates(folders)
	if err != nil {
		return err
	}
	for _, folder := range folders {
		prevState := resumeByID[folder.ID]
		resetAttempted := false
		for {
			resp, err := e.soapRequest(ctx, e.buildSyncFolderItemsEnvelope(folder.ID, prevState, sourceBatchSize))
			if err != nil {
				return fmt.Errorf("SyncFolderItems %s: %w", folder.ID, err)
			}
			deltaItems, newState, includesLast, err := e.parseSyncFolderItemsResponse(resp)
			if err != nil {
				if errors.Is(err, errInvalidEWSSyncState) && prevState != "" && !resetAttempted {
					prevState = ""
					resetAttempted = true
					continue
				}
				return fmt.Errorf("parse SyncFolderItems %s: %w", folder.ID, err)
			}
			if newState == "" {
				return fmt.Errorf("SyncFolderItems %s omitted SyncState", folder.ID)
			}
			fetchIDs := make([]string, 0, len(deltaItems))
			for _, delta := range deltaItems {
				if delta.ItemID == "" {
					return fmt.Errorf("SyncFolderItems %s returned change without ItemId", folder.ID)
				}
				if !delta.IsDelete {
					fetchIDs = append(fetchIDs, delta.ItemID)
				}
			}
			fetched := make(map[string]SourceItem, len(fetchIDs))
			for i := 0; i < len(fetchIDs); i += 50 {
				ids := fetchIDs[i:]
				if len(ids) > 50 {
					ids = ids[:50]
				}
				getResp, err := e.soapRequest(ctx, e.buildGetItemEnvelope(ids))
				if err != nil {
					return fmt.Errorf("GetItem delta %s: %w", folder.ID, err)
				}
				parsed := e.parseMimeContent(getResp, folder.ItemType)
				if len(parsed) != len(ids) {
					return fmt.Errorf("GetItem delta %s returned %d of %d items", folder.ID, len(parsed), len(ids))
				}
				for _, item := range parsed {
					item.Change = SourceUpsert
					item.SourceFolderID = folder.ID
					item.FolderPath = []string{folder.DisplayName}
					item.Tags = []string{folderTag(folder.ID)}
					fetched[item.SourceObjectID] = item
				}
			}
			batchItems := make([]SourceItem, 0, len(deltaItems))
			for _, delta := range deltaItems {
				if delta.IsDelete {
					batchItems = append(batchItems, SourceItem{
						Type: folder.ItemType, Change: SourceDelete, SourceObjectID: delta.ItemID,
						SourceVersion: delta.ChangeKey, SourceFolderID: folder.ID,
						FolderPath: []string{folder.DisplayName},
					})
					continue
				}
				item, ok := fetched[delta.ItemID]
				if !ok {
					return fmt.Errorf("GetItem delta %s omitted item %s", folder.ID, delta.ItemID)
				}
				batchItems = append(batchItems, item)
			}
			snapshot := ewsBatchSnapshot(folder.ID, newState)
			snapshot.Candidates[0].LegacyScope = folder.DisplayName
			// Old binaries address EWS state by display name. The durable cursor
			// remains bound to the provider's stable folder ID.
			snapshot.LegacyPatch = map[string]any{"delta": map[string]string{folder.DisplayName: newState}}
			if err := emit(SourceBatch{Items: batchItems, Candidate: snapshot}); err != nil {
				return err
			}
			prevState = newState
			if includesLast {
				break
			}
		}
	}
	return nil
}

func (e *EWSConnector) resolveEWSResumeStates(folders []ewsFolder) (map[string]string, error) {
	resumeByID := cloneStringMap(e.syncStates)
	for _, folder := range folders {
		legacy, ok := e.legacyStates[folder.DisplayName]
		if !ok {
			continue
		}
		for _, other := range folders {
			if other.ID != folder.ID && other.DisplayName == folder.DisplayName {
				return nil, fmt.Errorf("EWS legacy checkpoint display name %q is ambiguous", folder.DisplayName)
			}
		}
		if durable := resumeByID[folder.ID]; durable != "" && durable != legacy {
			return nil, fmt.Errorf("EWS durable and legacy checkpoints disagree for folder %q", folder.ID)
		}
		resumeByID[folder.ID] = legacy
	}
	return resumeByID, nil
}

// FetchDeltaItems performs incremental sync using SyncFolderItems for each folder.
// syncStates maps folder distinguished IDs to the previous SyncState values.
func (e *EWSConnector) FetchDeltaItems(ctx context.Context, syncStates map[string]string, progress func(done, total int)) (<-chan SourceItem, <-chan error) {
	items := make(chan SourceItem, 100)
	errs := make(chan error, 1)

	// Background migration goroutine — uses context.Background() for long-running operations.
	go func() {
		defer close(items)
		defer close(errs)

		folders, err := e.discoverFolders(ctx)
		if err != nil {
			errs <- err
			return
		}

		var done, total int
		if progress != nil {
			progress(0, len(folders))
		}

		for _, folder := range folders {
			if syncStates != nil {
				if _, ok := syncStates[folder.DisplayName]; !ok {
					continue
				}
			}
			prevState := ""
			resetAttempted := false
			if syncStates != nil {
				prevState = syncStates[folder.DisplayName]
			}
			for {
				resp, err := e.soapRequest(ctx, e.buildSyncFolderItemsEnvelope(folder.ID, prevState, 100))
				if err != nil {
					errs <- fmt.Errorf("SyncFolderItems %s: %w", folder.ID, err)
					return
				}

				deltaItems, newState, includesLast, err := e.parseSyncFolderItemsResponse(resp)
				if err != nil {
					if errors.Is(err, errInvalidEWSSyncState) && prevState != "" && !resetAttempted {
						// One bounded full-folder reconciliation. The final replacement
						// SyncState is published only after all emitted objects commit.
						prevState = ""
						resetAttempted = true
						continue
					}
					errs <- fmt.Errorf("parse SyncFolderItems %s: %w", folder.ID, err)
					return
				}
				if newState == "" {
					errs <- fmt.Errorf("SyncFolderItems %s omitted SyncState", folder.ID)
					return
				}

				var fetchIDs []string
				for _, di := range deltaItems {
					if di.ItemID == "" {
						errs <- fmt.Errorf("SyncFolderItems %s returned change without ItemId", folder.ID)
						return
					}
					if di.IsDelete {
						select {
						case items <- SourceItem{Type: folder.ItemType, Change: SourceDelete,
							SourceObjectID: di.ItemID, SourceVersion: di.ChangeKey,
							SourceFolderID: folder.ID, FolderPath: []string{folder.DisplayName}}:
						case <-ctx.Done():
							errs <- ctx.Err()
							return
						}
					} else {
						fetchIDs = append(fetchIDs, di.ItemID)
					}
				}

				for i := 0; i < len(fetchIDs); i += 50 {
					batch := fetchIDs[i:]
					if len(batch) > 50 {
						batch = batch[:50]
					}
					getResp, err := e.soapRequest(ctx, e.buildGetItemEnvelope(batch))
					if err != nil {
						errs <- fmt.Errorf("GetItem delta %s: %w", folder.ID, err)
						return
					}
					parsed := e.parseMimeContent(getResp, folder.ItemType)
					if len(parsed) != len(batch) {
						errs <- fmt.Errorf("GetItem delta %s returned %d of %d items", folder.ID, len(parsed), len(batch))
						return
					}
					for _, item := range parsed {
						item.Change = SourceUpsert
						item.SourceFolderID = folder.ID
						item.FolderPath = []string{folder.DisplayName}
						item.Tags = []string{folderTag(folder.ID)}
						select {
						case items <- item:
							done++
							if progress != nil {
								progress(done, total)
							}
						case <-ctx.Done():
							errs <- ctx.Err()
							return
						}
					}
				}

				prevState = newState
				if includesLast {
					if e.syncStates == nil {
						e.syncStates = make(map[string]string)
					}
					e.syncStates[folder.DisplayName] = newState
					break
				}
			}
		}
	}()

	return items, errs
}

// discoverFolders finds all distinguished folders and returns their IDs.
func (e *EWSConnector) discoverFolders(ctx context.Context) ([]ewsFolder, error) {
	var folders []ewsFolder
	for _, df := range distinguishedFolders {
		resp, err := e.soapRequest(ctx, e.buildGetFolderEnvelope(df.ID))
		if err != nil {
			// Folder might not exist — skip
			continue
		}
		// Parse FolderId from response
		id := e.parseFolderID(resp, df.ID)
		if id != "" {
			folders = append(folders, ewsFolder{
				ID:          id,
				DisplayName: df.ID,
				ItemType:    df.ItemType,
			})
		}
	}
	return folders, nil
}

// parseFolderID extracts the FolderId from a GetFolder SOAP response.
func (e *EWSConnector) parseFolderID(resp []byte, distinguishedID string) string {
	s := string(resp)
	// Find <t:FolderId Id="..." /> in the response
	start := strings.Index(s, `<t:FolderId`)
	if start < 0 {
		return ""
	}
	idStart := strings.Index(s[start:], `Id="`)
	if idStart < 0 {
		return ""
	}
	idStart += start + 4
	idEnd := strings.Index(s[idStart:], `"`)
	if idEnd < 0 {
		return ""
	}
	return s[idStart : idStart+idEnd]
}

// impersonationHeader returns the ExchangeImpersonation SOAP header XML, or empty string.
func (e *EWSConnector) impersonationHeader() string {
	if e.impersonateAs == "" {
		return ""
	}
	return fmt.Sprintf(
		`<t:ExchangeImpersonation><t:ConnectingSID><t:PrimarySmtpAddress>%s</t:PrimarySmtpAddress></t:ConnectingSID></t:ExchangeImpersonation>`,
		html.EscapeString(e.impersonateAs),
	)
}

func (e *EWSConnector) requestHeaders() string {
	return `<t:RequestServerVersion Version="Exchange2016"/>` + e.impersonationHeader()
}

// buildGetItemEnvelope builds a GetItem SOAP request for specific item IDs.
func (e *EWSConnector) buildGetItemEnvelope(itemIDs []string) string {
	requestHeaders := e.requestHeaders()
	var itemIDXML strings.Builder
	for _, id := range itemIDs {
		itemIDXML.WriteString(fmt.Sprintf(`<t:ItemId Id="%s"/>`, id))
	}
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header>%s</soap:Header>
  <soap:Body>
    <m:GetItem>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:IncludeMimeContent>true</t:IncludeMimeContent>
      </m:ItemShape>
      <m:ItemIds>%s</m:ItemIds>
    </m:GetItem>
  </soap:Body>
</soap:Envelope>`, requestHeaders, itemIDXML.String())
}

// buildSyncFolderItemsEnvelope builds a SyncFolderItems SOAP request for delta sync.
// An empty syncState requests a full sync for that folder.
func (e *EWSConnector) buildSyncFolderItemsEnvelope(folderID, syncState string, maxChanges int) string {
	requestHeaders := e.requestHeaders()
	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header>%s</soap:Header>
  <soap:Body>
    <m:SyncFolderItems>
      <m:ItemShape>
        <t:BaseShape>IdOnly</t:BaseShape>
        <t:IncludeMimeContent>true</t:IncludeMimeContent>
      </m:ItemShape>
      <m:SyncFolderId>
        <t:FolderId Id="%s"/>
      </m:SyncFolderId>
      <m:SyncState>%s</m:SyncState>
      <m:MaxChangesReturned>%d</m:MaxChangesReturned>
    </m:SyncFolderItems>
  </soap:Body>
</soap:Envelope>`, requestHeaders, folderID, syncState, maxChanges)
}

// parseMimeContent extracts MIME content from a GetItem SOAP response.
func (e *EWSConnector) parseMimeContent(resp []byte, itemType SourceItemType) []SourceItem {
	var items []SourceItem
	s := string(resp)
	tags := []string{"Message", "MeetingMessage", "MeetingRequest", "MeetingResponse", "MeetingCancellation", "PostItem"}
	switch itemType {
	case ItemCalendar:
		tags = []string{"CalendarItem"}
	case ItemContact:
		tags = []string{"Contact"}
	}
	for {
		start, tag := -1, ""
		for _, candidate := range tags {
			candidateStart := strings.Index(s, "<t:"+candidate)
			if candidateStart >= 0 && (start < 0 || candidateStart < start) {
				start, tag = candidateStart, candidate
			}
		}
		if start < 0 {
			break
		}
		closeTag := "</t:" + tag + ">"
		end := strings.Index(s[start:], closeTag)
		if end < 0 {
			break
		}
		block := s[start : start+end+len(closeTag)]
		itemID := ewsXMLAttr(block, "Id")
		changeKey := ewsXMLAttr(block, "ChangeKey")
		mimeStart := strings.Index(block, `<t:MimeContent`)
		if itemID != "" && mimeStart >= 0 {
			contentStart := strings.Index(block[mimeStart:], `>`)
			contentEnd := strings.Index(block[mimeStart:], `</t:MimeContent>`)
			if contentStart >= 0 && contentEnd > contentStart {
				payload := decodeEWSPayload(block[mimeStart+contentStart+1 : mimeStart+contentEnd])
				item := SourceItem{Type: itemType, Change: SourceUpsert,
					SourceObjectID: itemID, SourceVersion: changeKey}
				switch itemType {
				case ItemMail:
					item.RawMIME = payload
				case ItemCalendar:
					item.RawICS = string(payload)
				case ItemContact:
					item.RawVCF = string(payload)
				}
				items = append(items, item)
			}
		}
		s = s[start+end+len(closeTag):]
	}
	return items
}

func ewsXMLAttr(fragment, name string) string {
	needle := name + `="`
	start := strings.Index(fragment, needle)
	if start < 0 {
		return ""
	}
	start += len(needle)
	end := strings.Index(fragment[start:], `"`)
	if end < 0 {
		return ""
	}
	return html.UnescapeString(fragment[start : start+end])
}

func decodeEWSPayload(value string) []byte {
	value = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, html.UnescapeString(value))
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded
	}
	return []byte(html.UnescapeString(value))
}

// parseSyncFolderItemsResponse extracts delta items and the new SyncState.
func (e *EWSConnector) parseSyncFolderItemsResponse(resp []byte) ([]ewsDeltaItem, string, bool, error) {
	s := string(resp)
	if strings.Contains(s, "ErrorInvalidSyncStateData") ||
		strings.Contains(s, "ErrorInvalidWatermark") {
		return nil, "", false, errInvalidEWSSyncState
	}
	if strings.Contains(s, `ResponseClass="Error"`) {
		return nil, "", false, fmt.Errorf("EWS SyncFolderItems returned an error response")
	}

	// Extract SyncState
	ssStart := strings.Index(s, "<m:SyncState>")
	ssEnd := strings.Index(s, "</m:SyncState>")
	newSyncState := ""
	if ssStart >= 0 && ssEnd > ssStart {
		newSyncState = s[ssStart+13 : ssEnd]
	}

	items := make([]ewsDeltaItem, 0)
	remaining := s
	for {
		createIdx := strings.Index(remaining, "<t:Create>")
		updateIdx := strings.Index(remaining, "<t:Update>")
		deleteIdx := strings.Index(remaining, "<t:Delete>")

		// Find the earliest element
		idx := -1
		isDelete := false
		closeTag := ""
		switch {
		case createIdx >= 0 && (updateIdx < 0 || createIdx < updateIdx) && (deleteIdx < 0 || createIdx < deleteIdx):
			idx = createIdx
			closeTag = "</t:Create>"
		case updateIdx >= 0 && (deleteIdx < 0 || updateIdx < deleteIdx):
			idx = updateIdx
			closeTag = "</t:Update>"
		case deleteIdx >= 0:
			idx = deleteIdx
			closeTag = "</t:Delete>"
			isDelete = true
		}

		if idx < 0 {
			break
		}

		closeIdx := strings.Index(remaining[idx:], closeTag)
		if closeIdx < 0 {
			break
		}
		element := remaining[idx : idx+closeIdx+len(closeTag)]

		if isDelete {
			items = append(items, ewsDeltaItem{IsDelete: true,
				ItemID: ewsXMLAttr(element, "Id"), ChangeKey: ewsXMLAttr(element, "ChangeKey")})
		} else {
			di := ewsDeltaItem{ItemID: ewsXMLAttr(element, "Id"), ChangeKey: ewsXMLAttr(element, "ChangeKey")}
			// Extract ItemId
			idStart := strings.Index(element, `<t:ItemId`)
			if idStart >= 0 {
				idAttrStart := strings.Index(element[idStart:], `Id="`)
				if idAttrStart >= 0 {
					idAttrStart += idStart + 4
					idAttrEnd := strings.Index(element[idAttrStart:], `"`)
					if idAttrEnd >= 0 {
						di.ItemID = element[idAttrStart : idAttrStart+idAttrEnd]
					}
				}
			}
			// Extract MIME content (may be empty if Exchange doesn't include it)
			mimeStart := strings.Index(element, "<t:MimeContent")
			if mimeStart >= 0 {
				contentStart := strings.Index(element[mimeStart:], ">") + 1
				contentEnd := strings.Index(element[mimeStart:], "</t:MimeContent>")
				if contentEnd > contentStart {
					di.MimeContent = []byte(element[mimeStart+contentStart : mimeStart+contentEnd])
				}
			}
			items = append(items, di)
		}

		remaining = remaining[idx+len(element):]
	}

	includesLast := strings.Contains(s, `IncludesLastItemInRange="true"`) ||
		strings.Contains(s, `<m:IncludesLastItemInRange>true</m:IncludesLastItemInRange>`)
	return items, newSyncState, includesLast, nil
}

// folderTag maps distinguished folder IDs to system tag names.
func folderTag(folderID string) string {
	switch folderID {
	case "inbox":
		return ""
	case "sentitems":
		return "Sent"
	case "drafts":
		return "Drafts"
	case "deleteditems":
		return "Trash"
	case "junkemail":
		return "Spam"
	default:
		return ""
	}
}

// buildGetFolderEnvelope builds a SOAP XML envelope for GetFolder with optional impersonation.
func (e *EWSConnector) buildGetFolderEnvelope(distinguishedID string) string {
	requestHeaders := e.requestHeaders()

	return fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
  <soap:Header>
    %s
  </soap:Header>
  <soap:Body>
    <m:GetFolder>
      <m:FolderShape>
        <t:BaseShape>Default</t:BaseShape>
      </m:FolderShape>
      <m:FolderIds>
        <t:DistinguishedFolderId Id="%s"/>
      </m:FolderIds>
    </m:GetFolder>
  </soap:Body>
</soap:Envelope>`, requestHeaders, distinguishedID)
}

// soapRequest sends a SOAP envelope and returns the raw response body.
// Falls back to Basic auth if NTLM returns 401.
func (e *EWSConnector) soapRequest(ctx context.Context, envelope string) ([]byte, error) {
	if e.initErr != nil {
		return nil, fmt.Errorf("invalid EWS source policy: %w", e.initErr)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", e.serverURL, strings.NewReader(envelope))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.SetBasicAuth(e.username, e.password)

	if e.impersonateAs != "" {
		req.Header.Set("X-AnchorMailbox", e.impersonateAs)
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ews request: %w", err)
	}
	defer resp.Body.Close()

	if resp.ContentLength > ewsResponseMaxBytes {
		return nil, errEWSResponseTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, ewsResponseMaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("ews read body: %w", err)
	}
	if int64(len(body)) > ewsResponseMaxBytes {
		return nil, errEWSResponseTooLarge
	}

	if resp.StatusCode >= 400 {
		// EWS error documents can contain mailbox/server details and may be as
		// large as the response ceiling. Do not copy them into errors/logs.
		return nil, fmt.Errorf("EWS HTTP %d", resp.StatusCode)
	}

	return body, nil
}
