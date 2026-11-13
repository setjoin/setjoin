package migration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	abs "github.com/microsoft/kiota-abstractions-go"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

// M365Connector fetches data from Microsoft 365 via Graph API.
type M365Connector struct {
	cfg             MigrationM365Config
	client          *msgraphsdkgo.GraphServiceClient
	includeMail     bool
	includeCalendar bool
	includeContacts bool
	deltaLinks      map[string]string // per-user/folder delta links for incremental sync
	tokens          oauth2.TokenSource
}

var errM365DeltaReset = errors.New("Microsoft Graph delta token expired")

type graphHTTPError struct {
	Status int
	Body   string
}

func (e *graphHTTPError) Error() string {
	return fmt.Sprintf("Graph returned %d: %s", e.Status, e.Body)
}

// NewM365Connector creates a connector for the given M365 config.
func NewM365Connector(ctx context.Context, cfg MigrationM365Config) (*M365Connector, error) {
	c := &M365Connector{
		cfg:             cfg,
		includeMail:     true,
		includeCalendar: true,
		includeContacts: true,
	}

	cc := clientcredentials.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		TokenURL:     c.authEndpoint() + "/" + cfg.TenantID + "/oauth2/v2.0/token",
		Scopes:       []string{c.graphEndpoint() + "/.default"},
	}

	tokens := cc.TokenSource(ctx)
	adapter, err := msgraphsdkgo.NewGraphRequestAdapter(&m365AuthProvider{ts: tokens})
	if err != nil {
		return nil, fmt.Errorf("create graph adapter: %w", err)
	}

	adapter.SetBaseUrl(c.graphEndpoint() + "/v1.0")

	c.client = msgraphsdkgo.NewGraphServiceClient(adapter)
	c.tokens = tokens
	return c, nil
}

func (c *M365Connector) authEndpoint() string {
	if c.cfg.Cloud == "china" {
		return "https://login.chinacloudapi.cn"
	}
	return "https://login.microsoftonline.com"
}

func (c *M365Connector) graphEndpoint() string {
	if c.cfg.Cloud == "china" {
		return "https://microsoftgraph.chinacloudapi.cn"
	}
	return "https://graph.microsoft.com"
}

// TestConnection verifies the token and Graph API connectivity.
func (c *M365Connector) TestConnection(ctx context.Context) error {
	top := int32(1)
	resp, err := c.client.Users().Get(ctx, &users.UsersRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UsersRequestBuilderGetQueryParameters{
			Top: &top,
		},
	})
	if err != nil {
		return fmt.Errorf("graph test connection: %w", err)
	}
	vals := resp.GetValue()
	if len(vals) == 0 {
		return fmt.Errorf("no users found in tenant — verify permissions")
	}
	return nil
}

// FetchItems performs a full migration from M365.
func (c *M365Connector) FetchItems(ctx context.Context, progress func(done, total int)) (<-chan SourceItem, <-chan error) {
	itemCh := make(chan SourceItem, 100)
	errCh := make(chan error, 1)

	// Background migration goroutine — uses context.Background() for long-running operations.
	go func() {
		defer close(itemCh)
		defer close(errCh)

		if err := c.fetchInitialItems(ctx, itemCh, progress); err != nil {
			errCh <- err
		}
	}()

	return itemCh, errCh
}

func (c *M365Connector) fetchInitialItems(ctx context.Context, itemCh chan<- SourceItem, progress func(done, total int)) error {
	userID, err := c.resolveSourceUser(ctx)
	if err != nil {
		return err
	}
	if c.includeMail {
		if err := c.fetchMailInitialDelta(ctx, userID, itemCh); err != nil {
			return fmt.Errorf("fetch mail: %w", err)
		}
	}
	if c.includeCalendar {
		if err := c.fetchCalendar(ctx, userID, itemCh); err != nil {
			return fmt.Errorf("fetch calendar: %w", err)
		}
	}
	if c.includeContacts {
		if err := c.fetchContactsInitial(ctx, userID, itemCh); err != nil {
			return fmt.Errorf("fetch contacts: %w", err)
		}
	}
	if progress != nil {
		progress(1, 1)
	}
	return nil
}

// resolveSourceUser converts the explicit mailbox selector into the immutable
// Graph user id. A migration job is one source mailbox; tenant enumeration is
// never a valid fallback.
func (c *M365Connector) resolveSourceUser(ctx context.Context) (string, error) {
	if immutableID := strings.TrimSpace(c.cfg.SourceUserID); immutableID != "" {
		return immutableID, nil
	}
	selector := strings.TrimSpace(c.cfg.SourceEmail)
	if selector == "" {
		return "", fmt.Errorf("M365 source mailbox selector is required")
	}
	selectFields := []string{"id", "mail", "userPrincipalName"}
	user, err := c.client.Users().ByUserId(selector).Get(ctx, &users.UserItemRequestBuilderGetRequestConfiguration{
		QueryParameters: &users.UserItemRequestBuilderGetQueryParameters{Select: selectFields},
	})
	if err != nil {
		return "", fmt.Errorf("resolve M365 source mailbox %q: %w", c.cfg.SourceEmail, err)
	}
	if user.GetId() == nil || *user.GetId() == "" {
		return "", fmt.Errorf("resolved M365 source mailbox has no immutable user id")
	}
	resolved := *user.GetId()
	c.cfg.SourceUserID = resolved
	return resolved, nil
}

func (c *M365Connector) ResolveSourceIdentity(ctx context.Context) (SourceIdentity, error) {
	userID, err := c.resolveSourceUser(ctx)
	if err != nil {
		return SourceIdentity{}, err
	}
	selector := strings.ToLower(strings.TrimSpace(c.cfg.SourceEmail))
	if selector == "" {
		selector = userID
	}
	digest := hashSourcePayload([]byte("m365\x00" + selector))
	return SourceIdentity{SourceType: "m365", MailboxKey: "m365:" + userID, SelectorDigest: digest, SourceGeneration: 1}, nil
}

// SetDeltaLinks stores per-category delta links for the next incremental sync.
func (c *M365Connector) SetDeltaLinks(links map[string]string) {
	c.deltaLinks = links
}

// GetDeltaLinks returns the delta links collected during the last fetch.
func (c *M365Connector) GetDeltaLinks() map[string]string {
	if c.deltaLinks == nil {
		return nil
	}
	out := make(map[string]string, len(c.deltaLinks))
	for k, v := range c.deltaLinks {
		out[k] = v
	}
	return out
}

func (c *M365Connector) RestoreSourceState(state SourceResumeState) error {
	links := cloneStringMap(state.LegacyDelta)
	for _, candidate := range state.Durable {
		if candidate.Kind != "m365_delta_link" {
			return rejectCheckpointKind(candidate, "m365_delta_link")
		}
		var value string
		if err := json.Unmarshal(candidate.Value, &value); err != nil || value == "" {
			return fmt.Errorf("restore M365 checkpoint %q: invalid delta link", candidate.Scope)
		}
		links[candidate.Scope] = value
	}
	c.SetDeltaLinks(links)
	return nil
}

func (c *M365Connector) IterateSource(ctx context.Context) *SourceBatchStream {
	return newSourceBatchStream(ctx, c.iterateM365Batches)
}

func m365BatchSnapshot(scope, link string) SourceCheckpointSnapshot {
	return SourceCheckpointSnapshot{
		Candidates: []SourceCheckpointCandidate{{
			Scope: scope, LegacyScope: scope, Kind: "m365_delta_link", Value: jsonMarshal(link),
		}},
		LegacyPatch: map[string]any{"delta": map[string]string{scope: link}},
	}
}

// FetchItemsCursor performs delta (incremental) migration from M365.
func (c *M365Connector) FetchItemsCursor(ctx context.Context, cursor map[string]int) (<-chan SourceItem, <-chan error) {
	if len(c.deltaLinks) > 0 {
		return c.fetchDeltaItems(ctx)
	}
	return c.FetchItems(ctx, nil)
}

// fetchMailDelta fetches changed messages using a delta link.
func (c *M365Connector) fetchMailDelta(ctx context.Context, deltaLink, scope, tag string, itemCh chan<- SourceItem) error {
	return c.fetchDelta(ctx, deltaLink, scope, itemCh,
		func(item map[string]interface{}, itemCh chan<- SourceItem) error {
			id, _ := item["id"].(string)
			if id == "" {
				return fmt.Errorf("delta message omitted immutable id")
			}
			version, _ := item["changeKey"].(string)
			folderID := strings.TrimPrefix(scope, "messages:")
			if folderID == scope {
				folderID, _ = item["parentFolderId"].(string)
			}
			if _, removed := item["@removed"]; removed {
				return sendSourceItem(ctx, itemCh, SourceItem{Type: ItemMail, Change: SourceDelete, SourceObjectID: id, SourceVersion: version, SourceFolderID: folderID})
			}
			mimeBytes, err := c.downloadMIMEbyURL(ctx, id)
			if err != nil {
				return fmt.Errorf("download delta message %q: %w", id, err)
			}
			if tag == "" {
				tag = tagForDeltaItem(item)
			}
			return sendSourceItem(ctx, itemCh, SourceItem{
				Type: ItemMail, Change: SourceUpsert, SourceObjectID: id,
				SourceVersion: version, SourceFolderID: folderID, RawMIME: mimeBytes,
				Tags: []string{tag}, FolderPath: []string{tag},
			})
		})
}

// fetchCalendarDelta fetches changed events using a delta link.
func (c *M365Connector) fetchCalendarDelta(ctx context.Context, deltaLink string, itemCh chan<- SourceItem) error {
	return c.fetchDelta(ctx, deltaLink, "events", itemCh,
		func(item map[string]interface{}, itemCh chan<- SourceItem) error {
			id, _ := item["id"].(string)
			if id == "" {
				return fmt.Errorf("delta event omitted immutable id")
			}
			version, _ := item["changeKey"].(string)
			if _, removed := item["@removed"]; removed {
				return sendSourceItem(ctx, itemCh, SourceItem{Type: ItemCalendar, Change: SourceDelete, SourceObjectID: id, SourceVersion: version})
			}
			ics := eventMapToICS(item)
			if ics != "" {
				return sendSourceItem(ctx, itemCh, SourceItem{Type: ItemCalendar, Change: SourceUpsert, SourceObjectID: id, SourceVersion: version, RawICS: ics})
			}
			return nil
		})
}

// fetchContactsDelta fetches changed contacts using a delta link.
func (c *M365Connector) fetchContactsDelta(ctx context.Context, deltaLink, scope string, itemCh chan<- SourceItem) error {
	return c.fetchDelta(ctx, deltaLink, scope, itemCh,
		func(item map[string]interface{}, itemCh chan<- SourceItem) error {
			id, _ := item["id"].(string)
			if id == "" {
				return fmt.Errorf("delta contact omitted immutable id")
			}
			version, _ := item["changeKey"].(string)
			if _, removed := item["@removed"]; removed {
				return sendSourceItem(ctx, itemCh, SourceItem{Type: ItemContact, Change: SourceDelete, SourceObjectID: id, SourceVersion: version})
			}
			vcf := contactMapToVCF(item)
			if vcf != "" {
				return sendSourceItem(ctx, itemCh, SourceItem{Type: ItemContact, Change: SourceUpsert, SourceObjectID: id, SourceVersion: version, RawVCF: vcf})
			}
			return nil
		})
}

func sendSourceItem(ctx context.Context, itemCh chan<- SourceItem, item SourceItem) error {
	select {
	case itemCh <- item:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *M365Connector) iterateM365Batches(ctx context.Context, emit sourceBatchEmitter) error {
	links := c.GetDeltaLinks()
	if len(links) == 0 {
		userID, err := c.resolveSourceUser(ctx)
		if err != nil {
			return err
		}
		links = make(map[string]string)
		if c.includeMail {
			folders := make([]string, 0, len(wellKnownFolders))
			for folder := range wellKnownFolders {
				folders = append(folders, folder)
			}
			sort.Strings(folders)
			for _, folder := range folders {
				scope := "messages:" + folder
				links[scope] = c.graphEndpoint() + "/v1.0/users/" + url.PathEscape(userID) +
					"/mailFolders/" + url.PathEscape(folder) +
					"/messages/delta?$select=id,changeKey,parentFolderId&$top=100"
			}
		}
		if c.includeCalendar {
			links["events"] = c.graphEndpoint() + "/v1.0/users/" + url.PathEscape(userID) +
				"/events?$select=id,changeKey,subject,iCalUId&$top=100"
		}
		if c.includeContacts {
			if c.cfg.Cloud == "china" {
				// China Graph has no contact delta. Its ordinary paginated endpoint
				// still provides a bounded replay-safe page URL; the last page is
				// deliberately replayed after a crash rather than inventing a token.
				links["contacts"] = c.graphEndpoint() + "/v1.0/users/" + url.PathEscape(userID) +
					"/contacts?$select=id,changeKey,displayName,givenName,surname,companyName,jobTitle,businessPhones,mobilePhone,homePhones,emailAddresses&$top=100"
			} else {
				folders, err := c.listContactFolderIDs(ctx, userID)
				if err != nil {
					return err
				}
				for _, folder := range folders {
					scope := "contacts:" + folder
					links[scope] = c.graphEndpoint() + "/v1.0/users/" + url.PathEscape(userID) +
						"/contactFolders/" + url.PathEscape(folder) +
						"/contacts/delta?$select=id,changeKey,displayName,givenName,surname,companyName,jobTitle,businessPhones,mobilePhone,homePhones,emailAddresses&$top=100"
				}
			}
		}
	}
	categories := sortedCheckpointScopes(links)
	for _, category := range categories {
		tag := ""
		if strings.HasPrefix(category, "messages:") {
			tag = wellKnownFolders[strings.TrimPrefix(category, "messages:")]
		}
		if err := c.iterateM365Category(ctx, links[category], category, tag, emit); err != nil {
			return err
		}
	}
	return nil
}

func (c *M365Connector) iterateM365Category(ctx context.Context, link, category, tag string, emit sourceBatchEmitter) error {
	for link != "" {
		currentLink := link
		body, err := c.graphGET(ctx, link, "application/json", true)
		if err != nil {
			return fmt.Errorf("delta request: %w", err)
		}
		var page struct {
			Value     []map[string]interface{} `json:"value"`
			NextLink  string                   `json:"@odata.nextLink"`
			DeltaLink string                   `json:"@odata.deltaLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("parse delta response: %w", err)
		}
		if len(page.Value) > sourceBatchSize {
			return fmt.Errorf("M365 page contains %d items; maximum is %d", len(page.Value), sourceBatchSize)
		}
		items := make([]SourceItem, 0, len(page.Value))
		for _, raw := range page.Value {
			item, include, err := c.m365DeltaSourceItem(ctx, category, tag, raw)
			if err != nil {
				return err
			}
			if include {
				items = append(items, item)
			}
		}
		next := page.NextLink
		if page.DeltaLink != "" {
			next = page.DeltaLink
		}
		ordinaryFinal := next == "" && (category == "events" || (c.cfg.Cloud == "china" && category == "contacts"))
		if ordinaryFinal {
			// The existing calendar/China-contact APIs are ordinary pagination,
			// not delta feeds. Replaying the last page is safe through stable
			// reducer operation IDs and avoids inventing a provider token.
			next = currentLink
		}
		if next == "" {
			return fmt.Errorf("M365 delta page %q omitted continuation", category)
		}
		if err := emit(SourceBatch{Items: items, Candidate: m365BatchSnapshot(category, next)}); err != nil {
			return err
		}
		if page.DeltaLink != "" || ordinaryFinal {
			return nil
		}
		link = page.NextLink
	}
	return nil
}

func (c *M365Connector) m365DeltaSourceItem(ctx context.Context, category, tag string, item map[string]interface{}) (SourceItem, bool, error) {
	id, _ := item["id"].(string)
	if id == "" {
		return SourceItem{}, false, fmt.Errorf("delta %s object omitted immutable id", category)
	}
	version, _ := item["changeKey"].(string)
	folderID, _ := item["parentFolderId"].(string)
	if strings.HasPrefix(category, "messages") {
		if folderID == "" {
			folderID = strings.TrimPrefix(category, "messages:")
		}
		if _, removed := item["@removed"]; removed {
			return SourceItem{Type: ItemMail, Change: SourceDelete, SourceObjectID: id, SourceVersion: version, SourceFolderID: folderID}, true, nil
		}
		mimeBytes, err := c.downloadMIMEbyURL(ctx, id)
		if err != nil {
			return SourceItem{}, false, fmt.Errorf("download delta message %q: %w", id, err)
		}
		if tag == "" {
			tag = tagForDeltaItem(item)
		}
		return SourceItem{Type: ItemMail, Change: SourceUpsert, SourceObjectID: id,
			SourceVersion: version, SourceFolderID: folderID, RawMIME: mimeBytes,
			Tags: []string{tag}, FolderPath: []string{tag}}, true, nil
	}
	if category == "events" {
		if _, removed := item["@removed"]; removed {
			return SourceItem{Type: ItemCalendar, Change: SourceDelete, SourceObjectID: id, SourceVersion: version}, true, nil
		}
		ics := eventMapToICS(item)
		return SourceItem{Type: ItemCalendar, Change: SourceUpsert, SourceObjectID: id, SourceVersion: version, RawICS: ics}, ics != "", nil
	}
	if strings.HasPrefix(category, "contacts") {
		if _, removed := item["@removed"]; removed {
			return SourceItem{Type: ItemContact, Change: SourceDelete, SourceObjectID: id, SourceVersion: version}, true, nil
		}
		vcf := contactMapToVCF(item)
		return SourceItem{Type: ItemContact, Change: SourceUpsert, SourceObjectID: id, SourceVersion: version, RawVCF: vcf}, vcf != "", nil
	}
	return SourceItem{}, false, fmt.Errorf("unknown M365 delta category %q", category)
}

// fetchDelta is the generic delta sync loop. It follows @odata.nextLink for
// pagination and captures the final @odata.deltaLink for the next sync.
func (c *M365Connector) fetchDelta(ctx context.Context, urlStr string, category string, itemCh chan<- SourceItem, process func(map[string]interface{}, chan<- SourceItem) error) error {
	for urlStr != "" {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		body, err := c.graphGET(ctx, urlStr, "application/json", true)
		if err != nil {
			var httpErr *graphHTTPError
			if errors.As(err, &httpErr) && httpErr.Status == http.StatusGone {
				return errM365DeltaReset
			}
			return fmt.Errorf("delta request: %w", err)
		}

		var page struct {
			Value     []map[string]interface{} `json:"value"`
			NextLink  string                   `json:"@odata.nextLink"`
			DeltaLink string                   `json:"@odata.deltaLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return fmt.Errorf("parse delta response: %w", err)
		}

		for _, item := range page.Value {
			if err := process(item, itemCh); err != nil {
				return err
			}
		}

		if page.DeltaLink != "" {
			// Final page — store the delta link for next sync.
			if c.deltaLinks == nil {
				c.deltaLinks = make(map[string]string)
			}
			c.deltaLinks[category] = page.DeltaLink
			return nil
		}

		urlStr = page.NextLink
	}

	return nil
}

// tokenSource returns the OAuth2 token source cached in the connector.
func (c *M365Connector) tokenSource() oauth2.TokenSource {
	if c.tokens != nil {
		return c.tokens
	}
	cc := clientcredentials.Config{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		TokenURL:     c.authEndpoint() + "/" + c.cfg.TenantID + "/oauth2/v2.0/token",
		Scopes:       []string{c.graphEndpoint() + "/.default"},
	}
	return cc.TokenSource(context.Background())
}

// downloadMIMEbyURL downloads a message's raw MIME content using the $value endpoint.
func (c *M365Connector) downloadMIMEbyURL(ctx context.Context, messageID string) ([]byte, error) {
	userID, err := c.resolveSourceUser(ctx)
	if err != nil {
		return nil, err
	}
	urlStr := c.graphEndpoint() + "/v1.0/users/" + url.PathEscape(userID) +
		"/messages/" + url.PathEscape(messageID) + "/$value"
	return c.graphGET(ctx, urlStr, "text/plain", true)
}

func (c *M365Connector) graphGET(ctx context.Context, urlStr, accept string, immutableIDs bool) ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	for attempt := 0; attempt < 5; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		if err != nil {
			return nil, err
		}
		tok, err := c.tokenSource().Token()
		if err != nil {
			return nil, fmt.Errorf("Graph token: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		req.Header.Set("Accept", accept)
		if immutableIDs {
			req.Header.Set("Prefer", `IdType="ImmutableId"`)
		}
		resp, err := client.Do(req)
		if err != nil {
			if attempt == 4 {
				return nil, err
			}
			if err := waitGraphRetry(ctx, time.Duration(1<<attempt)*time.Second); err != nil {
				return nil, err
			}
			continue
		}
		maxBody := int64(64 << 20)
		if accept == "text/plain" {
			maxBody = 50 << 20
		}
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if int64(len(body)) > maxBody {
			return nil, fmt.Errorf("Graph response exceeds %d-byte limit", maxBody)
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return body, nil
		}
		if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable && resp.StatusCode != http.StatusGatewayTimeout {
			return nil, &graphHTTPError{Status: resp.StatusCode,
				Body: strings.TrimSpace(string(body[:min(len(body), 500)]))}
		}
		if attempt == 4 {
			return nil, fmt.Errorf("Graph retry budget exhausted after status %d", resp.StatusCode)
		}
		delay := graphRetryDelay(resp.Header.Get("Retry-After"), time.Duration(1<<attempt)*time.Second)
		if err := waitGraphRetry(ctx, delay); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("Graph retry budget exhausted")
}

func graphRetryDelay(value string, fallback time.Duration) time.Duration {
	if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds >= 0 {
		delay := time.Duration(seconds) * time.Second
		if delay > 30*time.Second {
			return 30 * time.Second
		}
		return delay
	}
	if when, err := http.ParseTime(value); err == nil {
		delay := time.Until(when)
		if delay < 0 {
			return 0
		}
		if delay > 30*time.Second {
			return 30 * time.Second
		}
		return delay
	}
	if fallback > 30*time.Second {
		return 30 * time.Second
	}
	return fallback
}

func waitGraphRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// tagForDeltaItem returns the appropriate tag for a delta message based on
// its parent folder, defaulting to "inbox".
func tagForDeltaItem(item map[string]interface{}) string {
	if folder, ok := item["parentFolderId"].(string); ok {
		switch folder {
		case "sentitems":
			return "sent"
		case "drafts":
			return "drafts"
		case "deleteditems":
			return "trash"
		case "junkemail":
			return "spam"
		}
	}
	return "inbox"
}

// fetchDeltaItems uses stored delta links to fetch only changes since the
// last sync. This corresponds to the @odata.deltaLink pattern in Graph API.
func (c *M365Connector) fetchDeltaItems(ctx context.Context) (<-chan SourceItem, <-chan error) {
	itemCh := make(chan SourceItem, 100)
	errCh := make(chan error, 1)

	// Background migration goroutine — uses context.Background() for long-running delta sync.
	go func() {
		defer close(itemCh)
		defer close(errCh)

		categories := make([]string, 0, len(c.deltaLinks))
		for category := range c.deltaLinks {
			categories = append(categories, category)
		}
		sort.Strings(categories)
		for _, category := range categories {
			deltaLink := c.deltaLinks[category]
			select {
			case <-ctx.Done():
				return
			default:
			}

			var fetchErr error
			switch {
			case strings.HasPrefix(category, "messages:"):
				folder := strings.TrimPrefix(category, "messages:")
				fetchErr = c.fetchMailDelta(ctx, deltaLink, category, wellKnownFolders[folder], itemCh)
			case category == "messages":
				fetchErr = c.fetchMailDelta(ctx, deltaLink, category, "", itemCh)
			case category == "events":
				fetchErr = c.fetchCalendarDelta(ctx, deltaLink, itemCh)
			case strings.HasPrefix(category, "contacts:") || category == "contacts":
				fetchErr = c.fetchContactsDelta(ctx, deltaLink, category, itemCh)
			default:
				errCh <- fmt.Errorf("unknown M365 delta category %q", category)
				return
			}
			if errors.Is(fetchErr, errM365DeltaReset) {
				c.deltaLinks = nil
				if err := c.fetchInitialItems(ctx, itemCh, nil); err != nil {
					errCh <- fmt.Errorf("rebuild expired M365 delta baseline: %w", err)
				}
				return
			}
			if fetchErr != nil {
				errCh <- fetchErr
				return
			}
		}
	}()

	return itemCh, errCh
}

var wellKnownFolders = map[string]string{
	"inbox":        "Inbox",
	"sentitems":    "Sent",
	"drafts":       "Drafts",
	"deleteditems": "Trash",
	"junkemail":    "Spam",
}

// fetchMailInitialDelta performs the required initial full delta round for
// every selected mail folder. Microsoft Graph message delta is folder-scoped;
// one mailbox-wide token would silently miss moves and folder-local deletes.
func (c *M365Connector) fetchMailInitialDelta(ctx context.Context, userID string, itemCh chan<- SourceItem) error {
	folders := make([]string, 0, len(wellKnownFolders))
	for folder := range wellKnownFolders {
		folders = append(folders, folder)
	}
	sort.Strings(folders)
	for _, folder := range folders {
		tag := wellKnownFolders[folder]
		scope := "messages:" + folder
		initialURL := c.graphEndpoint() + "/v1.0/users/" + url.PathEscape(userID) +
			"/mailFolders/" + url.PathEscape(folder) +
			"/messages/delta?$select=id,changeKey,parentFolderId&$top=100"
		if err := c.fetchMailDelta(ctx, initialURL, scope, tag, itemCh); err != nil {
			return fmt.Errorf("initial delta for mail folder %s: %w", folder, err)
		}
	}
	return nil
}

func (c *M365Connector) fetchContactsInitial(ctx context.Context, userID string, itemCh chan<- SourceItem) error {
	// Microsoft documents contact delta as unavailable in the China-operated
	// national cloud. Preserve full one-shot import there instead of claiming an
	// incremental cursor the service cannot honor.
	if c.cfg.Cloud == "china" {
		return c.fetchContacts(ctx, userID, itemCh)
	}
	folders, err := c.listContactFolderIDs(ctx, userID)
	if err != nil {
		return err
	}
	if len(folders) == 0 {
		return c.fetchContacts(ctx, userID, itemCh)
	}
	for _, folderID := range folders {
		scope := "contacts:" + folderID
		initialURL := c.graphEndpoint() + "/v1.0/users/" + url.PathEscape(userID) +
			"/contactFolders/" + url.PathEscape(folderID) +
			"/contacts/delta?$select=id,changeKey,displayName,givenName,surname,companyName,jobTitle,businessPhones,mobilePhone,homePhones,emailAddresses&$top=100"
		if err := c.fetchContactsDelta(ctx, initialURL, scope, itemCh); err != nil {
			return fmt.Errorf("initial delta for contact folder %s: %w", folderID, err)
		}
	}
	return nil
}

func (c *M365Connector) listContactFolderIDs(ctx context.Context, userID string) ([]string, error) {
	urlStr := c.graphEndpoint() + "/v1.0/users/" + url.PathEscape(userID) +
		"/contactFolders?$select=id&$top=100"
	var ids []string
	for urlStr != "" {
		body, err := c.graphGET(ctx, urlStr, "application/json", false)
		if err != nil {
			return nil, fmt.Errorf("list contact folders: %w", err)
		}
		var page struct {
			Value []struct {
				ID string `json:"id"`
			} `json:"value"`
			NextLink string `json:"@odata.nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, fmt.Errorf("parse contact folders: %w", err)
		}
		for _, folder := range page.Value {
			if folder.ID == "" {
				return nil, fmt.Errorf("contact folder omitted immutable id")
			}
			ids = append(ids, folder.ID)
		}
		urlStr = page.NextLink
	}
	sort.Strings(ids)
	return ids, nil
}

func immutableIDHeader() *abs.RequestHeaders {
	h := abs.NewRequestHeaders()
	h.TryAdd("Prefer", `IdType="ImmutableId"`)
	return h
}

// fetchCalendar downloads calendar events and converts them to ICS format.
func (c *M365Connector) fetchCalendar(ctx context.Context, userID string, itemCh chan<- SourceItem) error {
	top := int32(100)
	builder := c.client.Users().ByUserId(userID).Events()
	config := &users.ItemEventsRequestBuilderGetRequestConfiguration{
		Headers: immutableIDHeader(),
		QueryParameters: &users.ItemEventsRequestBuilderGetQueryParameters{
			Top: &top, Select: []string{"id", "changeKey", "subject", "iCalUId"},
		},
	}
	for {
		resp, err := builder.Get(ctx, config)
		if err != nil {
			return fmt.Errorf("list events: %w", err)
		}
		for _, evt := range resp.GetValue() {
			if evt.GetId() == nil || *evt.GetId() == "" {
				return fmt.Errorf("events page returned an event without immutable id")
			}
			icsData, err := c.downloadICS(ctx, userID, *evt.GetId())
			if err != nil {
				return fmt.Errorf("download event %s: %w", *evt.GetId(), err)
			}
			if len(icsData) == 0 {
				return fmt.Errorf("event %s serialized to an empty payload", *evt.GetId())
			}
			version := ""
			if evt.GetChangeKey() != nil {
				version = *evt.GetChangeKey()
			}
			if err := sendSourceItem(ctx, itemCh, SourceItem{Type: ItemCalendar, Change: SourceUpsert,
				SourceObjectID: *evt.GetId(), SourceVersion: version, RawICS: string(icsData)}); err != nil {
				return err
			}
		}
		nextLink := resp.GetOdataNextLink()
		if nextLink == nil || *nextLink == "" {
			break
		}
		builder = users.NewItemEventsRequestBuilder(*nextLink, c.client.GetAdapter())
		config = nil
	}
	return nil
}

// downloadICS fetches an event as raw ICS by using the adapter directly.
// The Microsoft Graph API does not expose a $value endpoint for events,
// so we fetch the full event and serialize it to ICS format.
func (c *M365Connector) downloadICS(ctx context.Context, userID, eventID string) ([]byte, error) {
	evt, err := c.client.Users().ByUserId(userID).Events().ByEventId(eventID).Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get event: %w", err)
	}
	return eventToICS(evt), nil
}

// eventToICS serializes a Microsoft Graph event to iCalendar (ICS) format.
func eventToICS(evt graphmodels.Eventable) []byte {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\n")
	b.WriteString("VERSION:2.0\r\n")
	b.WriteString("PRODID:-//Mailserver//Migration//EN\r\n")
	b.WriteString("BEGIN:VEVENT\r\n")

	if uid := evt.GetICalUId(); uid != nil {
		fmt.Fprintf(&b, "UID:%s\r\n", *uid)
	} else if id := evt.GetId(); id != nil {
		fmt.Fprintf(&b, "UID:%s\r\n", *id)
	}

	if subject := evt.GetSubject(); subject != nil {
		fmt.Fprintf(&b, "SUMMARY:%s\r\n", escapeICS(*subject))
	}

	if start := evt.GetStart(); start != nil {
		dt := icsDateTime(start)
		if dt != "" {
			fmt.Fprintf(&b, "DTSTART:%s\r\n", dt)
		}
	}
	if end := evt.GetEnd(); end != nil {
		dt := icsDateTime(end)
		if dt != "" {
			fmt.Fprintf(&b, "DTEND:%s\r\n", dt)
		}
	}

	if body := evt.GetBody(); body != nil {
		if content := body.GetContent(); content != nil {
			fmt.Fprintf(&b, "DESCRIPTION:%s\r\n", escapeICS(*content))
		}
	}

	if loc := evt.GetLocation(); loc != nil {
		if displayName := loc.GetDisplayName(); displayName != nil {
			fmt.Fprintf(&b, "LOCATION:%s\r\n", escapeICS(*displayName))
		}
	}

	b.WriteString("END:VEVENT\r\n")
	b.WriteString("END:VCALENDAR\r\n")
	return []byte(b.String())
}

// icsDateTime formats a DateTimeTimeZone to ICS format.
func icsDateTime(dt graphmodels.DateTimeTimeZoneable) string {
	dateTime := dt.GetDateTime()
	if dateTime == nil || *dateTime == "" {
		return ""
	}
	// Microsoft Graph returns ISO 8601: "2024-01-15T10:00:00.0000000"
	// ICS needs: "20240115T100000Z" or "20240115T100000" with TZID
	t, err := time.Parse("2006-01-02T15:04:05.0000000", *dateTime)
	if err != nil {
		// Try without fractional seconds
		t, err = time.Parse("2006-01-02T15:04:05", *dateTime)
		if err != nil {
			return *dateTime
		}
	}
	return t.UTC().Format("20060102T150405Z")
}

// escapeICS escapes special characters for ICS text properties.
func escapeICS(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, ";", "\\;")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// fetchContacts downloads contacts and converts them to VCF format.
func (c *M365Connector) fetchContacts(ctx context.Context, userID string, itemCh chan<- SourceItem) error {
	top := int32(100)
	builder := c.client.Users().ByUserId(userID).Contacts()
	config := &users.ItemContactsRequestBuilderGetRequestConfiguration{
		Headers: immutableIDHeader(),
		QueryParameters: &users.ItemContactsRequestBuilderGetQueryParameters{
			Top: &top, Select: []string{"id", "changeKey"},
		},
	}
	for {
		resp, err := builder.Get(ctx, config)
		if err != nil {
			return fmt.Errorf("list contacts: %w", err)
		}
		for _, contact := range resp.GetValue() {
			if contact.GetId() == nil || *contact.GetId() == "" {
				return fmt.Errorf("contacts page returned a contact without immutable id")
			}
			vcfData, err := c.downloadVCF(ctx, userID, *contact.GetId())
			if err != nil {
				return fmt.Errorf("download contact %s: %w", *contact.GetId(), err)
			}
			if len(vcfData) == 0 {
				return fmt.Errorf("contact %s serialized to an empty payload", *contact.GetId())
			}
			version := ""
			if contact.GetChangeKey() != nil {
				version = *contact.GetChangeKey()
			}
			if err := sendSourceItem(ctx, itemCh, SourceItem{Type: ItemContact, Change: SourceUpsert,
				SourceObjectID: *contact.GetId(), SourceVersion: version, RawVCF: string(vcfData)}); err != nil {
				return err
			}
		}
		nextLink := resp.GetOdataNextLink()
		if nextLink == nil || *nextLink == "" {
			break
		}
		builder = users.NewItemContactsRequestBuilder(*nextLink, c.client.GetAdapter())
		config = nil
	}
	return nil
}

// downloadVCF fetches a contact and serializes it to vCard format.
func (c *M365Connector) downloadVCF(ctx context.Context, userID, contactID string) ([]byte, error) {
	contact, err := c.client.Users().ByUserId(userID).Contacts().ByContactId(contactID).Get(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("get contact: %w", err)
	}
	return contactToVCF(contact), nil
}

// contactToVCF serializes a Microsoft Graph contact to vCard (VCF) 3.0 format.
func contactToVCF(contact graphmodels.Contactable) []byte {
	var b strings.Builder
	b.WriteString("BEGIN:VCARD\r\n")
	b.WriteString("VERSION:3.0\r\n")

	// FN (formatted name)
	if dn := contact.GetDisplayName(); dn != nil {
		fmt.Fprintf(&b, "FN:%s\r\n", escapeVCF(*dn))
	}

	// N (structured name)
	given := strOrEmpty(contact.GetGivenName())
	surname := strOrEmpty(contact.GetSurname())
	fmt.Fprintf(&b, "N:%s;%s;;;\r\n", escapeVCF(surname), escapeVCF(given))

	// ORG
	if org := contact.GetCompanyName(); org != nil {
		fmt.Fprintf(&b, "ORG:%s\r\n", escapeVCF(*org))
	}

	// TITLE
	if title := contact.GetJobTitle(); title != nil {
		fmt.Fprintf(&b, "TITLE:%s\r\n", escapeVCF(*title))
	}

	// TEL
	for _, phone := range contact.GetBusinessPhones() {
		fmt.Fprintf(&b, "TEL;TYPE=WORK:%s\r\n", phone)
	}
	if mobile := contact.GetMobilePhone(); mobile != nil && *mobile != "" {
		fmt.Fprintf(&b, "TEL;TYPE=CELL:%s\r\n", *mobile)
	}
	for _, phone := range contact.GetHomePhones() {
		fmt.Fprintf(&b, "TEL;TYPE=HOME:%s\r\n", phone)
	}

	// EMAIL
	for _, email := range contact.GetEmailAddresses() {
		if addr := email.GetAddress(); addr != nil && *addr != "" {
			fmt.Fprintf(&b, "EMAIL:%s\r\n", *addr)
		}
	}

	b.WriteString("END:VCARD\r\n")
	return []byte(b.String())
}

// escapeVCF escapes special characters for vCard properties.
func escapeVCF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, ";", "\\;")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "")
	return s
}

// strOrEmpty returns the string value or empty string if nil.
func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// m365AuthProvider implements the Kiota AuthenticationProvider interface
// using an oauth2.TokenSource for client credentials flow.
type m365AuthProvider struct {
	ts oauth2.TokenSource
}

// eventMapToICS builds an iCalendar VEVENT from a raw delta response map.
func eventMapToICS(m map[string]interface{}) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\n")
	b.WriteString("VERSION:2.0\r\n")
	b.WriteString("PRODID:-//Mailserver//Migration//EN\r\n")
	b.WriteString("BEGIN:VEVENT\r\n")

	if uid, ok := m["iCalUId"].(string); ok && uid != "" {
		fmt.Fprintf(&b, "UID:%s\r\n", uid)
	} else if id, ok := m["id"].(string); ok && id != "" {
		fmt.Fprintf(&b, "UID:%s\r\n", id)
	}

	if subject, ok := m["subject"].(string); ok {
		fmt.Fprintf(&b, "SUMMARY:%s\r\n", escapeICS(subject))
	}

	if start, ok := m["start"].(map[string]interface{}); ok {
		if dt := mapDateTime(start); dt != "" {
			fmt.Fprintf(&b, "DTSTART:%s\r\n", dt)
		}
	}
	if end, ok := m["end"].(map[string]interface{}); ok {
		if dt := mapDateTime(end); dt != "" {
			fmt.Fprintf(&b, "DTEND:%s\r\n", dt)
		}
	}

	if body, ok := m["body"].(map[string]interface{}); ok {
		if content, ok := body["content"].(string); ok && content != "" {
			fmt.Fprintf(&b, "DESCRIPTION:%s\r\n", escapeICS(content))
		}
	}
	if loc, ok := m["location"].(map[string]interface{}); ok {
		if name, ok := loc["displayName"].(string); ok && name != "" {
			fmt.Fprintf(&b, "LOCATION:%s\r\n", escapeICS(name))
		}
	}

	b.WriteString("END:VEVENT\r\n")
	b.WriteString("END:VCALENDAR\r\n")
	return b.String()
}

// contactMapToVCF builds a vCard from a raw delta response map.
func contactMapToVCF(m map[string]interface{}) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCARD\r\n")
	b.WriteString("VERSION:3.0\r\n")

	if name, ok := m["displayName"].(string); ok && name != "" {
		fmt.Fprintf(&b, "FN:%s\r\n", escapeVCF(name))
	}
	if given, ok := m["givenName"].(string); ok {
		fmt.Fprintf(&b, "N:%s;%s;;;\r\n", escapeVCF(nameOr(m, "surname", "")), escapeVCF(given))
	}

	// email addresses
	if emails, ok := m["emailAddresses"].([]interface{}); ok {
		for _, e := range emails {
			if em, ok := e.(map[string]interface{}); ok {
				if addr, ok := em["address"].(string); ok && addr != "" {
					fmt.Fprintf(&b, "EMAIL:%s\r\n", escapeVCF(addr))
				}
			}
		}
	}
	// phones
	if phones, ok := m["businessPhones"].([]interface{}); ok {
		for _, p := range phones {
			if ph, ok := p.(string); ok && ph != "" {
				fmt.Fprintf(&b, "TEL;TYPE=WORK:%s\r\n", escapeVCF(ph))
			}
		}
	}
	if title, ok := m["jobTitle"].(string); ok && title != "" {
		fmt.Fprintf(&b, "TITLE:%s\r\n", escapeVCF(title))
	}

	b.WriteString("END:VCARD\r\n")
	return b.String()
}

func nameOr(m map[string]interface{}, key, def string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return def
}

// mapDateTime converts a Graph API {"dateTime":"...","timeZone":"..."} map to
// ICS compact form. Graph returns ISO 8601 (e.g. "2024-01-15T10:00:00.0000000");
// ICS requires compact form ("20240115T100000Z" for UTC or
// "TZID=America/New_York:20240115T100000" for local time).
// The previous implementation was a no-op (strings.Replace("T","T")) that left
// the raw ISO string in the ICS output, causing parse failures in all consumers.
func mapDateTime(dt map[string]interface{}) string {
	dateTime, _ := dt["dateTime"].(string)
	if dateTime == "" {
		return ""
	}
	// Parse with fractional-seconds format, fall back to without.
	t, err := time.Parse("2006-01-02T15:04:05.0000000", dateTime)
	if err != nil {
		t, err = time.Parse("2006-01-02T15:04:05", dateTime)
		if err != nil {
			return "" // unparseable — emit nothing rather than malformed ICS
		}
	}
	tz, _ := dt["timeZone"].(string)
	if tz == "UTC" || tz == "" {
		return t.UTC().Format("20060102T150405Z")
	}
	// Non-UTC: emit TZID-qualified compact form (preserves local time + TZID).
	return "TZID=" + tz + ":" + t.Format("20060102T150405")
}

func (p *m365AuthProvider) AuthenticateRequest(ctx context.Context, request *abs.RequestInformation, additionalAuthenticationContext map[string]interface{}) error {
	tok, err := p.ts.Token()
	if err != nil {
		return fmt.Errorf("m365 token: %w", err)
	}
	if request.Headers == nil {
		request.Headers = abs.NewRequestHeaders()
	}
	request.Headers.TryAdd("Authorization", "Bearer "+tok.AccessToken)
	return nil
}
