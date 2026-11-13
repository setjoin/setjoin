package spam

import (
	"bytes"
	"encoding/binary"
	"hash/fnv"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

const (
	// DefaultFeatureSize is the default feature hash space: 2^20 = 1,048,576
	// buckets. The persisted model holds three float64 tables over this space
	// (FTRL z/n/weights) ≈ 24 MiB per user (the historical "~8MB" note
	// understated it — D-MAILSERVER-INTERNAL-SPAM-007 records the real
	// footprint and the cache/capacity policy as its owner decision).
	DefaultFeatureSize = 1 << 20
)

var (
	// Token separators — split on whitespace, punctuation, HTML tags.
	reWord    = regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9]{2,}`) // 3+ char words
	reURL     = regexp.MustCompile(`https?://[^\s<>"']+`)
	reEmail   = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)
	reHTMLTag = regexp.MustCompile(`<[^>]+>`)

	// Common spam words that should NOT be stemmed.
	suspiciousWords = []string{
		"viagra", "cialis", "lottery", "winner", "million", "prize",
		"urgent", "click", "free", "offer", "discount", "guaranteed",
		"act now", "limited time", "exclusive",
	}
)

// PerUserFeatureKey derives the stable per-user feature-space key for userID.
//
// med-shard3-016 per-user feature hashing: the key is mixed into every feature
// hash (see ExtractFeatures), so each user's model occupies its own bucket
// mapping. A bucket collision an attacker crafts against one victim's space
// does not exist in any other user's space — collision work cannot be shared
// across victims. The derivation is pure and public: this isolates victims
// from each other; it is not a secret salt.
func PerUserFeatureKey(userID int64) uint32 {
	h := fnv.New64a()
	var buf [8]byte
	// The bit pattern of userID (negative IDs wrap deterministically) is the
	// key material; no numeric interpretation of the conversion exists.
	binary.LittleEndian.PutUint64(buf[:], uint64(userID)) //nolint:gosec // G115: bit-pattern hash key, sign wrap is deterministic
	h.Write(buf[:])
	// Truncation to 32 bits is the intended key-space reduction.
	return uint32(h.Sum64()) //nolint:gosec // G115: deliberate 64→32-bit key-space truncation
}

// featureIndex hashes token into the fixed DefaultFeatureSize table under the
// given per-user feature-space key. The key is part of the hash input (not
// just the modulus), so two keys yield completely disjoint bucket assignments
// for the same token.
func featureIndex(key uint32, token string) uint32 {
	h := fnv.New32a()
	var kb [4]byte
	binary.LittleEndian.PutUint32(kb[:], key)
	h.Write(kb[:])
	h.Write([]byte(token))
	return h.Sum32() % DefaultFeatureSize
}

// parsedMessage is the RFC 5322 header/body split plus the small subset of
// headers the feature extractor consumes. Header names are lowercased;
// the first occurrence of a name wins; continuation lines (leading WSP) are
// unfolded into the previous header's value. body is a zero-copy SLICE of the
// input raw bytes (D-MAILSERVER-INTERNAL-SPAM-006: extraction must not make a
// full string copy of an attacker-scale message just to split it).
type parsedMessage struct {
	headers map[string]string
	body    []byte
}

// parseMessage splits raw at the FIRST blank line separating the header block
// from the body (CRLF or bare-LF conventions, whichever separator appears
// first) and parses the header block. Feature extraction must consume identity
// fields (From/Subject/Content-Type/Message-Id/Date) from these PARSED headers
// only: a "From:" or "Subject:" line inside attacker-controlled body bytes
// must never contribute header features (header impersonation).
func parseMessage(raw []byte) parsedMessage {
	headBlock := raw
	var body []byte
	crlf := bytes.Index(raw, []byte("\r\n\r\n"))
	lf := bytes.Index(raw, []byte("\n\n"))
	sep := -1
	sepLen := 0
	switch {
	case crlf >= 0 && lf >= 0:
		if crlf <= lf {
			sep, sepLen = crlf, 4
		} else {
			sep, sepLen = lf, 2
		}
	case crlf >= 0:
		sep, sepLen = crlf, 4
	case lf >= 0:
		sep, sepLen = lf, 2
	}
	if sep >= 0 {
		headBlock = raw[:sep]
		body = raw[sep+sepLen:]
	}

	pm := parsedMessage{headers: make(map[string]string), body: body}
	var lastName string
	for _, line := range bytes.Split(headBlock, []byte("\n")) {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			// RFC 5322 §2.2.3 continuation: unfold into the previous header.
			if lastName != "" {
				pm.headers[lastName] += " " + strings.TrimSpace(string(line))
			}
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			lastName = ""
			continue // not a header line; tolerate garbage
		}
		name := strings.ToLower(strings.TrimSpace(string(line[:colon])))
		value := strings.TrimSpace(string(line[colon+1:]))
		if _, dup := pm.headers[name]; !dup {
			pm.headers[name] = value
		}
		lastName = name
	}
	return pm
}

// ExtractFeatures extracts feature indices from a raw email.
//
// med-shard3-016 remediation, two halves:
//
//  1. Parsed extraction: From/Subject/Content-Type/Message-Id/Date features
//     derive ONLY from the parsed header block (see parseMessage). The
//     pre-remediation behavior — first email-like string anywhere in the raw
//     bytes, first "Subject:"/"Content-Type:" substring anywhere — let a body
//     line like "From: victim@x" impersonate the sender and body text defeat
//     the missing-header features. The body proper is the content after the
//     first header/body separator.
//
//  2. Per-user keyed hashing: `size` is the caller's per-user feature-space
//     key (PerUserFeatureKey(userID), stored as Model.featSize for models the
//     store hands out), mixed into every hash so bucket collisions cannot be
//     shared across users. Indices are reduced into the fixed
//     DefaultFeatureSize table — the FTRL table the store builds for every
//     model — so a keyed model's extract space always equals its table.
//     Models constructed directly via NewModel must keep the default size.
//
// The returned indices are deduplicated and unordered.
//
// Extraction runs on the input BYTE SLICE without a full string copy
// (D-MAILSERVER-INTERNAL-SPAM-006): only the small parsed header values and
// individual regex matches are converted to strings.
func ExtractFeatures(raw []byte, size uint32) []uint32 {
	pm := parseMessage(raw)
	seen := make(map[uint32]bool, 64)
	feats := make([]uint32, 0, 64)
	add := func(token string) {
		idx := featureIndex(size, token)
		if !seen[idx] {
			seen[idx] = true
			feats = append(feats, idx)
		}
	}

	// 1. Sender — the PARSED From header value only. An email-like string in
	// the body or any other header never contributes the from: feature.
	if from := pm.headers["from"]; from != "" {
		if match := reEmail.FindString(from); match != "" {
			add("from:" + strings.ToLower(match))
		} else {
			add("from:addr:" + strings.ToLower(from))
		}
	}

	// 2. Subject — the PARSED Subject header value only.
	if subject := pm.headers["subject"]; subject != "" {
		for _, word := range reWord.FindAllString(strings.ToLower(subject), -1) {
			add("s:" + word)
		}
		// All-caps penalty.
		if len(subject) > 0 && float64(countCaps(subject))/float64(len(subject)) > 0.5 {
			add("allcaps")
		}
	}

	// 3. URLs — content-derived signal from anywhere in the message (matched
	// on the byte slice; only each small match is converted for url.Parse).
	for _, rawURL := range reURL.FindAll(raw, -1) {
		if u, err := url.Parse(string(rawURL)); err == nil {
			host := strings.ToLower(u.Host)
			// SLD
			parts := strings.Split(host, ".")
			if len(parts) >= 2 {
				add("url:" + parts[len(parts)-2] + "." + parts[len(parts)-1])
			}
			// Path segments
			for _, seg := range strings.Split(u.Path, "/") {
				if seg != "" {
					add("path:" + seg)
				}
			}
		}
	}

	// 4. Content-Type — the PARSED header value only.
	if ct := strings.ToLower(pm.headers["content-type"]); ct != "" {
		if strings.Contains(ct, "text/html") {
			add("ct:html")
		}
		if strings.Contains(ct, "text/plain") {
			add("ct:plain")
		}
	}

	// 5. Body words — the parsed body only (text after the first blank line),
	// processed as a byte slice (no full-copy string conversion).
	if len(pm.body) > 0 {
		body := bytes.ToLower(reHTMLTag.ReplaceAll(pm.body, []byte(" ")))
		for _, word := range reWord.FindAll(body, -1) {
			add("w:" + string(word))
		}
		// Suspicious word boost
		for _, kw := range suspiciousWords {
			if bytes.Contains(body, []byte(kw)) {
				add("susp:" + kw)
			}
		}
	}

	// 6. Missing headers — presence decided on the PARSED header block, never
	// by substring-scanning attacker bytes for "Message-Id:"/"Date:".
	if _, ok := pm.headers["message-id"]; !ok {
		add("miss:mid")
	}
	if _, ok := pm.headers["date"]; !ok {
		add("miss:date")
	}

	return feats
}

func countCaps(s string) int {
	n := 0
	for _, r := range s {
		if unicode.IsUpper(r) {
			n++
		}
	}
	return n
}
