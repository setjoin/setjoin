# Spam Classifier Enhancement — Design Spec

Date: 2026-06-05
Status: Design

## Goal

Upgrade the spam detection pipeline with six pure-Go enhancements inspired by rspamd's architecture, while respecting the existing decision tree: virus→quarantine, spam→Junk folder, greylist→temporary reject, clean→Inbox.

## Current State

The SMTP pipeline has 9 composable checks (`mailserver/internal/smtp/pipeline.go`), per-user FTRL classifier (`mailserver/internal/spam/`), ClamAV integration, CAPE sandbox, RBL/DNSBL, SPF/DKIM/DMARC, and greylisting. The pipeline classifies messages as clean/spam/virus and routes accordingly via the tag system (Phase 17).

## Enhancement 1: OSB Tokenizer

### What it is
Orthogonal Sparse Bigrams — rspamd's language-agnostic tokenization algorithm. Sliding window of 5 tokens, all unordered bigrams within the window. Works identically on English, Chinese, Japanese, Korean without language detection.

### How it works
```
Input: "购买伟哥现在便宜特价"
  Step 1: CJK detection — each character IS a token
  Tokens: [购买, 伟哥, 现在, 便宜, 特价]
  
  Step 2: Sliding window of 5, generate all unordered bigrams
  Window 1: [购买, 伟哥, 现在, 便宜, 特价]
    → 购买-伟哥, 购买-现在, 购买-便宜, 购买-特价, 
      伟哥-现在, 伟哥-便宜, 伟哥-特价,
      现在-便宜, 现在-特价, 便宜-特价

Input: "buy cheap viagra now free"
  Step 1: Latin detection — split on whitespace
  Tokens: [buy, cheap, viagra, now, free]
  
  Step 2: Same sliding window algorithm
    → buy-cheap, buy-viagra, buy-now, buy-free,
      cheap-viagra, cheap-now, cheap-free,
      viagra-now, viagra-free, now-free
```

### Implementation
```go
// shared/spam/tokenizer.go — ~150 lines
func OSBTokenize(text string) []string
func isCJK(r rune) bool  // Unicode range check
func extractTokens(text string) []string  // CJK=per-char, Latin=per-word
func slidingBigrams(tokens []string, window int) []string
```

### Integration
Replace current word-tokenizer in FTRL training/inference path. FTRL model trains on OSB tokens instead of raw words. No API change — same train/predict interface.

### Performance
- CJK: ~500µs per message (character iteration + bigram generation)
- Latin: ~200µs per message (word split + bigram generation)
- Token count per message: ~50-200 tokens

---

## Enhancement 2: Multi-Class Bayesian

### What it is
Extend the existing binary FTRL classifier from spam/ham to 5 categories, matching rspamd's multi-class Bayesian (2025 feature).

### Categories
| Class | Label | Action |
|-------|-------|--------|
| ham | `__label__ham` | Deliver to Inbox |
| spam | `__label__spam` | Deliver to Junk folder |
| newsletter | `__label__newsletter` | Deliver to Inbox (user preference) |
| promotional | `__label__promotional` | Deliver to Inbox, Gmail-style "Promotions" tab |
| phishing | `__label__phishing` | Quarantine + admin alert (high confidence) |

### How it differs from binary
Binary FTRL: one weight vector, sigmoid output → [0,1] spam probability
Multi-class FTRL: 5 weight vectors, softmax output → probability distribution

### Training
- User marks as spam → train `__label__spam` +1
- User marks as ham → train `__label__ham` +1
- User marks as phishing → train `__label__phishing` +1
- System auto-classifies newsletters (via List-Unsubscribe header + content patterns)
- System auto-classifies promotional (via bulk sender patterns + unsubscribe links)

### Implementation
```go
// shared/spam/multiclass.go — ~200 lines
type MultiClassFTRL struct { classes []string; models map[string]*FTRLModel }
func (m *MultiClassFTRL) Predict(features []string) ClassResult
func (m *MultiClassFTRL) Train(features []string, class string) error
```

---

## Enhancement 3: Composite Symbols

### What it is
Boolean logic combining multiple pipeline check results into higher-signal rules. rspamd's composite symbols let you express: "unauthenticated + known spam IP + external sender = auto-reject."

### Implementation
No new code — just a config file that combines existing pipeline checks:

```yaml
# mailserver/internal/smtp/spam_rules.yaml
composites:
  - name: SPOOFED_UNAUTH
    conditions:
      - check: spf
        result: [fail, softfail, neutral]
      - check: dkim
        result: [fail, none]
      - check: dmarc
        result: [fail, none]
    action: score +50.0
    description: "Sender claims to be from domain but all auth failed"

  - name: IMAGE_ONLY_SPAM
    conditions:
      - check: mime_type
        result: ["image/*"]
      - check: body_text_length
        lt: 50
      - check: sender_auth
        result: [unauthenticated]
    action: score +8.0
    description: "Image-only email from unauthenticated external sender"

  - name: BULK_NEWSLETTER
    conditions:
      - check: list_unsubscribe
        result: [present]
      - check: spam_score
        lt: 3.0
    action: classify newsletter
    description: "Has unsubscribe header and low spam score → newsletter"

  - name: ENCRYPTED_ARCHIVE_EXTERNAL
    conditions:
      - check: has_encrypted_attachment
        result: [true]
      - check: sender_auth
        result: [unauthenticated]
    action: strip_attachment + quarantine
    description: "Encrypted attachment from unknown sender"
```

Pipeline evaluator reads the YAML config at startup. Each composite is evaluated after individual checks. Scores are additive.

---

## Enhancement 4: Fuzzy Image Hashing

### What it is
Perceptual hashing of image attachments. Identical images produce identical hashes. Visually similar images produce similar hashes. Catches spam campaigns that reuse the same product image across thousands of messages.

### Algorithm
Average hash (aHash): resize to 8×8 grayscale, compare each pixel to mean, produce 64-bit hash. Fast enough for SMTP-time processing (~2ms per image).

### Integration
- Extract images from MIME attachments
- Compute aHash for each image > 1KB
- Check against Redis/in-memory cache of known spam image hashes
- Match → score +5.0
- New spam image → store hash, expire after 30 days

### Implementation
```go
// shared/spam/imagehash.go — ~150 lines
func AverageHash(img image.Image) uint64
func HammingDistance(a, b uint64) int  // for near-duplicate detection
```

---

## Enhancement 5: HTML Structure Fingerprinting

### What it is
DOM tree structural hashing. Extracts the HTML tag structure (ignoring text content and image URLs), hashes it. Catches phishing that copies bank login HTML templates with modified links.

### Algorithm
1. Parse HTML → DOM tree
2. Extract structure: tag names + class/ID attributes (no text, no src/href)
3. Hash the structure string with SHA-256
4. Compare against known phishing templates

### Integration
- Extract HTML body from MIME
- Compute structure hash
- Check against phishing template database
- Match → score +15.0 + quarantine

### Implementation
```go
// shared/spam/htmlstruct.go — ~200 lines
func StructureHash(html string) string
func ExtractTagStructure(node *html.Node) string
```

### Template database
Ship with 50 known phishing templates (bank logins, DocuSign, Microsoft 365, DHL, etc.). Admin can add custom templates. Community-updatable feed.

---

## Enhancement 6: Encrypted Archive Policy

### What it is
Block or quarantine encrypted/password-protected ZIP/RAR/7z attachments from unauthenticated external senders. Detect password-in-body patterns.

### Decision tree (respecting existing pipeline)
```
Encrypted attachment detected:
  │
  ├── Sender is authenticated internal user
  │     → Pass through, score +2.0, flag for user awareness
  │
  ├── Sender is known contact (in user's address book)
  │     → QUARANTINE (low priority)
  │     → Admin reviews in quarantine dashboard
  │     → User gets digest: "Message from {contact} with encrypted attachment"
  │     → If admin releases: attachment passes through
  │
  ├── Sender is external unknown
  │     → QUARANTINE entire message
  │     → Admin reviews in quarantine dashboard
  │     → If admin releases: attachment stripped, notification added
  │     → If admin rejects: silently dropped, sender NOT notified
  │     → Rationale: delivering a "notification" from an attacker IS a 
  │       social engineering vector. The attacker knows the message reached
  │       the user and can follow up. Quarantine breaks the attack chain.
  │
  └── Password-in-body detected (regex: "password is", "密码", "解压密码", "pw:")
        → QUARANTINE (high priority)
        → Admin alert: "Encrypted attachment + password in body"
        → Never auto-release — requires manual admin review

### Implementation
```go
// shared/spam/archive.go — ~100 lines
func DetectEncryptedArchive(attachment []byte, mimeType string) bool
func DetectPasswordInBody(body string) bool
```

---

## Enhancement 7: Spamtrap Detection

### What it is
Designated email addresses that should never receive legitimate mail. Any message delivered to a spamtrap address is automatically classified as spam and used to train the classifier. This is one of the highest-signal spam indicators — zero false positives by definition.

### How it works
1. Admin creates spamtrap addresses: `trap-{random}@company.com`, `honeypot@company.com`
2. These addresses are never given to humans, never send email, never appear on the web
3. Spammers harvest them from data breaches, WHOIS records, or dictionary attacks
4. When a message arrives at a spamtrap address → auto-classify as spam, train FTRL +1.0
5. The sender IP/domain gets a permanent reputation penalty

### Implementation
```go
// shared/spam/spamtrap.go — ~60 lines
type SpamtrapStore struct {
    addresses map[string]bool  // lowercased spamtrap emails
}

func (s *SpamtrapStore) IsSpamtrap(rcpt string) bool {
    return s.addresses[strings.ToLower(rcpt)]
}

// Called during SMTP RCPT TO processing:
// if spamtrapStore.IsSpamtrap(rcpt) → mark as spam, train classifier, penalize sender
```

### Admin configuration
```yaml
# mailserver/internal/smtp/spam_rules.yaml
spamtraps:
  enabled: true
  addresses:
    - trap-a7b3c9@company.com
    - honeypot@company.com
  auto_train: true           # auto-train FTRL on spamtrap messages
  sender_penalty: permanent  # "permanent" or "temporary"
  penalty_duration: 90d      # how long to penalize sender (if temporary)
```

### Spamtrap address generation
```bash
mailctl spamtrap create          # Generate a new random spamtrap
mailctl spamtrap list            # List all active spamtraps
mailctl spamtrap delete <addr>   # Remove a spamtrap
```

Generated addresses use a random prefix to prevent guessing: `trap-a7b3c9d1@company.com`.

---

## Enhancement 8: MIME Content Type Rules

### What it is
Score messages based on MIME structure patterns that correlate with spam.

### Rules
```yaml
mime_rules:
  - pattern: "only image attachments, no text body, external sender"
    score: +3.0
  
  - pattern: "HTML body with hidden text (white-on-white, font-size:0)"
    score: +5.0
  
  - pattern: "multiple attached executables disguised as documents"
    score: +10.0 + quarantine
  
  - pattern: "base64-encoded attachment with misleading extension"
    score: +4.0
  
  - pattern: "QR code in image attachment + shortened URL in body"
    score: +3.0
```

### Implementation
```go
// shared/spam/mimerules.go — ~50 lines
func CheckMIMERules(msg *ParsedMessage) []ScoreAdjustment
```

---

## Decision Tree Integration

All enhancements feed into the existing pipeline. The final action respects the established hierarchy:

```
Message received
  │
  ├── ClamAV scan
  │     ├── Virus detected → QUARANTINE (admin quarantine)
  │     └── Clean → continue
  │
  ├── Pipeline checks (SPF/DKIM/DMARC/RBL/greylist/composites/MIME rules)
  │     ├── Score < greylist threshold → ACCEPT
  │     ├── Score ≥ greylist threshold → TEMPORARY REJECT (greylist)
  │     └── Continue scoring
  │
  ├── Statistical classification (OSB tokenizer + multi-class FTRL)
  │     ├── ham → deliver to Inbox
  │     ├── spam → deliver to Junk folder
  │     ├── newsletter → deliver to Inbox (user pref)
  │     ├── promotional → deliver to Inbox (user pref)
  │     └── phishing → QUARANTINE + admin alert
  │
  ├── Attachment checks
  │     ├── Encrypted archive + external → QUARANTINE (entire message, not deliverable)
  │     ├── Unknown external: admin reviews, release strips attachment
  │     ├── Known contact: user gets digest, can release
  │     └── Password-in-body: admin alert, never auto-release
  │     ├── Image hash match known spam → score +5.0
  │     ├── HTML structure match phishing → QUARANTINE
  │     └── Clean → deliver
  │
  └── Final delivery
        ├── QUARANTINE → admin quarantine (viruses, phishing, encrypted external)
        ├── Junk folder → user's Junk tag (spam)
        └── Inbox → user's Inbox tag (ham, newsletter, promotional)
```

## New Files

```
shared/spam/tokenizer.go          — OSB tokenizer (~150 lines)
shared/spam/tokenizer_test.go
shared/spam/multiclass.go         — Multi-class FTRL (~200 lines)
shared/spam/multiclass_test.go
shared/spam/imagehash.go          — Average hash (~150 lines)
shared/spam/imagehash_test.go
shared/spam/htmlstruct.go         — HTML structure hash (~200 lines)
shared/spam/htmlstruct_test.go
shared/spam/archive.go            — Encrypted archive detection (~100 lines)
shared/spam/archive_test.go
shared/spam/mimerules.go          — MIME content rules (~50 lines)
shared/spam/mimerules_test.go
shared/spam/composites.go         — Composite symbol evaluator (~100 lines)
mailserver/internal/smtp/spam_rules.yaml  — Composite + MIME rule config
mailserver/internal/smtp/phishing_templates.json  — Known phishing HTML structures
```

## Performance

All enhancements run in-process, no external services:
- OSB tokenizer: ~300µs per message
- Multi-class FTRL: ~100µs per message (5 small vectors vs 1)
- Image hashing: ~2ms per image (only on messages with image attachments, ~5% of traffic)
- HTML structure hash: ~500µs per HTML message
- Encrypted archive detection: ~50µs (file header check)
- MIME rules: ~100µs
- Composite evaluation: ~50µs

Total added latency per message: <5ms. At 10,000 messages/day, ~50 seconds of total CPU. Negligible.

---

## Enhancement 9: Forged Recipients Detection

### What it is
Compares SMTP envelope recipients (RCPT TO) with MIME header recipients (To, Cc). If the MIME headers claim the message is addressed to `alice@company.com` but SMTP delivered it to `bob@company.com`, the headers are forged — a common BCC-spam and phishing technique.

### Implementation
```go
// shared/spam/forged.go — ~50 lines
func DetectForgedRecipients(smtpRcpts []string, mimeTo []string, mimeCc []string) (bool, float64)
// Returns: forged=true, score=+5.0 if none of the MIME recipients match any SMTP recipient
```

---

## Enhancement 10: Reply Detection

### What it is
Tracks sent Message-IDs in Redis. When inbound mail has an `In-Reply-To` header matching a known sent message, it's a legitimate conversation reply. Apply negative score (-4.0) to prevent false positives.

### Implementation
```go
// shared/spam/reply.go — ~80 lines
func TrackSentMessage(msgID string)  // Store in Redis with TTL
func IsKnownReply(inReplyTo string) bool  // Check Redis
```

Low score (-4.0) means "this is almost certainly not spam." Doesn't override virus/phishing decisions.

---

## Enhancement 11: External Relay Detection

### What it is
Parses `Received:` headers to determine the actual sending IP chain. If a message claims to be from `@company.com` (internal domain) but the first external Received header shows it came from `203.0.113.5` (external IP), it's spoofed.

### Implementation
```go
// shared/spam/external_relay.go — ~60 lines
func DetectExternalRelay(receivedHeaders []string, internalDomains []string) (bool, string)
// Returns: relayed=true, external_ip="203.0.113.5"
// Score +5.0 for internal-domain claim + external relay mismatch
```

---

## Enhancement 12: Mixed Charset Detection

### What it is
Detects messages mixing CJK and Latin scripts in the same body. Common in Chinese-language spam: English product names ("Rolex", "Nike") embedded in Chinese text. rspamd's `chartable` module flags this as `R_MIXED_CHARSET`.

### Implementation
```go
// shared/spam/charset.go — ~40 lines
func DetectMixedCharset(text string) (bool, float64)
// Count CJK vs Latin character runs. If message has significant runs of both
// (>10% each) and isn't a legitimate bilingual message (has unsubscribe header),
// score +2.0
```

---

## Enhancement 13: Fake HTML Detection

### What it is
Detects hidden/stylized text patterns used to fool content filters while showing different content to users: `font-size: 0`, `color: white` on white background, `display: none` wrapping spam keywords, `visibility: hidden` text blocks.

### Implementation
```go
// shared/spam/fakehtml.go — ~50 lines
func DetectFakeHTML(htmlBody string) (bool, []string)
// Regex patterns: font-size:\s*0, color:\s*white|#fff|#ffffff,
// display:\s*none, visibility:\s*hidden, opacity:\s*0
// Score +5.0 if any found
```

---

## Enhancement 14: Corrupted Archive Defense

### What it is
Graceful handling of malformed ZIP/RAR/7z archives. Attackers deliberately corrupt archives to bypass scanners. rspamd's `archives.c` has extensive bounds checking. Our current code should never panic on invalid input.

### Implementation
```go
// shared/spam/archive.go — add 30 lines
// Wrap archive parsing in recover(), validate header lengths before reads,
// return safe error instead of panicking on truncated/malformed archives.
```

---

## Enhancement 15: Content Type Verification

### What it is
Check that the actual file magic bytes match the claimed Content-Type. A file claiming `Content-Type: application/pdf` but starting with `MZ` (Windows executable) or `%PDF` missing is suspicious.

### Implementation
```go
// shared/spam/content_verify.go — ~40 lines
var magicBytes = map[string][]byte{
    "application/pdf":  []byte("%PDF"),
    "image/jpeg":       []byte{0xFF, 0xD8, 0xFF},
    "image/png":        []byte{0x89, 0x50, 0x4E, 0x47},
    "application/zip":  []byte{0x50, 0x4B, 0x03, 0x04},
    "application/x-rar": []byte("Rar!"),
    "application/gzip": []byte{0x1F, 0x8B},
}

func VerifyContentType(claimedType string, headerBytes []byte) (bool, string)
// Returns: match=false, actual="application/zip"
// Score +3.0 for mismatch
```

---

## Enhancement 16: SMTP/Header Sender Mismatch

### What it is
Compare SMTP MAIL FROM (envelope sender) with the From: header (message sender). Legitimate mail has these matching. Phishing and spoofing often don't — the envelope is a compromised server, the header claims to be `ceo@company.com`.

### Implementation
```go
// shared/spam/sender_mismatch.go — ~30 lines
func DetectSenderMismatch(smtpFrom string, headerFrom string) (bool, float64)
// Compare domains. If envelope domain ≠ header domain and DMARC not aligned,
// score +3.0
// Skip if SPF/DKIM passed (legitimate forwarding, mailing lists)
```

---

## Deferred Decision: Hyperscan

**Date:** 2026-06-05
**Status:** NOT NOW — re-evaluate when conditions change

### What it is
Intel Hyperscan is a high-performance regex engine that matches thousands of patterns simultaneously in a single pass. Used by rspamd for multi-pattern matching across headers, body, URLs.

### Go bindings
`flier/gohs` exists (CGo wrapper, 240 stars). Requires `libhs.so` at compile time. ARM/M1 falls back to VectorScan community fork (Intel abandoned Hyperscan in 2023).

### Why NOT now
Our pipeline has **5 regex patterns** total. Hyperscan is optimized for 5,000+ patterns. The CGo dependency cost (cross-compilation toolchain, +5-8MB shared library, ARM compatibility issues) outweighs the ~45µs savings per message. Pipeline time is dominated by DNS queries and I/O, not regex.

### When to re-evaluate
- Pattern count exceeds **500+** (10x growth in spam rule complexity)
- Message volume exceeds **1M/day** (100x current scale)
- VectorScan ARM support reaches production stability
- A pure-Go alternative to Hyperscan emerges (Go regexp with Aho-Corasick for multi-pattern)
- Community demand for regex-based custom spam rules grows significantly

### Alternative to watch
Go's `regexp` with pre-compiled patterns + parallel goroutine matching for high pattern counts. At 500-1000 patterns, parallel Go regexp can match Hyperscan throughput without CGo.

---

## References

- rspamd OSB tokenizer: Orthogonal Sparse Bigrams for language-agnostic text classification
- rspamd multi-class Bayesian: 20-category classification (2025 FOSDEM presentation)
- rspamd fuzzy hashing: perceptual hash for spam campaign detection
- rspamd composite symbols: Boolean logic combining pipeline checks
- Gmail Promotions tab: Multi-class classification for inbox organization
- Exchange Online Protection: Encrypted attachment policies
- `mailserver/internal/smtp/pipeline.go` — existing pipeline architecture
- `mailserver/internal/spam/` — existing FTRL classifier
- Phase 17 tag system — Gmail-style labels (Inbox, Junk, Trash)
