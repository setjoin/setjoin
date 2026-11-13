package spam

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"golang.org/x/net/html"
)

// StructStatus is the fail-closed outcome channel for HTML structure
// extraction. The status, never the hash string, is the classification
// signal: on any status other than StructOK the hash is "" and no benign
// conclusion may be drawn.
type StructStatus uint8

const (
	// StructOK: input parsed, stayed within the StructBudget, and a
	// structure hash was produced.
	StructOK StructStatus = iota
	// StructEmpty: the input is empty (or parses to no structural
	// content), so there is nothing to hash. Not an error, but not a
	// hashable structure either.
	StructEmpty
	// StructBudgetExceeded: the input or the walked structure exceeded the
	// StructBudget (depth, input size, or serialized size) and the walk was
	// abandoned. Unclassifiable by design.
	StructBudgetExceeded
	// StructUnparseable: the HTML parser rejected the input outright (for
	// example nesting deep enough to exhaust the parser's open-element
	// stack). Unclassifiable by design.
	StructUnparseable
)

// String returns a stable, lowercase name for the status, for logs.
func (s StructStatus) String() string {
	switch s {
	case StructOK:
		return "ok"
	case StructEmpty:
		return "empty"
	case StructBudgetExceeded:
		return "budget_exceeded"
	case StructUnparseable:
		return "unparseable"
	default:
		return "unknown"
	}
}

// Depth and size ceilings for structure extraction. These are constants,
// owner-tunable at the wiring seam via StructBudget, not config surfaces.
const (
	// defaultStructMaxDepth bounds element nesting the walker will descend.
	// 512 covers real-world newsletter/table HTML (typical legitimate depth
	// is under ~100 levels) while staying far inside fatal-stack territory:
	// the walk is iterative, so this is a memory/DoS bound plus a contract
	// that holds for tree shapes not produced by the pinned parser. It must
	// not be derived from x/net parse behavior, which is pinned-dependency
	// detail that already drifted once (see manifest r2-C7-1).
	defaultStructMaxDepth = 512
	// defaultStructMaxInputBytes caps the raw HTML accepted for parsing
	// (2 MiB comfortably covers real message HTML parts; larger parts are
	// adversarial for this detector's purposes).
	defaultStructMaxInputBytes = 2 << 20 // 2 MiB
	// defaultStructMaxStructureBytes caps the serialized structure string
	// before hashing. The serialization collapses text to "TEXT" and drops
	// attribute values, so it is rarely larger than its input; matching the
	// input cap bounds worst-case expansion from attribute-heavy markup.
	defaultStructMaxStructureBytes = 2 << 20 // 2 MiB
)

// StructBudget bounds the work extractStructureHash may perform.
// A non-positive limit fails closed: every input exceeds it.
type StructBudget struct {
	MaxDepth          int // maximum element nesting levels to walk
	MaxInputBytes     int // maximum raw HTML length accepted for parsing
	MaxStructureBytes int // maximum serialized structure length before hashing
}

// DefaultStructBudget returns the package-default budget. The numbers are
// named constants with the rationale above; they are deliberately far from
// fatal-stack territory (the pre-rewrite recursive walker could burn
// ~130+ MB of stack on a 25 MB nested part; the iterative walker burns
// bounded heap under this budget regardless).
func DefaultStructBudget() StructBudget {
	return StructBudget{
		MaxDepth:          defaultStructMaxDepth,
		MaxInputBytes:     defaultStructMaxInputBytes,
		MaxStructureBytes: defaultStructMaxStructureBytes,
	}
}

// StructureHash computes a SHA-256 hash of the HTML DOM tree structure,
// ignoring text content and attribute values. This catches phishing emails
// that copy a legitimate service's HTML template exactly, changing only
// the text and URLs.
//
// What is preserved in the hash:
//   - Tag names (html, body, div, form, input, etc.)
//   - Class and id attribute NAMES (not values — values change between copies)
//   - The parent-child nesting structure
//
// What is normalized away:
//   - All text content → replaced with "TEXT"
//   - All attribute values (href, src, etc.)
//   - Whitespace between elements
//
// The result is the first 128 bits (32 hex chars) of the SHA-256 digest.
// Returns empty string if the HTML is empty, cannot be parsed, or exceeds
// the DefaultStructBudget.
//
// Compatibility wrapper only: the string return cannot distinguish "clean
// miss" from "budget exhausted" or "unparseable", both of which hash to "".
// Classification paths must use ClassifyStructure, which carries the status
// on the result; do not wire this wrapper into scoring decisions.
func StructureHash(htmlStr string) string {
	hash, status := extractStructureHash(htmlStr, DefaultStructBudget())
	if status != StructOK {
		return ""
	}
	return hash
}

// ExtractStructureHash is the budgeted form of StructureHash. It returns the
// structure hash together with the StructStatus outcome. On any status other
// than StructOK the hash is "": the status is the classification signal, and
// callers must map non-OK statuses per the owner-decided policy — never to a
// benign miss.
func ExtractStructureHash(htmlStr string, budget StructBudget) (string, StructStatus) {
	return extractStructureHash(htmlStr, budget)
}

// ClassifyStructure is the public classification boundary for HTML structure
// phishing matching. It runs budgeted extraction internally and returns the
// status ON the result:
//
//	status != StructOK  =>  (false, "", status) — unclassifiable, never benign
//	known == true       =>  requires status == StructOK
//
// The wiring contract (future phishing-feed package): the live path calls
// this function and maps StructBudgetExceeded / StructUnparseable /
// StructEmpty per the owner-decided reject-vs-static-classify policy —
// never to a benign miss. Unclassifiable and clean-miss outcomes are
// distinguishable by types at this one call; no caller-side discipline is
// required.
func ClassifyStructure(htmlStr string, templates map[string]string, budget StructBudget) (known bool, template string, status StructStatus) {
	hash, st := extractStructureHash(htmlStr, budget)
	if st != StructOK {
		return false, "", st
	}
	known, template = IsKnownPhishing(hash, templates)
	return known, template, StructOK
}

// extractStructureHash parses htmlStr under budget and hashes the normalized
// structure. Fail-closed: every non-OK outcome returns "" with its status.
func extractStructureHash(htmlStr string, budget StructBudget) (string, StructStatus) {
	if htmlStr == "" {
		return "", StructEmpty
	}
	if len(htmlStr) > budget.MaxInputBytes {
		// Input-size cap is checked before parsing: oversized parts are an
		// adversarial-input outcome, not a parse failure.
		return "", StructBudgetExceeded
	}

	doc, err := html.Parse(strings.NewReader(htmlStr))
	if err != nil {
		// The pinned x/net parser converts its own limits (e.g. the
		// 512-open-element cap at v0.58.0) into parse errors. Exhausting the
		// parser's cap on adversarially nested input is a real
		// classification input today and MUST surface as StructUnparseable —
		// not collapse to a "" hash that clean-misses in template lookup.
		return "", StructUnparseable
	}
	if doc == nil {
		return "", StructUnparseable
	}

	structure, status := extractStructureBounded(doc, budget)
	if status != StructOK {
		return "", status
	}
	if structure == "" {
		// Nothing structural to hash (defensive: the parser synthesizes
		// html/body for any input, so this is not reachable through
		// html.Parse today; programmatic callers can hit it).
		return "", StructEmpty
	}

	h := sha256.Sum256([]byte(structure))
	return hex.EncodeToString(h[:16]), StructOK // first 128 bits
}

// structFrame is one open container on the explicit walk stack.
type structFrame struct {
	elem     bool       // true for element frames (framed with parens)
	prefix   string     // element framing: "(tag|@class|@id"; "" for document/doctype
	depth    int        // element nesting depth of this container (root container = 0)
	children []string   // serialized non-empty children so far
	next     *html.Node // next child to process
}

// extractStructureBounded serializes an HTML node tree into the normalized
// structure string using an explicit frame stack — strictly iterative, one
// heap frame per open element, no Go recursion on tree depth. Depth is
// tracked while pushing frames and the serialized size while appending, so
// both budgets are enforced inside OUR walk; nothing is assumed from x/net
// parse behavior.
//
// Serialization is byte-identical to the original recursive serializer
// (golden-hash continuity): text nodes become "TEXT", elements become
// "(tagname|@class|@id children)", document/doctype nodes serialize as the
// space-joined serialization of their children, and empty child
// serializations are omitted at fold time — matching the recursive
// original's `if s != ""` filter, so a doctype contributes no bytes.
//
// On budget exhaustion it stops and returns ("", StructBudgetExceeded) — a
// partial structure is never synthesized.
func extractStructureBounded(root *html.Node, budget StructBudget) (string, StructStatus) {
	if root == nil {
		return "", StructEmpty
	}

	// total tracks the exact serialized length of the final structure:
	// framing bytes at frame push, child separators at append, the child
	// space at close. Checked after every increment; monotone.
	var (
		stack []*structFrame
		total int
	)
	checkBudget := func() StructStatus {
		if total > budget.MaxStructureBytes {
			return StructBudgetExceeded
		}
		return StructOK
	}

	pushFrame := func(n *html.Node, depth int) {
		f := &structFrame{depth: depth, next: n.FirstChild}
		if n.Type == html.ElementNode {
			f.elem = true
			f.prefix = "(" + n.Data
			for _, attr := range n.Attr {
				if attr.Key == "class" || attr.Key == "id" {
					f.prefix += "|@" + attr.Key
				}
			}
			total += len(f.prefix) + 1 // opening "(" and closing ")"
		}
		stack = append(stack, f)
	}

	pushFrame(root, 0)
	if checkBudget() != StructOK {
		return "", StructBudgetExceeded
	}

	rootResult := ""
	for len(stack) > 0 {
		f := stack[len(stack)-1]

		// Advance to the next child that contributes output; comments and
		// other node types serialize to "".
		c := f.next
		for c != nil && !structChildRelevant(c) {
			c = c.NextSibling
		}
		f.next = c

		if c == nil {
			// Frame complete: close it and fold into the parent.
			stack = stack[:len(stack)-1]
			var serialized string
			if f.elem {
				if len(f.children) > 0 {
					serialized = f.prefix + " " + strings.Join(f.children, " ") + ")"
					total++ // space between prefix and children
				} else {
					serialized = f.prefix + ")"
				}
			} else {
				// DocumentNode / DoctypeNode: children joined by spaces.
				serialized = strings.Join(f.children, " ")
			}
			if len(stack) == 0 {
				rootResult = serialized
				break
			}
			if serialized == "" {
				// Astra L2-C7 hash continuity: a transparent container that
				// serializes to "" (a doctype frame has no children) must be
				// OMITTED when folding, exactly as the original recursive
				// serializer's `if s != ""` filter did. Appending the empty
				// string made strings.Join emit a leading separator,
				// shifting every hash for doctype-bearing inputs (adding
				// <!doctype html> moved <p>Hello</p> from 36c7… to 14f6…).
				// Element frames are never empty ("(tag)" minimum).
				continue
			}
			parent := stack[len(stack)-1]
			if len(parent.children) > 0 {
				total++ // join separator
			}
			parent.children = append(parent.children, serialized)
			if checkBudget() != StructOK {
				return "", StructBudgetExceeded
			}
			continue
		}

		f.next = c.NextSibling
		switch c.Type {
		case html.TextNode:
			if strings.TrimSpace(c.Data) == "" {
				continue
			}
			if len(f.children) > 0 {
				total++ // join separator
			}
			f.children = append(f.children, "TEXT")
			total += len("TEXT")
		case html.ElementNode:
			if f.depth+1 > budget.MaxDepth {
				return "", StructBudgetExceeded
			}
			pushFrame(c, f.depth+1)
		case html.DocumentNode, html.DoctypeNode:
			// Transparent container: serialize children at the same depth.
			pushFrame(c, f.depth)
		default:
			// Comment and other node types serialize to "".
		}
		if checkBudget() != StructOK {
			return "", StructBudgetExceeded
		}
	}

	return rootResult, StructOK
}

// structChildRelevant reports whether a node can contribute output.
func structChildRelevant(n *html.Node) bool {
	switch n.Type {
	case html.TextNode, html.ElementNode, html.DocumentNode, html.DoctypeNode:
		return true
	default:
		return false
	}
}

// IsKnownPhishing checks a structure hash against a database of known phishing
// templates. Returns true and the template name if a match is found.
//
// The templates map is keyed by structure hash hex strings (as produced by
// StructureHash) and valued by human-readable template descriptions.
//
// Pure map-lookup primitive: performs NO parsing, carries NO status, and an
// empty or unknown hash is indistinguishable from a clean miss. It must not
// be the wiring entry — use ClassifyStructure, whose result carries the
// StructStatus needed to keep budget-exhausted and unparseable inputs from
// silently classifying as benign.
func IsKnownPhishing(hash string, templates map[string]string) (bool, string) {
	if templates == nil {
		return false, ""
	}
	name, ok := templates[hash]
	return ok, name
}
