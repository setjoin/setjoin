package jmap

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ResultReference is the RFC 8620 §3.7 object form of a "#argName" value: an
// argument whose value is taken from the result of an earlier method call in
// the same request. The client writes `{"#ids": {"resultOf":"t0",
// "name":"Email/query","path":"/ids/*"}}`; the server resolves it before the
// referencing method runs.
type ResultReference struct {
	// ResultOf is the call id (the 3rd array element / ClientID) of a prior
	// method call in this request.
	ResultOf string `json:"resultOf"`
	// Name is the required response name of that prior call (e.g. "Email/query").
	Name string `json:"name"`
	// Path is a JSON Pointer (RFC 6901) into the prior response's args object,
	// with the §3.7 "*" array-map + flatten extension.
	Path string `json:"path"`
}

// resolveReferences evaluates every "#name" argument in `args` against the
// already-emitted `prior` method responses (in order) per RFC 8620 §3.7 and
// returns the rewritten args. `args` arrives as the raw JSON the client sent;
// each `#foo` key is replaced by a plain `foo` key holding the resolved value.
//
// It returns a non-nil *Error when:
//   - an args object carries both "foo" and "#foo"            → invalidArguments
//   - a "#foo" value is not a well-formed ResultReference     → invalidResultReference
//   - no prior response has the referenced resultOf call id   → invalidResultReference
//   - the matched prior response's name differs from `name`   → invalidResultReference
//     (an errored predecessor has response name "error", so it fails here)
//   - the JSON Pointer `path` does not resolve                → invalidResultReference
//
// When `args` contains no `#`-prefixed key it is returned unchanged (the common
// non-chained path is a no-op).
func resolveReferences(args json.RawMessage, prior []MethodCall) (json.RawMessage, *Error) {
	if len(args) == 0 {
		return args, nil
	}
	// Decode into an ordered-insensitive map; back-refs are keyed by name so a
	// plain map is sufficient (RFC argument names are unique within an object).
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(args, &obj); err != nil {
		// Not a JSON object (or invalid JSON). There is nothing to resolve here;
		// hand the raw args through so Dispatch produces the normal
		// invalidArguments error for non-object args, preserving prior behavior.
		return args, nil
	}

	// Fast path: no reference keys at all.
	hasRef := false
	for k := range obj {
		if strings.HasPrefix(k, "#") {
			hasRef = true
			break
		}
	}
	if !hasRef {
		return args, nil
	}

	out := make(map[string]json.RawMessage, len(obj))
	for k, v := range obj {
		if !strings.HasPrefix(k, "#") {
			out[k] = v
		}
	}

	for k, v := range obj {
		if !strings.HasPrefix(k, "#") {
			continue
		}
		argName := k[1:]
		// RFC §3.7: "foo" and "#foo" in the same object → invalidArguments.
		if _, clash := obj[argName]; clash {
			return nil, &Error{
				Type:        "invalidArguments",
				Description: fmt.Sprintf("argument %q given in both plain and referenced (#%s) form", argName, argName),
			}
		}

		var ref ResultReference
		if err := json.Unmarshal(v, &ref); err != nil || ref.ResultOf == "" || ref.Name == "" {
			return nil, &Error{
				Type:        "invalidResultReference",
				Description: fmt.Sprintf("malformed ResultReference for #%s", argName),
			}
		}

		resolved, err := evalResultReference(ref, prior)
		if err != nil {
			return nil, &Error{
				Type:        "invalidResultReference",
				Description: fmt.Sprintf("#%s: %v", argName, err),
			}
		}
		encoded, mErr := json.Marshal(resolved)
		if mErr != nil {
			return nil, &Error{
				Type:        "invalidResultReference",
				Description: fmt.Sprintf("#%s: cannot encode resolved value: %v", argName, mErr),
			}
		}
		out[argName] = encoded
	}

	rewritten, err := json.Marshal(out)
	if err != nil {
		return nil, &Error{Type: "invalidResultReference", Description: err.Error()}
	}
	return rewritten, nil
}

// evalResultReference runs steps 1–3 of the RFC §3.7 resolution algorithm:
// find the first prior response whose call id == ref.ResultOf, check its name,
// then apply the path pointer to its args object.
func evalResultReference(ref ResultReference, prior []MethodCall) (any, error) {
	var match *MethodCall
	for i := range prior {
		if prior[i].ClientID == ref.ResultOf {
			match = &prior[i]
			break
		}
	}
	if match == nil {
		return nil, fmt.Errorf("no prior response with resultOf %q", ref.ResultOf)
	}
	// Step 2: the response name must match. An errored predecessor has
	// response name "error", so this rejects reading into an error payload.
	if match.Name != ref.Name {
		return nil, fmt.Errorf("response name %q does not match referenced name %q", match.Name, ref.Name)
	}

	var doc any
	if len(match.Args) == 0 {
		doc = nil
	} else if err := json.Unmarshal(match.Args, &doc); err != nil {
		return nil, fmt.Errorf("prior response args are not valid JSON: %w", err)
	}

	return evalPointer(doc, ref.Path)
}

// evalPointer applies an RFC 6901 JSON Pointer to a decoded JSON value, with
// the RFC 8620 §3.7 extension that a "*" reference token maps the remaining
// tokens through every element of the current array and flattens one level of
// array-of-arrays. Pure and table-testable.
//
// An empty pointer ("") returns the whole document. A pointer that does not
// begin with "/" (and is non-empty) is malformed per RFC 6901.
func evalPointer(doc any, pointer string) (any, error) {
	if pointer == "" {
		return doc, nil
	}
	if !strings.HasPrefix(pointer, "/") {
		return nil, fmt.Errorf("invalid JSON Pointer %q: must be empty or begin with '/'", pointer)
	}
	tokens := strings.Split(pointer[1:], "/")
	return evalTokens(doc, tokens)
}

// evalTokens walks the remaining reference tokens against the current value.
func evalTokens(cur any, tokens []string) (any, error) {
	for i, tok := range tokens {
		// §3.7 array-map extension: a bare "*" maps the rest of the tokens
		// across every array element, flattening one level of nested arrays.
		if tok == "*" {
			arr, ok := cur.([]any)
			if !ok {
				return nil, fmt.Errorf("'*' applied to non-array value")
			}
			rest := tokens[i+1:]
			out := make([]any, 0, len(arr))
			for _, item := range arr {
				v, err := evalTokens(item, rest)
				if err != nil {
					return nil, err
				}
				// Flatten one level: if applying the rest produced an array,
				// splice its items in rather than nesting.
				if sub, isArr := v.([]any); isArr {
					out = append(out, sub...)
				} else {
					out = append(out, v)
				}
			}
			return out, nil
		}

		key := unescapePointerToken(tok)
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[key]
			if !ok {
				return nil, fmt.Errorf("pointer token %q not found in object", key)
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(key)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, fmt.Errorf("pointer token %q is not a valid index into array of length %d", key, len(node))
			}
			cur = node[idx]
		default:
			return nil, fmt.Errorf("pointer token %q applied to non-container value", key)
		}
	}
	return cur, nil
}

// unescapePointerToken decodes the RFC 6901 escape sequences: "~1" → "/" and
// "~0" → "~". Order matters: ~1 must be decoded before ~0 (RFC 6901 §4).
func unescapePointerToken(tok string) string {
	tok = strings.ReplaceAll(tok, "~1", "/")
	tok = strings.ReplaceAll(tok, "~0", "~")
	return tok
}
