package jmap

import (
	"encoding/json"
	"strconv"
)

// parse.go — the c4 position-aware argument codec. One constructor for
// method-level errors, one scalar-id parser that names the offending property,
// and one list parser whose malformed entries the caller folds into the
// method's per-record bucket (notFound / notDestroyed / notRecovered /
// notPurged) instead of silently dropping them.

// methodError builds the ("error", args) method-response pair every JMAP
// method-level error in this package routes through.
func methodError(typ, description string) (string, json.RawMessage) {
	errJSON, _ := json.Marshal(Error{Type: typ, Description: description})
	return "error", errJSON
}

// parseID parses one per-record JMAP object id. Ids are positive BIGSERIALs,
// so ok=false means the id can never exist: the caller reports it per-record
// (RFC 8620 §5.1/§5.3) rather than dropping it.
func parseID(id string) (int64, bool) {
	v, err := strconv.ParseInt(id, 10, 64)
	return v, err == nil && v > 0
}

// parseArg parses a required scalar id argument. On failure it returns a
// non-nil invalidArguments payload naming the property, so every malformed
// scalar id rejects with the same position-aware error.
func parseArg(id, property string) (int64, json.RawMessage) {
	if v, ok := parseID(id); ok {
		return v, nil
	}
	errJSON, _ := json.Marshal(Error{Type: "invalidArguments", Description: "invalid " + property})
	return 0, errJSON
}

// parseIDList splits per-record id strings into the valid int64s and the
// malformed originals. When every entry is malformed, valid is a non-nil
// empty slice — so the reducer receives an EMPTY array (fetch/destroy none),
// never NULL (which means "all" on get paths and errors FOREACH on set paths).
func parseIDList(ids []string) (valid []int64, bad []string) {
	for _, id := range ids {
		if v, ok := parseID(id); ok {
			valid = append(valid, v)
		} else {
			bad = append(bad, id)
		}
	}
	if valid == nil && bad != nil {
		valid = []int64{}
	}
	return valid, bad
}

// addNotFound folds malformed requested ids into a get-response's `notFound`
// array (RFC 8620 §5.1: an id that cannot exist is notFound). result is
// returned byte-identical when bad is empty — the valid-input wire shape is
// untouched.
func addNotFound(result json.RawMessage, bad []string) json.RawMessage {
	if len(bad) == 0 || len(result) == 0 {
		return result
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(result, &obj); err != nil {
		return result
	}
	var arr []any
	if raw, ok := obj["notFound"]; ok {
		_ = json.Unmarshal(raw, &arr) // null / absent → arr stays nil
	}
	for _, id := range bad {
		arr = append(arr, id)
	}
	notFound, err := json.Marshal(arr)
	if err != nil {
		return result
	}
	obj["notFound"] = notFound
	out, err := json.Marshal(obj)
	if err != nil {
		return result
	}
	return out
}

// addSetErrors folds malformed per-record ids into a set-style response's
// map bucket (notDestroyed / notRecovered / notPurged) as
// {"<id>": {"type": "notFound"}} — the same shape the reducers emit for
// well-formed-but-nonexistent ids. Byte-identical when bad is empty.
func addSetErrors(result json.RawMessage, key string, bad []string) json.RawMessage {
	if len(bad) == 0 {
		return result
	}
	obj := map[string]json.RawMessage{}
	if len(result) > 0 {
		if err := json.Unmarshal(result, &obj); err != nil {
			return result
		}
	}
	m := map[string]json.RawMessage{}
	if raw, ok := obj[key]; ok {
		_ = json.Unmarshal(raw, &m) // null → m stays empty
	}
	for _, id := range bad {
		m[id] = json.RawMessage(`{"type":"notFound"}`)
	}
	bucket, err := json.Marshal(m)
	if err != nil {
		return result
	}
	obj[key] = bucket
	out, err := json.Marshal(obj)
	if err != nil {
		return result
	}
	return out
}
