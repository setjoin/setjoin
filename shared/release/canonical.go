package release

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

func strictDecode(data []byte, dst any) error {
	if len(data) == 0 {
		return fmt.Errorf("empty document")
	}
	if len(data) > MaxDocumentBytes {
		return fmt.Errorf("document exceeds %d bytes", MaxDocumentBytes)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var walk func() error
	walk = func() error {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				if _, exists := seen[key]; exists {
					return fmt.Errorf("duplicate JSON key %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := dec.Token()
			if err != nil || closing != json.Delim('}') {
				return fmt.Errorf("invalid JSON object")
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
			closing, err := dec.Token()
			if err != nil || closing != json.Delim(']') {
				return fmt.Errorf("invalid JSON array")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter %q", delim)
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func CanonicalManifest(m *Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	copy := *m
	copy.Signatures = nil
	return json.Marshal(&copy)
}
func CanonicalEntitlement(e *Entitlement) ([]byte, error) {
	if err := e.ValidateUnsigned(); err != nil {
		return nil, err
	}
	copy := *e
	copy.Signatures = nil
	return json.Marshal(&copy)
}
func MarshalManifest(m *Manifest) ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}
func MarshalEntitlement(e *Entitlement) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}
