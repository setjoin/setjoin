package admin

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// IdentitySourceRuntimeConfig is the bounded, decrypted runtime projection of
// an active AD or LDAP source. Secret material remains private to this package
// and is exposed only through BindPassword so generic formatting cannot print
// it accidentally.
type IdentitySourceRuntimeConfig struct {
	SourceKey        string
	Kind             string
	Host             string
	Port             int
	Transport        string
	BaseDN           string
	BindDN           string
	SubjectAttribute string
	UserFilter       string
	GroupFilter      string
	bindPassword     string
}

func (c IdentitySourceRuntimeConfig) BindPassword() string {
	return c.bindPassword
}

// DecodeIdentitySourceRuntime decrypts and revalidates the stored declarative
// source before it reaches a connector. The same validator used by plan/apply
// owns accepted fields, so runtime parsing cannot silently drift into a second
// source schema.
func DecodeIdentitySourceRuntime(
	codec *ConfigSecretCodec,
	sourceKey string,
	rowKind string,
	envelope []byte,
) (IdentitySourceRuntimeConfig, error) {
	if codec == nil || len(envelope) == 0 {
		return IdentitySourceRuntimeConfig{}, errors.New("identity source secret codec or envelope is unavailable")
	}
	plain, err := codec.Decrypt("identity_source."+sourceKey, envelope)
	if err != nil {
		return IdentitySourceRuntimeConfig{}, fmt.Errorf("decrypt identity source runtime: %w", err)
	}
	var stored identityStoredSourceDocument
	if err := decodeStrictJSON(plain, &stored); err != nil {
		return IdentitySourceRuntimeConfig{}, fmt.Errorf("decode identity source runtime envelope: %w", err)
	}
	document, _, err := validateIdentitySourceDocument(stored.Document)
	if err != nil {
		return IdentitySourceRuntimeConfig{}, fmt.Errorf("validate identity source runtime document: %w", err)
	}
	if document.Metadata.SourceKey != sourceKey {
		return IdentitySourceRuntimeConfig{}, errors.New("identity source runtime key does not match catalog row")
	}

	var spec struct {
		Type     string `json:"type"`
		Endpoint struct {
			Host string `json:"host"`
			Port int    `json:"port"`
			TLS  string `json:"tls"`
		} `json:"endpoint"`
		SubjectAttribute string `json:"subjectAttribute"`
		BaseDN           string `json:"baseDN"`
		BindDN           string `json:"bindDN"`
		UserFilter       string `json:"userFilter"`
		GroupFilter      string `json:"groupFilter"`
	}
	if err := json.Unmarshal(document.Spec, &spec); err != nil {
		return IdentitySourceRuntimeConfig{}, fmt.Errorf("decode identity source runtime spec: %w", err)
	}
	if spec.Type != rowKind || (spec.Type != "ad" && spec.Type != "ldap") {
		return IdentitySourceRuntimeConfig{}, errors.New("identity source runtime kind does not match catalog row")
	}
	encodedPassword := stored.Secrets["bindPassword"]
	if encodedPassword == "" {
		return IdentitySourceRuntimeConfig{}, errors.New("identity source bind password is not configured")
	}
	passwordBytes, err := base64.StdEncoding.DecodeString(encodedPassword)
	if err != nil || len(passwordBytes) == 0 {
		return IdentitySourceRuntimeConfig{}, errors.New("identity source bind password encoding is invalid")
	}
	password := string(passwordBytes)
	clear(passwordBytes)
	return IdentitySourceRuntimeConfig{
		SourceKey:        sourceKey,
		Kind:             spec.Type,
		Host:             spec.Endpoint.Host,
		Port:             spec.Endpoint.Port,
		Transport:        spec.Endpoint.TLS,
		BaseDN:           spec.BaseDN,
		BindDN:           spec.BindDN,
		SubjectAttribute: spec.SubjectAttribute,
		UserFilter:       spec.UserFilter,
		GroupFilter:      spec.GroupFilter,
		bindPassword:     password,
	}, nil
}
