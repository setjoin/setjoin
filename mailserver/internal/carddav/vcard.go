package carddav

import (
	"fmt"
	"strings"
	"time"
)

// VCardValue is a typed value like EMAIL or TEL.
type VCardValue struct {
	Type  string
	Value string
}

// VCardAddress represents an ADR property (7-component structured value).
type VCardAddress struct {
	Type    string
	POBox   string // position 0: post office box
	ExtAddr string // position 1: extended address
	Street  string // position 2: street address
	City    string // position 3: city/locality
	Region  string // position 4: state/province/region
	Code    string // position 5: postal code
	Country string // position 6: country
}

// VCard holds the fields we care about from a vCard 3.0.
type VCard struct {
	UID         string
	FN          string
	N           string // Family;Given;Middle;Prefix;Suffix
	ORG         string
	TITLE       string
	ROLE        string
	NOTE        string
	NICKNAME    string
	GENDER      string
	KIND        string
	PRODID      string
	PhotoURI    string
	Emails      []VCardValue
	Phones      []VCardValue
	Addresses   []VCardAddress
	URLs        []VCardValue
	IMPPs       []VCardValue
	Birthday    *time.Time
	Anniversary *time.Time
	Categories  []string
}

// contactToVCard serializes a DB contact row into a vCard 3.0 string.
func contactToVCard(contact *contactRow) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCARD\r\n")
	b.WriteString("VERSION:3.0\r\n")
	b.WriteString(escapeLine(fmt.Sprintf("UID:%s", escape(contact.VCardUID))) + "\r\n")
	b.WriteString(escapeLine(fmt.Sprintf("FN:%s", escape(contact.DisplayName))) + "\r\n")

	n := fmt.Sprintf("%s;%s;;;", escape(coalesce(contact.LastName)), escape(coalesce(contact.FirstName)))
	b.WriteString(escapeLine(fmt.Sprintf("N:%s", n)) + "\r\n")

	if coalesceStr(contact.Company) != "" {
		b.WriteString(escapeLine(fmt.Sprintf("ORG:%s", escape(coalesceStr(contact.Company)))) + "\r\n")
	}
	if coalesceStr(contact.JobTitle) != "" {
		b.WriteString(escapeLine(fmt.Sprintf("TITLE:%s", escape(coalesceStr(contact.JobTitle)))) + "\r\n")
	}
	if coalesceStr(contact.Department) != "" {
		b.WriteString(escapeLine(fmt.Sprintf("ROLE:%s", escape(coalesceStr(contact.Department)))) + "\r\n")
	}
	if coalesceStr(contact.Notes) != "" {
		b.WriteString(escapeLine(fmt.Sprintf("NOTE:%s", escape(coalesceStr(contact.Notes)))) + "\r\n")
	}
	if contact.Birthday != nil {
		b.WriteString(fmt.Sprintf("BDAY:%s\r\n", contact.Birthday.Format("20060102")))
	}
	if contact.Anniversary != nil {
		b.WriteString(fmt.Sprintf("ANNIVERSARY:%s\r\n", contact.Anniversary.Format("20060102")))
	}
	if contact.Department != nil && *contact.Department != "" {
		b.WriteString(escapeLine(fmt.Sprintf("ROLE:%s", escape(*contact.Department))) + "\r\n")
	}
	b.WriteString("KIND:individual\r\n")
	b.WriteString("PRODID:-//Mailserver//CardDAV//EN\r\n")
	if contact.Notes != nil && *contact.Notes != "" {
		b.WriteString(escapeLine(fmt.Sprintf("NOTE:%s", escape(*contact.Notes))) + "\r\n")
	}
	if contact.AvatarSHA256 != nil && *contact.AvatarSHA256 != "" {
		b.WriteString(fmt.Sprintf("PHOTO;VALUE=URI:/blobs/%s\r\n", *contact.AvatarSHA256))
	}

	for _, e := range contact.Emails {
		b.WriteString(escapeLine(fmt.Sprintf("EMAIL;TYPE=%s:%s", e.Type, escape(e.Value))) + "\r\n")
	}
	for _, p := range contact.Phones {
		b.WriteString(escapeLine(fmt.Sprintf("TEL;TYPE=%s:%s", p.Type, escape(p.Value))) + "\r\n")
	}
	for _, a := range contact.Addresses {
		adr := fmt.Sprintf("%s;%s;%s;%s;%s;%s;%s",
			a.POBox, a.ExtAddr, a.Street, a.City, a.Region, a.Code, a.Country)
		b.WriteString(escapeLine(fmt.Sprintf("ADR;TYPE=%s:%s", a.Type, escape(adr))) + "\r\n")
	}
	for _, u := range contact.URLs {
		b.WriteString(escapeLine(fmt.Sprintf("URL;TYPE=%s:%s", u.Type, escape(u.Value))) + "\r\n")
	}
	if len(contact.Categories) > 0 {
		b.WriteString(escapeLine(fmt.Sprintf("CATEGORIES:%s", escape(strings.Join(contact.Categories, ",")))) + "\r\n")
	}

	b.WriteString(fmt.Sprintf("REV:%s\r\n", contact.UpdatedAt.UTC().Format("20060102T150405Z")))
	b.WriteString("END:VCARD\r\n")
	return b.String()
}

// parseVCard parses a minimal vCard 3.0 into a VCard struct.
func parseVCard(data string) (VCard, error) {
	var vc VCard
	lines := unfoldLines(data)
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "BEGIN:VCARD" || line == "END:VCARD" {
			continue
		}
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "UID:"):
			vc.UID = unescape(strings.TrimPrefix(line, "UID:"))
		case strings.HasPrefix(upper, "FN:"):
			vc.FN = unescape(strings.TrimPrefix(line, "FN:"))
		case strings.HasPrefix(upper, "N:"):
			vc.N = unescape(strings.TrimPrefix(line, "N:"))
		case strings.HasPrefix(upper, "ORG:"):
			vc.ORG = unescape(strings.TrimPrefix(line, "ORG:"))
		case strings.HasPrefix(upper, "TITLE:"):
			vc.TITLE = unescape(strings.TrimPrefix(line, "TITLE:"))
		case strings.HasPrefix(upper, "ROLE:"):
			vc.ROLE = unescape(strings.TrimPrefix(line, "ROLE:"))
		case strings.HasPrefix(upper, "NOTE:"):
			vc.NOTE = unescape(strings.TrimPrefix(line, "NOTE:"))
		case strings.HasPrefix(upper, "BDAY:"):
			if t, err := time.Parse("20060102", strings.TrimPrefix(line, "BDAY:")); err == nil {
				vc.Birthday = &t
			}
		case strings.HasPrefix(upper, "ANNIVERSARY:"):
			if t, err := time.Parse("20060102", strings.TrimPrefix(line, "ANNIVERSARY:")); err == nil {
				vc.Anniversary = &t
			}
		case strings.HasPrefix(upper, "NICKNAME:"):
			vc.NICKNAME = unescape(strings.TrimPrefix(line, "NICKNAME:"))
		case strings.HasPrefix(upper, "GENDER:"):
			vc.GENDER = strings.TrimPrefix(line, "GENDER:")
		case strings.HasPrefix(upper, "KIND:"):
			vc.KIND = strings.TrimPrefix(line, "KIND:")
		case strings.HasPrefix(upper, "PRODID:"):
			vc.PRODID = strings.TrimPrefix(line, "PRODID:")
		case strings.HasPrefix(upper, "X-IMPP") || strings.HasPrefix(upper, "IMPP"):
			if v := parseParamValue(line); v != nil {
				vc.IMPPs = append(vc.IMPPs, *v)
			}
		case strings.HasPrefix(upper, "EMAIL"):
			if v := parseParamValue(line); v != nil {
				vc.Emails = append(vc.Emails, *v)
			}
		case strings.HasPrefix(upper, "TEL"):
			if v := parseParamValue(line); v != nil {
				vc.Phones = append(vc.Phones, *v)
			}
		case strings.HasPrefix(upper, "ADR"):
			if a := parseAddress(line); a != nil {
				vc.Addresses = append(vc.Addresses, *a)
			}
		case strings.HasPrefix(upper, "URL"):
			if v := parseParamValue(line); v != nil {
				vc.URLs = append(vc.URLs, *v)
			}
		case strings.HasPrefix(upper, "CATEGORIES:"):
			vc.Categories = splitComma(unescape(strings.TrimPrefix(line, "CATEGORIES:")))
		case strings.HasPrefix(upper, "PHOTO"):
			if strings.Contains(line, "/blobs/") {
				parts := strings.Split(line, "/blobs/")
				if len(parts) == 2 {
					vc.PhotoURI = strings.TrimSpace(parts[1])
				}
			}
		}
	}
	if vc.FN == "" && vc.N != "" {
		parts := strings.Split(vc.N, ";")
		if len(parts) >= 2 {
			vc.FN = strings.TrimSpace(parts[1] + " " + parts[0])
		} else if len(parts) == 1 {
			vc.FN = strings.TrimSpace(parts[0])
		}
	}
	if vc.UID == "" {
		return vc, fmt.Errorf("missing UID")
	}
	return vc, nil
}

// ParseVCard is the public wrapper for parseVCard (used by the migration package).
func ParseVCard(data string) (VCard, error) {
	return parseVCard(data)
}

func parseParamValue(line string) *VCardValue {
	// Format: PROPERTY;TYPE=xxx:value or PROPERTY:value
	propEnd := strings.Index(line, ":")
	if propEnd < 0 {
		return nil
	}
	value := unescape(line[propEnd+1:])
	propPart := line[:propEnd]
	var typ string
	for _, p := range strings.Split(propPart, ";") {
		if strings.HasPrefix(strings.ToUpper(p), "TYPE=") {
			typ = strings.ToLower(strings.TrimPrefix(p, "TYPE="))
			break
		}
	}
	if typ == "" {
		typ = "other"
	}
	return &VCardValue{Type: typ, Value: value}
}

func parseAddress(line string) *VCardAddress {
	propEnd := strings.Index(line, ":")
	if propEnd < 0 {
		return nil
	}
	value := line[propEnd+1:]
	propPart := line[:propEnd]
	var typ string
	for _, p := range strings.Split(propPart, ";") {
		if strings.HasPrefix(strings.ToUpper(p), "TYPE=") {
			typ = strings.ToLower(strings.TrimPrefix(p, "TYPE="))
			break
		}
	}
	if typ == "" {
		typ = "other"
	}
	parts := strings.Split(unescape(value), ";")
	a := &VCardAddress{Type: typ}
	if len(parts) > 0 {
		a.POBox = parts[0]
	}
	if len(parts) > 1 {
		a.ExtAddr = parts[1]
	}
	if len(parts) > 2 {
		a.Street = parts[2]
	}
	if len(parts) > 3 {
		a.City = parts[3]
	}
	if len(parts) > 4 {
		a.Region = parts[4]
	}
	if len(parts) > 5 {
		a.Code = parts[5]
	}
	if len(parts) > 6 {
		a.Country = parts[6]
	}
	return a
}

func unfoldLines(data string) []string {
	lines := strings.Split(data, "\n")
	var out []string
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if len(out) > 0 {
				out[len(out)-1] += strings.TrimLeft(line, " \t")
			}
		} else {
			out = append(out, line)
		}
	}
	return out
}

func escapeLine(s string) string {
	if len(s) <= 75 {
		return s
	}
	var parts []string
	for len(s) > 75 {
		split := 75
		for split > 0 && split < len(s) && s[split]&0xC0 == 0x80 {
			split--
		}
		if split == 0 {
			split = 75
		}
		parts = append(parts, s[:split])
		s = s[split:]
	}
	parts = append(parts, s)
	return strings.Join(parts, "\r\n ")
}

func escape(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, ";", "\\;")
	s = strings.ReplaceAll(s, ",", "\\,")
	s = strings.ReplaceAll(s, "\n", "\\n")
	return s
}

func unescape(s string) string {
	s = strings.ReplaceAll(s, "\\n", "\n")
	s = strings.ReplaceAll(s, "\\r", "\r")
	s = strings.ReplaceAll(s, "\\,", ",")
	s = strings.ReplaceAll(s, "\\;", ";")
	s = strings.ReplaceAll(s, "\\\\", "\\")
	return s
}

func coalesce(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
