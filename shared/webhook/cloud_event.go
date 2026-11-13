package webhook

import (
	"crypto/rand"
	"encoding/json"
	"time"
)

// CloudEvent is a CloudEvents 1.0.2 envelope.
type CloudEvent struct {
	SpecVersion     string      `json:"specversion"`
	ID              string      `json:"id"`
	Source          string      `json:"source"`
	Type            string      `json:"type"`
	Time            string      `json:"time"`
	DataContentType string      `json:"datacontenttype,omitempty"`
	Data            interface{} `json:"data"`
}

// NewCloudEvent creates a CloudEvent with a unique nanoid-based ID.
func NewCloudEvent(source, eventType string, data interface{}) CloudEvent {
	return CloudEvent{
		SpecVersion:     "1.0",
		ID:              "evt_" + nanoid(13),
		Source:          source,
		Type:            eventType,
		Time:            time.Now().UTC().Format(time.RFC3339),
		DataContentType: "application/json",
		Data:            data,
	}
}

// Marshal returns the JSON-encoded CloudEvent bytes.
func (e CloudEvent) Marshal() ([]byte, error) {
	return json.Marshal(e)
}

// nanoid generates a URL-safe random ID of the given length.
func nanoid(n int) string {
	const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	randBytes := make([]byte, n)
	if _, err := rand.Read(randBytes); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	for i := range b {
		b[i] = alphabet[randBytes[i]%byte(len(alphabet))]
	}
	return string(b)
}
