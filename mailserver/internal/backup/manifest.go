package backup

// Manifest represents a blob manifest file stored in the backup bucket. Each run
// writes a FULL inventory (every live blob hash), so a manifest is a self-contained
// restore point — there is no delta chain and no synthetic-full merge.
type Manifest struct {
	Timestamp string   `json:"timestamp"`
	Type      string   `json:"type"` // "full" or "incr"
	Hashes    []string `json:"hashes"`
	Count     int      `json:"count"`
	TotalSize int64    `json:"total_size"`
}
