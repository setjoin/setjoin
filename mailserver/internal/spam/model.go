package spam

// Model wraps the FTRL classifier with feature extraction for a single user.
type Model struct {
	ftrl     *FTRL
	featSize uint32
}

// NewModel creates a new untrained model.
func NewModel(featSize uint32) *Model {
	if featSize == 0 {
		featSize = DefaultFeatureSize
	}
	return &Model{
		ftrl:     NewFTRL(featSize, DefaultFTRLParams()),
		featSize: featSize,
	}
}

// Score returns the spam probability (0-1) for a raw email.
func (m *Model) Score(raw []byte) float64 {
	feats := ExtractFeatures(raw, m.featSize)
	if len(feats) == 0 {
		return 0.0
	}
	return m.ftrl.Predict(feats)
}

// Train updates the model on a single labeled example.
// isSpam=true means the user marked it as spam.
// Runs synchronously — caller should batch.
func (m *Model) Train(raw []byte, isSpam bool) {
	feats := ExtractFeatures(raw, m.featSize)
	if len(feats) == 0 {
		return
	}
	label := 0.0
	if isSpam {
		label = 1.0
	}
	m.ftrl.Update(feats, label)
}

// Save serializes the model to bytes for PostgreSQL BYTEA storage.
func (m *Model) Save() ([]byte, error) {
	return m.ftrl.MarshalBinary()
}

// Load deserializes the model from PostgreSQL BYTEA.
func (m *Model) Load(data []byte) error {
	return m.ftrl.UnmarshalBinary(data)
}

// ResidentBytes approximates the heap footprint of the loaded model: the FTR2
// serialized layout (8-byte header + W/Z/N float64 tables) mirrors the three
// in-memory table allocations, so it is also the working-set cost of holding
// the model resident across a delivery-scoring batch
// (feature.spam_model_batch_load observability; owner decision A6). At
// DefaultFeatureSize (2^20) this is ~24 MB per user model.
func (m *Model) ResidentBytes() int64 {
	return int64(8) + int64(m.ftrl.Size)*3*8
}
