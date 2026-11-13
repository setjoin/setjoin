package vad

import (
	"sort"
	"sync"
)

// Manager runs one Detector per track in a room and enforces F10: at most
// Cap tracks may hold a decoder+ASR slot at once, even if more than Cap
// tracks are simultaneously voice-active — the lowest-energy active track
// yields its slot to a louder one. A room with ≤Cap simultaneous speakers
// never sees an eviction; the cap only bites past it.
type Manager struct {
	cap       int
	threshold float64
	hangover  int

	mu        sync.Mutex
	detectors map[string]*Detector
	energy    map[string]float64 // present only for currently voice-active tracks
	holding   map[string]bool    // present (true) only for tracks currently granted a slot
}

// NewManager returns a Manager capping concurrent held slots at cap (the
// ASR_MAX_ACTIVE_TRACKS env, F10), using an energy Detector per track with
// the given threshold/hangover.
func NewManager(cap int, threshold float64, hangover int) *Manager {
	return &Manager{
		cap:       cap,
		threshold: threshold,
		hangover:  hangover,
		detectors: map[string]*Detector{},
		energy:    map[string]float64{},
		holding:   map[string]bool{},
	}
}

// Update feeds one frame's energy for track id and returns whether that
// track currently holds an ASR slot (false for silence, and false for a
// voice-active track that lost the cap tie-break to louder tracks).
func (m *Manager) Update(id string, frameEnergy float64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	det, ok := m.detectors[id]
	if !ok {
		det = NewDetector(m.threshold, m.hangover)
		m.detectors[id] = det
	}
	if !det.Update(frameEnergy) {
		delete(m.energy, id)
		delete(m.holding, id)
		return false
	}
	m.energy[id] = frameEnergy
	m.rebalance()
	return m.holding[id]
}

// Remove drops all state for id (F17 — a disconnected track's slot frees
// immediately, with no lingering entry to skew the next rebalance).
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.detectors, id)
	delete(m.energy, id)
	delete(m.holding, id)
}

// rebalance recomputes which of the currently voice-active tracks hold a
// slot: the top Cap by energy hold, everyone else yields. Ties break by
// track id for determinism (irrelevant in practice — real energy samples
// essentially never tie exactly).
func (m *Manager) rebalance() {
	ids := make([]string, 0, len(m.energy))
	for id := range m.energy {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if m.energy[ids[i]] != m.energy[ids[j]] {
			return m.energy[ids[i]] > m.energy[ids[j]]
		}
		return ids[i] < ids[j]
	})
	for i, id := range ids {
		m.holding[id] = i < m.cap
	}
}
