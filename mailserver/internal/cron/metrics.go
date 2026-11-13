package cron

import (
	"sync"
	"time"
)

// Metrics tracks cron task execution stats for Prometheus.
// In production these are registered with the Prometheus client.
// For now they are in-memory counters accessible via an admin endpoint.
type Metrics struct {
	mu          sync.RWMutex
	lastRun     map[string]time.Time
	lastSuccess map[string]time.Time
	lastError   map[string]string
	success     map[string]int64
	failure     map[string]int64
	timeout     map[string]int64
	panic       map[string]int64
	durations   map[string][]time.Duration // last 10 durations per task
}

// NewMetrics creates a new metrics tracker.
func NewMetrics() *Metrics {
	return &Metrics{
		lastRun:     make(map[string]time.Time),
		lastSuccess: make(map[string]time.Time),
		lastError:   make(map[string]string),
		success:     make(map[string]int64),
		failure:     make(map[string]int64),
		timeout:     make(map[string]int64),
		panic:       make(map[string]int64),
		durations:   make(map[string][]time.Duration),
	}
}

func (m *Metrics) recordSuccess(task string, now time.Time) {
	m.mu.Lock()
	m.success[task]++
	m.lastSuccess[task] = now
	m.lastError[task] = ""
	m.mu.Unlock()
}

func (m *Metrics) recordFailure(task string, now time.Time, errText string) {
	m.mu.Lock()
	m.failure[task]++
	m.lastRun[task] = now
	m.lastError[task] = errText
	m.mu.Unlock()
}

func (m *Metrics) recordTimeout(task string, now time.Time, errText string) {
	m.mu.Lock()
	m.timeout[task]++
	m.lastRun[task] = now
	m.lastError[task] = errText
	m.mu.Unlock()
}

func (m *Metrics) recordPanic(task string, now time.Time, errText string) {
	m.mu.Lock()
	m.panic[task]++
	m.lastRun[task] = now
	m.lastError[task] = errText
	m.mu.Unlock()
}

func (m *Metrics) recordDuration(task string, now time.Time, d time.Duration) {
	m.mu.Lock()
	m.lastRun[task] = now
	m.durations[task] = append(m.durations[task], d)
	if len(m.durations[task]) > 10 {
		m.durations[task] = m.durations[task][len(m.durations[task])-10:]
	}
	m.mu.Unlock()
}

// Snapshot returns a copy of current metrics for admin display.
func (m *Metrics) Snapshot() map[string]TaskMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make(map[string]TaskMetrics, len(m.lastRun))
	for task := range m.lastRun {
		var avgDuration time.Duration
		durs := m.durations[task]
		if len(durs) > 0 {
			var total time.Duration
			for _, d := range durs {
				total += d
			}
			avgDuration = total / time.Duration(len(durs))
		}
		out[task] = TaskMetrics{
			LastRun:      m.lastRun[task],
			LastSuccess:  m.lastSuccess[task],
			LastError:    m.lastError[task],
			SuccessCount: m.success[task],
			FailureCount: m.failure[task],
			TimeoutCount: m.timeout[task],
			PanicCount:   m.panic[task],
			AvgDuration:  avgDuration,
		}
	}
	return out
}

// TaskMetrics is a point-in-time snapshot for a single task.
type TaskMetrics struct {
	LastRun      time.Time     `json:"last_run"`
	LastSuccess  time.Time     `json:"last_success"`
	LastError    string        `json:"last_error,omitempty"`
	SuccessCount int64         `json:"success_count"`
	FailureCount int64         `json:"failure_count"`
	TimeoutCount int64         `json:"timeout_count"`
	PanicCount   int64         `json:"panic_count"`
	AvgDuration  time.Duration `json:"avg_duration"`
}
