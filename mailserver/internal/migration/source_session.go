package migration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

const (
	// sourceBatchSize is the maximum source-object window retained by the
	// adapters and orchestrator. Provider pages smaller than this bound remain
	// intact; larger IMAP UID ranges are split at this boundary.
	sourceBatchSize = 100
	// sourceStreamJoinTimeout bounds shutdown independently of a cancelled job
	// context so a stuck provider cannot strand the migration worker forever.
	sourceStreamJoinTimeout = 5 * time.Second
)

// SourceCheckpointCandidate is a provider-owned cursor that becomes durable
// only after the orchestrator has acknowledged every item covered by it.
// Adapters serialize Value; the orchestrator only commits the opaque payload.
type SourceCheckpointCandidate struct {
	Scope       string
	LegacyScope string
	Kind        string
	Value       json.RawMessage
}

// SourceResumeState carries both the additive checkpoint table and the legacy
// migration_jobs projection used while the source-identity rail is disabled or
// by retained binaries. Adapters decide how their provider state is decoded.
type SourceResumeState struct {
	Durable     []SourceCheckpointCandidate
	LegacyUIDs  map[string]int
	LegacyDelta map[string]string
}

// SourceCheckpointSnapshot is proposed by a source session after iteration.
// LegacyPatch is a compatibility projection only; neither representation is
// persisted by the adapter.
type SourceCheckpointSnapshot struct {
	Candidates  []SourceCheckpointCandidate
	LegacyPatch map[string]any
}

// SourceBatch is one ordered, closed provider page/window. Candidate covers
// exactly Items (and any source-side gaps the provider closed while producing
// the page). It becomes durable only after the orchestrator applies every item.
type SourceBatch struct {
	Items     []SourceItem
	Candidate SourceCheckpointSnapshot
	sequence  uint64
}

// SourceBatchStream keeps at most one unacknowledged provider page in flight.
// The producer cannot perform the next source read until Acknowledge returns
// its current page, which binds source reads to durable target progress.
type SourceBatchStream struct {
	batches <-chan SourceBatch
	acks    chan<- uint64
	cancel  context.CancelFunc
	done    <-chan struct{}

	mu          *sync.Mutex
	terminalErr *error
}

type sourceBatchEmitter func(SourceBatch) error

func newSourceBatchStream(parent context.Context, produce func(context.Context, sourceBatchEmitter) error) *SourceBatchStream {
	ctx, cancel := context.WithCancel(parent)
	batches := make(chan SourceBatch, 1)
	acks := make(chan uint64)
	done := make(chan struct{})
	mu := &sync.Mutex{}
	var terminalErr error

	stream := &SourceBatchStream{
		batches: batches, acks: acks, cancel: cancel, done: done,
		mu: mu, terminalErr: &terminalErr,
	}
	go func() {
		defer close(batches)
		defer close(done)
		var sequence uint64
		emit := func(batch SourceBatch) error {
			if len(batch.Items) > sourceBatchSize {
				return fmt.Errorf("source batch contains %d items; maximum is %d", len(batch.Items), sourceBatchSize)
			}
			sequence++
			batch.sequence = sequence
			select {
			case batches <- batch:
			case <-ctx.Done():
				return ctx.Err()
			}
			select {
			case acknowledged := <-acks:
				if acknowledged != sequence {
					return fmt.Errorf("source batch acknowledgement %d does not match %d", acknowledged, sequence)
				}
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		err := produce(ctx, emit)
		mu.Lock()
		terminalErr = err
		mu.Unlock()
	}()
	return stream
}

// Next returns the next closed page or io.EOF after the producer has joined.
func (s *SourceBatchStream) Next(ctx context.Context) (SourceBatch, error) {
	select {
	case batch, ok := <-s.batches:
		if ok {
			return batch, nil
		}
		if err := s.Join(ctx); err != nil {
			return SourceBatch{}, err
		}
		return SourceBatch{}, io.EOF
	case <-ctx.Done():
		return SourceBatch{}, ctx.Err()
	}
}

func (s *SourceBatchStream) Acknowledge(ctx context.Context, batch SourceBatch) error {
	if batch.sequence == 0 {
		return fmt.Errorf("source batch was not produced by this stream")
	}
	select {
	case s.acks <- batch.sequence:
		return nil
	case <-s.done:
		return s.Join(ctx)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *SourceBatchStream) Cancel() { s.cancel() }

func (s *SourceBatchStream) Join(ctx context.Context) error {
	select {
	case <-s.done:
		s.mu.Lock()
		defer s.mu.Unlock()
		return *s.terminalErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

// consumeSourceBatches is the acknowledgement owner shared by production and
// crash/cancellation tests. A page is acknowledged only after handle returns;
// on any failure the producer is cancelled and joined with a fresh bounded
// context, leaving the prior durable cursor available for replay.
func consumeSourceBatches(ctx context.Context, stream *SourceBatchStream, handle func(context.Context, SourceBatch) error) (retErr error) {
	defer func() {
		stream.Cancel()
		drainCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sourceStreamJoinTimeout)
		defer cancel()
		joinErr := stream.Join(drainCtx)
		if retErr == nil && joinErr != nil && !errors.Is(joinErr, context.Canceled) {
			retErr = joinErr
		}
	}()
	for {
		batch, err := stream.Next(ctx)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := handle(ctx, batch); err != nil {
			return err
		}
		if err := stream.Acknowledge(ctx, batch); err != nil {
			return err
		}
	}
}

// SourceSession is the mandatory resumable connector contract. It keeps source
// identity and provider-specific restore/capture semantics behind one seam,
// while target apply ordering and durable checkpoint commit stay in Orchestrator.
type SourceSession interface {
	Connector
	ResolveSourceIdentity(ctx context.Context) (SourceIdentity, error)
	RestoreSourceState(state SourceResumeState) error
	IterateSource(ctx context.Context) *SourceBatchStream
}

func cloneStringMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func sortedCheckpointScopes[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func rejectCheckpointKind(candidate SourceCheckpointCandidate, expected string) error {
	return fmt.Errorf("restore source checkpoint %q: kind %q is not %q", candidate.Scope, candidate.Kind, expected)
}

func dedupeSourceBatch(items []SourceItem) []SourceItem {
	seenObjects := make(map[string]struct{}, len(items))
	seenUIDs := make(map[string]map[uint32]struct{})
	out := make([]SourceItem, 0, len(items))
	for _, item := range items {
		change := item.Change
		if change == "" {
			change = SourceUpsert
		}
		envelopeKey := fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s", item.Type,
			item.SourceObjectID, item.SourceVersion, change, item.SourceFolderID)
		if _, exists := seenObjects[envelopeKey]; exists {
			continue
		}
		seenObjects[envelopeKey] = struct{}{}
		if item.SourceUID != 0 {
			if seenUIDs[item.SourceFolderID] == nil {
				seenUIDs[item.SourceFolderID] = make(map[uint32]struct{})
			}
			if _, exists := seenUIDs[item.SourceFolderID][item.SourceUID]; exists {
				continue
			}
			seenUIDs[item.SourceFolderID][item.SourceUID] = struct{}{}
		}
		out = append(out, item)
	}
	return out
}
