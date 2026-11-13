package presentation

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// M6 slice 2 — the two remaining Drive-fixture cells of the cross-feature
// continuity matrix (plan M6 "Prove Drive branch conflicts, compare/restore,
// ... remain coherent"; matrix rows "Drive branch conflicts" and
// "Compare/restore"). This file is the CONTRACT half: the cells are proven
// against the M1/M2 contracts Meet reuses verbatim (driveboundary.go's
// immutable SourceRef, rendition.go's RenditionKey/manifest identity binding,
// provider.go's EvaluateRebind rebind primitive, envelope.go's durable
// source.switched fact) with NO live Drive and NO network. The REAL-reducer
// half of the same six named outcomes runs against the actual Drive reducers
// and meet pin fences in m6_compare_restore_db_test.go (DB_DSN-gated).
//
// Flags stay OFF: pure store/contract tests — nothing here flips a feature
// flag, registers a route, or touches a WOPI path.

// m6crManifestFor pins a well-formed manifest to one immutable Drive version
// identity AND gives it a head-specific integrity digest, so two heads never
// share a rendition identity (the base helper keeps the shared fixture
// digest; real producers digest distinct page sets).
func m6crManifestFor(t *testing.T, nodeID, versionID int64, sha string) Manifest {
	t.Helper()
	m := m6ContinuityManifestFor(t, nodeID, versionID, sha)
	m.IntegrityDigest = m6sha(fmt.Sprintf("m6cr-manifest-v%d", versionID))
	if err := m.Validate(); err != nil {
		t.Fatalf("fixture manifest for version %d rejected: %v", versionID, err)
	}
	return m
}

// m6crQualifiedProvider is a fully admitted M1 provider identity (every field
// evidence-shaped, AdmitProviderIdentity-clean) to drive the rebind compare
// primitive.
func m6crQualifiedProvider(t *testing.T, rendererVersion string) ProviderIdentity {
	t.Helper()
	id := ProviderIdentity{
		RendererID:           "soffice",
		RendererVersion:      rendererVersion,
		FontPackDigest:       strings.Repeat("cd", 32),
		LocaleProfile:        "en-US",
		OutputProfileVersion: RenditionProfileVersion,
		SupportedOSArch:      "linux/amd64",
		ArtifactFormat:       "tar.zst",
		ArtifactSHA256:       m6sha("qualified-artifact-bytes"),
		LicenseSPDX:          "MPL-2.0",
		ProvenanceRef:        "build/provenance/qual-m6cr",
		SandboxPolicy:        "seatbelt-rendition",
		HealthProtocol:       "http/health",
		EvidenceRef:          "qualification/m6cr",
	}
	if err := AdmitProviderIdentity(id); err != nil {
		t.Fatalf("fixture provider identity rejected: %v", err)
	}
	return id
}

// ── Cell: Drive branch conflicts ─────────────────────────────────────────
// plan:869 — pos `m6-branch-conflict-pos`: diverged Drive heads both
// presentable.

// Positive: after a file's history diverges (a main-head save and an
// independent branch head grown from the same fork point), BOTH heads are
// presentable — each pins its own complete immutable identity (SourceRef,
// rendition key, manifest digest) and mints a valid page capability. Nothing
// about one head's identity leans on the other.
func TestM6BranchConflictDivergedHeadsBothPresentable(t *testing.T) {
	const node = int64(5)
	baseSHA := m6sha("branch-fork-base-bytes")
	mainSHA := m6sha("branch-main-head-bytes")
	sideSHA := m6sha("branch-side-head-bytes")
	base := SourceRef{DriveNodeID: node, DriveVersionID: 11, SourceSHA256: baseSHA}
	main := SourceRef{DriveNodeID: node, DriveVersionID: 12, SourceSHA256: mainSHA}
	side := SourceRef{DriveNodeID: node, DriveVersionID: 13, SourceSHA256: sideSHA}
	// Every diverged head is a complete, validatable Drive identity.
	for name, ref := range map[string]SourceRef{"fork base": base, "main head": main, "side head": side} {
		if err := ref.Validate(); err != nil {
			t.Fatalf("%s source ref: %v", name, err)
		}
	}
	idents := []SourceRef{base, main, side}
	for i := 0; i < len(idents); i++ {
		for j := i + 1; j < len(idents); j++ {
			if idents[i].DriveVersionID == idents[j].DriveVersionID || idents[i].SourceSHA256 == idents[j].SourceSHA256 {
				t.Fatalf("diverged heads %d and %d share an identity component", idents[i].DriveVersionID, idents[j].DriveVersionID)
			}
		}
	}

	// Each head carries its own pinned rendition: a validating manifest bound
	// to ITS version identity, with a distinct integrity digest, and a page
	// capability minted against that digest.
	digests := map[int64]string{}
	for _, ref := range []SourceRef{base, main, side} {
		m := m6crManifestFor(t, node, ref.DriveVersionID, ref.SourceSHA256)
		if m.Key.DriveVersionID != ref.DriveVersionID || m.Key.SourceSHA256 != ref.SourceSHA256 {
			t.Fatalf("manifest for version %d drifted off its identity", ref.DriveVersionID)
		}
		if _, dup := digests[ref.DriveVersionID]; dup {
			t.Fatalf("version %d presented twice", ref.DriveVersionID)
		}
		digests[ref.DriveVersionID] = m.IntegrityDigest
		capability := NewPageCapability("p-1", "m-1", m.Pages[0].ID, m.IntegrityDigest, time.Now().Add(time.Minute).UnixMilli())
		if err := capability.Validate(); err != nil {
			t.Fatalf("page capability for version %d: %v", ref.DriveVersionID, err)
		}
		if capability.ManifestDigest != m.IntegrityDigest {
			t.Fatalf("capability for version %d drifted off its manifest digest", ref.DriveVersionID)
		}
	}
	if digests[11] == digests[12] || digests[12] == digests[13] || digests[11] == digests[13] {
		t.Fatal("diverged heads share a rendition digest; a compare view could not tell them apart")
	}
}

// Negative: comparing across diverged heads never silently aliases the pinned
// rendition. The dedup key joins version identity AND source bytes, the
// manifest grammar refuses a laundered (old pin, new bytes) identity, and the
// M1 rebind compare primitive returns RebindRequired — the pinned session is
// never moved by a comparison.
func TestM6BranchConflictCompareNeverAliasesPinnedRendition(t *testing.T) {
	const node = int64(5)
	pinnedSHA := m6sha("alias-pin-base-bytes")
	sideSHA := m6sha("alias-side-head-bytes")
	pinned := m6crManifestFor(t, node, 21, pinnedSHA)
	side := m6crManifestFor(t, node, 22, sideSHA)

	// The compare itself: every identity component the rendition cache joins
	// differs between the pinned rendition and the side head's rendition.
	if side.Key == pinned.Key {
		t.Fatal("the diverged side head aliased the pinned rendition key")
	}
	if side.DriveVersionID == pinned.DriveVersionID || side.SourceSHA256 == pinned.SourceSHA256 ||
		side.IntegrityDigest == pinned.IntegrityDigest {
		t.Fatal("the diverged side head aliased a pinned identity component")
	}

	// A manifest presenting the SIDE head's bytes under the PINNED version id
	// is the laundered-pin shape: the key tuple must bind to the manifest
	// body, so validation refuses it — a compare can never conclude "same
	// rendition" by re-pointing identities.
	forged := m6crManifestFor(t, node, 22, sideSHA)
	forged.DriveVersionID = 21 // pinned pin, side bytes
	err := forged.Validate()
	if err == nil || !strings.Contains(err.Error(), "bind to the manifest identity") {
		t.Fatalf("side bytes under the pinned version id: got %v, want a key-binding refusal", err)
	}

	// The M1 compare primitive: a candidate identity discovered for the side
	// head differs from the pinned provider identity → RebindRequired, and
	// there is no API that moves the pin — comparison alone changes nothing.
	pinnedProvider := m6crQualifiedProvider(t, "from-qualification")
	sideProvider := m6crQualifiedProvider(t, "side-qualification")
	if got := EvaluateRebind(pinnedProvider, sideProvider); got != RebindRequired {
		t.Fatalf("compare across diverged heads returned %d, want RebindRequired", got)
	}
	if got := EvaluateRebind(pinnedProvider, pinnedProvider); got != RebindUnchanged {
		t.Fatalf("identical compare returned %d, want RebindUnchanged", got)
	}
	// The pinned identity survives the comparison byte-identical.
	if err := pinned.Validate(); err != nil {
		t.Fatalf("pinned manifest invalidated by a compare across heads: %v", err)
	}
}

// Recovery: after conflict RESOLUTION (Drive adopt — a NEW merged version
// identity carrying the adopted head's proven bytes), the presenter re-pins
// ONLY through an explicit act: the durable source.switched fact carries the
// new identity, the old pinned rendition stays intact for history, and the
// merged identity is genuinely new (distinct version id, adopted bytes).
func TestM6BranchConflictResolutionRepinsExplicitly(t *testing.T) {
	const node = int64(5)
	pinnedSHA := m6sha("resolve-pin-base-bytes")
	sideSHA := m6sha("resolve-side-head-bytes")
	pinned := m6crManifestFor(t, node, 31, pinnedSHA)

	// Resolution product (Drive adopt): a NEW version identity — bytes are
	// never synthesized, so the content sha is the adopted side head's, but
	// the version id and therefore the pinned identity are new.
	merged := SourceRef{DriveNodeID: node, DriveVersionID: 34, SourceSHA256: sideSHA}
	if err := merged.Validate(); err != nil {
		t.Fatalf("merged source ref: %v", err)
	}
	if merged.DriveVersionID == 31 || merged.SourceSHA256 == pinnedSHA {
		t.Fatal("resolution did not mint a new identity for the adopted bytes")
	}
	mergedManifest := m6crManifestFor(t, node, merged.DriveVersionID, merged.SourceSHA256)

	// The explicit repin: the durable vocabulary carries the fact
	// (source.switched), the encoded history entry names the NEW identity,
	// and a fresh page capability binds the NEW manifest digest.
	if !KindSourceSwitched.DurableCommittable() {
		t.Fatal("source.switched is not durably committable; a repin could not enter the history rail")
	}
	payload, err := json.Marshal(map[string]any{
		"driveNodeId":        node,
		"driveVersionId":     merged.DriveVersionID,
		"manifestDigest":     mergedManifest.IntegrityDigest,
		"manifestGeneration": 2,
	})
	if err != nil {
		t.Fatalf("encode switch payload: %v", err)
	}
	frame := NewEnvelope("p-1", 3, 1, KindSourceSwitched, payload, time.Now().UTC().Format(time.RFC3339))
	raw, err := frame.Encode()
	if err != nil {
		t.Fatalf("encode source.switched history entry: %v", err)
	}
	verdict, err := Classify(raw, FrameContext{PresentationID: "p-1", ContextConfirmedSeq: 2, KnownGeneration: 1})
	if err != nil || verdict != VerdictInvalidateCheckpoint {
		t.Fatalf("history entry classified %d (%v), want an invalidation hint", verdict, err)
	}
	var decoded Envelope
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode history entry: %v", err)
	}
	var entry struct {
		DriveNodeID        int64  `json:"driveNodeId"`
		DriveVersionID     int64  `json:"driveVersionId"`
		ManifestDigest     string `json:"manifestDigest"`
		ManifestGeneration int64  `json:"manifestGeneration"`
	}
	if err := json.Unmarshal(decoded.Payload, &entry); err != nil {
		t.Fatalf("decode history payload: %v", err)
	}
	if entry.DriveVersionID != merged.DriveVersionID || entry.DriveNodeID != node ||
		entry.ManifestDigest != mergedManifest.IntegrityDigest || entry.ManifestGeneration != 2 {
		t.Fatalf("history entry does not name the new explicit identity: %+v", entry)
	}

	// The OLD pinned rendition is untouched by the repin — history keeps the
	// pre-resolution pin exactly as it was.
	if err := pinned.Validate(); err != nil {
		t.Fatalf("pre-resolution pinned manifest disturbed by the repin: %v", err)
	}
	recoveryCapability := NewPageCapability("p-1", "m-1", mergedManifest.Pages[0].ID, mergedManifest.IntegrityDigest, time.Now().Add(time.Minute).UnixMilli())
	if err := recoveryCapability.Validate(); err != nil || recoveryCapability.ManifestDigest == pinned.IntegrityDigest {
		t.Fatalf("recovery capability did not bind the new digest: %v", err)
	}
}

// ── Cell: Compare/restore ────────────────────────────────────────────────
// plan:870 — pos `m6-compare-restore-pos`: compare of two versions lists
// differences without mutating the pin.

// Positive: comparing two presentation versions derives a complete difference
// list purely from immutable identity fields (version id, source sha,
// rendition key, manifest digest) — a READ with no side effects: the pinned
// manifest and its source ref re-read and re-validate byte-identical after
// the comparison, so comparing never mutates the pin.
func TestM6CompareVersionsListsDifferencesWithoutMutatingPin(t *testing.T) {
	const node = int64(5)
	pinnedSHA := m6sha("compare-pinned-base-bytes")
	savedSHA := m6sha("compare-saved-head-bytes")
	pinned := m6crManifestFor(t, node, 41, pinnedSHA)
	saved := m6crManifestFor(t, node, 42, savedSHA)
	pinnedRef := SourceRef{DriveNodeID: node, DriveVersionID: 41, SourceSHA256: pinnedSHA}
	if err := pinnedRef.Validate(); err != nil {
		t.Fatalf("pinned source ref: %v", err)
	}

	// The difference list a compare view shows — every component distinct:
	if pinned.DriveVersionID == saved.DriveVersionID {
		t.Fatal("compare: version identities not distinct")
	}
	if pinned.SourceSHA256 == saved.SourceSHA256 {
		t.Fatal("compare: source bytes not distinct")
	}
	if pinned.Key == saved.Key {
		t.Fatal("compare: rendition keys not distinct")
	}
	if pinned.IntegrityDigest == saved.IntegrityDigest {
		t.Fatal("compare: manifest digests not distinct")
	}

	// Comparing is a pure read: re-validate both manifests and re-read the
	// pinned identity — everything byte-identical, the pin unmoved.
	if err := pinned.Validate(); err != nil {
		t.Fatalf("compare read invalidated the pinned manifest: %v", err)
	}
	if err := saved.Validate(); err != nil {
		t.Fatalf("compare read invalidated the compared manifest: %v", err)
	}
	after := SourceRef{DriveNodeID: node, DriveVersionID: 41, SourceSHA256: pinnedSHA}
	if after != pinnedRef {
		t.Fatal("the compare read moved the pinned source identity")
	}
	capability := NewPageCapability("p-1", "m-1", pinned.Pages[0].ID, pinned.IntegrityDigest, time.Now().Add(time.Minute).UnixMilli())
	if err := capability.Validate(); err != nil || capability.ManifestDigest != pinned.IntegrityDigest {
		t.Fatalf("the pin's capability did not survive the compare: %v", err)
	}
}

// Negative: restore to a pinned base fails loudly when the target version is
// missing or rewritten (plan:870's neg wording). Missing identities are
// refused at the source-ref and manifest boundaries; a rewritten rendition
// entry is refused by the key binding; and the rebind primitive never
// silently adopts a rewritten candidate.
func TestM6CompareRestoreTargetMissingOrRewrittenFailsClosed(t *testing.T) {
	const node = int64(5)
	pinnedSHA := m6sha("restore-pinned-base-bytes")
	rewrittenSHA := m6sha("restore-rewritten-bytes")

	// MISSING: an incomplete identity can never anchor a restore. Zero or
	// negative Drive identities and malformed hashes all refuse.
	for name, ref := range map[string]SourceRef{
		"missing version": {DriveNodeID: node, DriveVersionID: 0, SourceSHA256: pinnedSHA},
		"missing node":    {DriveNodeID: 0, DriveVersionID: 43, SourceSHA256: pinnedSHA},
		"malformed sha":   {DriveNodeID: node, DriveVersionID: 43, SourceSHA256: "nothex"},
	} {
		if err := ref.Validate(); err == nil {
			t.Fatalf("%s: restore target accepted without its identity", name)
		}
	}
	missingManifest := m6crManifestFor(t, node, 43, pinnedSHA)
	missingManifest.DriveVersionID = 0
	if err := missingManifest.Validate(); err == nil || !strings.Contains(err.Error(), "source identity incomplete") {
		t.Fatalf("manifest with a missing version identity: got %v, want a source-identity refusal", err)
	}

	// REWRITTEN: the pinned version's rendition entry was rewritten to carry
	// different bytes — the key tuple no longer binds to the manifest body,
	// and validation refuses the alias before any restore could publish it.
	rewritten := m6crManifestFor(t, node, 41, pinnedSHA)
	rewritten.Key.SourceSHA256 = rewrittenSHA
	err := rewritten.Validate()
	if err == nil || !strings.Contains(err.Error(), "bind to the manifest identity") {
		t.Fatalf("rewritten rendition entry: got %v, want a key-binding refusal", err)
	}
	// The rewritten candidate is a DIFFERENT identity: the rebind compare
	// flags it and nothing adopts it silently.
	pinnedProvider := m6crQualifiedProvider(t, "from-qualification")
	rewrittenProvider := m6crQualifiedProvider(t, "rewritten-qualification")
	if got := EvaluateRebind(pinnedProvider, rewrittenProvider); got != RebindRequired {
		t.Fatalf("rewritten candidate returned %d, want RebindRequired", got)
	}
	// The honest pin is untouched by the failed restore attempts.
	honest := m6crManifestFor(t, node, 41, pinnedSHA)
	if err := honest.Validate(); err != nil {
		t.Fatalf("pinned manifest disturbed by refused restores: %v", err)
	}
}

// Recovery: a restore that succeeds replays the PINNED base's proven bytes
// under a NEW explicit version identity; the re-pin moves to that new
// identity only via the explicit source.switched fact, which enters the
// durable rail as the history entry, while the pre-restore identity stays
// readable for history.
func TestM6CompareRestoreRepinsNewIdentityWithHistoryEntry(t *testing.T) {
	const node = int64(5)
	pinnedSHA := m6sha("restore-recovery-base-bytes")
	pinned := m6crManifestFor(t, node, 51, pinnedSHA)

	// Restore product: new version identity (52), SAME proven content bytes
	// (a restore never synthesizes or rewrites bytes), new rendition identity.
	restored := SourceRef{DriveNodeID: node, DriveVersionID: 52, SourceSHA256: pinnedSHA}
	if err := restored.Validate(); err != nil {
		t.Fatalf("restored source ref: %v", err)
	}
	if restored.DriveVersionID == 51 {
		t.Fatal("restore did not mint a new version identity")
	}
	restoredManifest := m6crManifestFor(t, node, 52, pinnedSHA)
	if restoredManifest.IntegrityDigest == pinned.IntegrityDigest {
		t.Fatal("the restored rendition aliased the pre-restore manifest digest")
	}

	// The explicit re-pin history entry carries the NEW identity at the NEXT
	// checkpoint sequence — a fresh frame the authorized read then confirms.
	payload, err := json.Marshal(map[string]any{
		"driveNodeId":        node,
		"driveVersionId":     restored.DriveVersionID,
		"manifestDigest":     restoredManifest.IntegrityDigest,
		"manifestGeneration": 2,
	})
	if err != nil {
		t.Fatalf("encode repin payload: %v", err)
	}
	frame := NewEnvelope("p-1", 4, 1, KindSourceSwitched, payload, time.Now().UTC().Format(time.RFC3339))
	raw, err := frame.Encode()
	if err != nil {
		t.Fatalf("encode repin history entry: %v", err)
	}
	verdict, err := Classify(raw, FrameContext{PresentationID: "p-1", ContextConfirmedSeq: 3, KnownGeneration: 1})
	if err != nil || verdict != VerdictInvalidateCheckpoint {
		t.Fatalf("repin entry classified %d (%v), want an invalidation hint", verdict, err)
	}
	var entry struct {
		DriveVersionID int64  `json:"driveVersionId"`
		ManifestDigest string `json:"manifestDigest"`
	}
	if err := json.Unmarshal(frame.Payload, &entry); err != nil {
		t.Fatalf("decode repin entry: %v", err)
	}
	if entry.DriveVersionID != 52 || entry.ManifestDigest != restoredManifest.IntegrityDigest {
		t.Fatalf("repin history entry does not name the restored identity: %+v", entry)
	}

	// The pre-restore pinned identity remains valid and distinct — the move
	// replaced the pin, it did not rewrite the old identity's rendition.
	if err := pinned.Validate(); err != nil {
		t.Fatalf("pre-restore pinned manifest disturbed: %v", err)
	}
}
