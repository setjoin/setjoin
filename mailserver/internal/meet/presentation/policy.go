package presentation

// PolicyMode is the administrator recording-policy matrix ("Recording
// policy") — a typed matrix, not a single default.
type PolicyMode string

const (
	PolicyLocalPreferred PolicyMode = "local_preferred"
	PolicyServerOnly     PolicyMode = "server_only"
	PolicyLocalOnly      PolicyMode = "local_only"
	PolicyDisabled       PolicyMode = "disabled"
)

// Surface is one capture surface of the policy matrix.
type Surface string

const (
	SurfaceElectron Surface = "electron"
	SurfaceBrowser  Surface = "browser_mobile"
	SurfaceServer   Surface = "server"
	SurfaceSemantic Surface = "semantic"
)

// AllowsCapture implements the frozen matrix. capabilityPassed is the
// surface's own capability probe result: for browser/mobile under
// local_preferred ("offer only when the capability probe passes") and for
// local_only's managed-capable Electron client.
//
//	local_preferred | offer local first | probe-gated offer | explicit fallback | qualified explicit selection
//	server_only     | no local target   | no local target   | RoomComposite path | qualified server audio / authorized B2 companion index
//	local_only      | managed-capable   | hidden            | disabled           | local registration only
//	disabled        | disabled          | disabled          | disabled           | disabled
func AllowsCapture(policy PolicyMode, surface Surface, capabilityPassed bool) bool {
	switch policy {
	case PolicyLocalPreferred:
		switch surface {
		case SurfaceElectron:
			return true
		case SurfaceBrowser:
			return capabilityPassed
		case SurfaceServer, SurfaceSemantic:
			return true
		}
	case PolicyServerOnly:
		switch surface {
		case SurfaceServer, SurfaceSemantic:
			return true
		}
	case PolicyLocalOnly:
		switch surface {
		case SurfaceElectron:
			return capabilityPassed
			// SurfaceServer/SurfaceSemantic stay false: local_only denies M4
			// server audio and central page/caption retention.
		}
	case PolicyDisabled:
		return false
	}
	return false
}

// AllowsLocalRegistration reports the `local_only` semantic column: a
// truthful local package registration is permitted where central capture is
// not. No server response may ever claim a local path or retained bytes.
func AllowsLocalRegistration(policy PolicyMode) bool {
	return policy == PolicyLocalOnly
}

// Invariants are the plan-fixed recording-start rules every mode shares.
const (
	// One primary recording mode per meeting row-serialized lifecycle; no
	// silent concurrent local/server recorder, no automatic producer
	// fallback. Stop and reconcile before a separately authorized
	// replacement starts.
	InvariantSinglePrimaryMode = "single-primary-recording-mode"
	// Every start executes a reducer transaction BEFORE capture begins;
	// the reducer checks role, guest policy, tenant policy, meeting state,
	// legal-hold/retention mode and concurrent recording state; emits the
	// non-dismissible banner; returns a short-lived capture lease.
	InvariantLeaseAfterReducerCommit = "reducer-commit-before-capture"
	// All modes extend the same recording-active predicate, BZ199 guest
	// exclusion, banner, lease, stop/drain and retention boundary.
	InvariantSharedLifecycle = "bz199-shared-recording-lifecycle"
	// Presentation/captions alone never authorize capture.
	InvariantExplicitStartRequired = "presentation-never-authorizes-capture"
)

// FailureCode is the named failure registry ("Error and rescue registry").
// Codes are stable wire/problem slugs; the owning layer and rescue are
// frozen alongside them.
type FailureCode string

const (
	FailSourceVersionGone          FailureCode = "sourceVersionGone"
	FailUnsupportedDocument        FailureCode = "unsupportedDocument"
	FailDocumentProtected          FailureCode = "documentProtected"
	FailRendererTimeout            FailureCode = "rendererTimeout"
	FailPresentationAccessRevoked  FailureCode = "presentationAccessRevoked"
	FailStalePresenterGeneration   FailureCode = "stalePresenterGeneration"
	FailPresentationSequenceGap    FailureCode = "presentationSequenceGap"
	FailCheckpointRefreshThrottled FailureCode = "checkpointRefreshThrottled"
	FailLocalCaptureUnavailable    FailureCode = "localCaptureUnavailable"
	FailCaptureLeaseExpired        FailureCode = "captureLeaseExpired"
	FailTimelineGap                FailureCode = "timelineGap"
	FailIntegrityMismatch          FailureCode = "integrityMismatch"
	FailExportCompositionFailed    FailureCode = "exportCompositionFailed"
	FailHistoryProjectionStale     FailureCode = "historyProjectionStale"
)

// FailureOwner names the layer that raises each code.
type FailureOwner string

const (
	OwnerRenditionRequest     FailureOwner = "rendition-request"
	OwnerRenditionWorker      FailureOwner = "rendition-worker"
	OwnerPageFetch            FailureOwner = "page-fetch"
	OwnerPresentationMutation FailureOwner = "presentation-mutation"
	OwnerPresentationEvent    FailureOwner = "presentation-event"
	OwnerCheckpointRead       FailureOwner = "checkpoint-read"
	OwnerLocalPreflight       FailureOwner = "local-recording-preflight"
	OwnerLocalLease           FailureOwner = "local-recording-lease"
	OwnerSemanticWriter       FailureOwner = "semantic-writer"
	OwnerSemanticReplay       FailureOwner = "semantic-replay"
	OwnerMP4Export            FailureOwner = "mp4-export"
	OwnerDriveHistory         FailureOwner = "drive-history-projector"
)

// FailureRegistry binds each code to its owning layer. Unknown codes are
// never minted by callers — the registry is closed and tested for coverage.
var FailureRegistry = map[FailureCode]FailureOwner{
	FailSourceVersionGone:          OwnerRenditionRequest,
	FailUnsupportedDocument:        OwnerRenditionWorker,
	FailDocumentProtected:          OwnerRenditionWorker,
	FailRendererTimeout:            OwnerRenditionWorker,
	FailPresentationAccessRevoked:  OwnerPageFetch,
	FailStalePresenterGeneration:   OwnerPresentationMutation,
	FailPresentationSequenceGap:    OwnerPresentationEvent,
	FailCheckpointRefreshThrottled: OwnerCheckpointRead,
	FailLocalCaptureUnavailable:    OwnerLocalPreflight,
	FailCaptureLeaseExpired:        OwnerLocalLease,
	FailTimelineGap:                OwnerSemanticWriter,
	FailIntegrityMismatch:          OwnerSemanticReplay,
	FailExportCompositionFailed:    OwnerMP4Export,
	FailHistoryProjectionStale:     OwnerDriveHistory,
}
