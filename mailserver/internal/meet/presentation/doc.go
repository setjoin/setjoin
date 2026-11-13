// Package presentation freezes the M0/M1 contract layer of the MEET plan
// (retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-semantic-
// recording.md): the `meet-pages-v1` protected paged-rendition profile, the
// presentation event envelope, the durable checkpoint/state machine, the
// `.sjrec` semantic-recording package layout and its deletion lifecycle, the
// typed recording-policy matrix, the named failure codes, the qualified
// renderer/font/provider identity pins with explicit requalification (M1a),
// the stale-subscription cleanup contract (M1b), and the Drive-side source
// boundary Meet must reuse (never rebuild).
//
// M0/M1 ship CONTRACTS ONLY — every type here is inert data and pure
// functions. No route, worker, reducer, or table is wired by this package;
// behavior admits work only after `feature.meet_document_presentation`,
// `feature.meet_semantic_recording`, or `feature.meet_local_recording` is
// separately enabled AND M2+ milestones add the gated start paths.
//
// Inviolable boundaries this package encodes but never implements around:
//
//   - Meet is NEVER a WOPI host; Office launch/save stays Drive's contracts
//     (drive.office_launch_begin/revoke, office_choice_query).
//   - Meet never writes `blobs.ref_count` directly; storage reclamation goes
//     through the owning reducer's child-release path.
//   - Reducers own presenter rights, durable checkpoints, recording policy,
//     consent, audit and state bumps; frames received over any transport are
//     untrusted checkpoint-invalidation hints.
//   - The `.sjrec` package is a logical Drive recording package: delete/hold
//     are reducer-atomic at the package boundary, never object-store-atomic.
package presentation
