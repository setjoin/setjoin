# Per-User FTRL-Proximal Spam Classifier — Design Spec

Date: 2026-06-03
Status: **Implemented** (FTRL-Proximal per-user classifier, 12 tests, admin dashboard + CLI, 30s batched training via PG NOTIFY)
Implementation plan: `docs/plans/spam-classifier.md`
Depends on: SMTP pipeline refactor (`docs/plans/smtp-pipeline-refactor.md`)

## Goal

Add per-user machine-learning spam classification that learns from individual Junk/Not-Junk folder moves, providing personalized spam filtering without manual rule tuning.

## Architecture: Two Spam Layers

```
Layer 1 (Inbound): Global rules-based — SPF/DKIM/DMARC/RBL/greylist/ClamAV + keywords
  Score > 7 → REJECT (550 bounce)
  Score 3-7 → DELIVER (grey area, refined by Layer 2)
  Score < 3 → DELIVER

Layer 2 (Delivery): Per-user FTRL-Proximal ML
  Sender in user's safe list → Inbox (skip scoring)
  Sender in user's blocked list → Junk (skip scoring)
  FTRL score > 0.7 → Junk
  FTRL score ≤ 0.7 → Inbox
  New user (no model) → Inbox (pass through)
```

The layers are independent. Layer 1 is global, stateless, unchanged. Layer 2 is per-user, stateful, additive. A message rejected by Layer 1 never reaches Layer 2. A message accepted by Layer 1 gets different per-recipient verdicts from Layer 2: Alice → Junk, Bob → Inbox, Carol (new user) → Inbox.

## Decision: FTRL-Proximal over Bayesian

We port Stalwart's approach (AGPL-3.0, architectural inspiration only — no code copied):

| Criterion | Bayesian | FTRL-Proximal |
|-----------|----------|---------------|
| Implementation | ~15 lines Go | ~80 lines Go |
| Hyperparameters | None | 4 (alpha, beta, L1, L2) |
| Memory per user | ~8MB | ~8MB |
| Accuracy at 1k+ samples | Good | Better |
| Online learning | Native | Native |
| Cold start (no samples) | Pass through | Pass through |

We chose FTRL because (a) it's a known quantity — Stalwart v0.15+ uses it in production, (b) the core update is well-documented and simple to port, (c) the accuracy advantage over Bayesian matters at SetJoin's target scale (300-10,000 users). Hyperparameters use Stalwart's defaults (alpha=0.1, beta=1.0, L1=0.01, L2=0.01), validated against their production tuning.

## Feature Extraction

Ported from Stalwart's tokenizer design. Six feature types extracted from each email:

| Feature Type | Source | Encoding |
|-------------|--------|----------|
| Sender | `From:` header address | `"from:" + addr` |
| Subject words | `Subject:` header, 3+ char words | `"s:" + stemmed_word` |
| URLs | `http://` and `https://` in body | `"url:" + SLD`, `"path:" + segment` |
| Content-Type | MIME `Content-Type:` header | `"ct:html"`, `"ct:plain"` |
| Body words | Plain text after headers | `"w:" + stemmed_word` |
| Suspicious | Known spam keywords (viagra, lottery, etc.) | `"susp:" + keyword` |
| Structural | Missing `Message-ID`, missing `Date`, all-caps subject | `"miss:mid"`, `"miss:date"`, `"allcaps"` |

Features are hashed via FNV-1a into a fixed vector space (default 2^20 = 1,048,576 buckets, ~8MB per user model). Feature hashing avoids the unbounded vocabulary problem of bag-of-words classifiers. Each unique (token, user) pair is a feature index.

## Training Trigger

Training is triggered by Junk/Not-Junk folder moves, captured via a PL/pgSQL trigger on `message_tags`:

```sql
CREATE TRIGGER message_tags_spam_train
    AFTER INSERT OR DELETE ON message_tags
    FOR EACH ROW EXECUTE FUNCTION spam_train_notify();
```

The trigger fires `pg_notify('spam_train', '{user_id, message_id, is_spam}')` — one event per tag change. A Go NOTIFY listener collects events into 30-second batches with deduplication and a 100-message cap per batch. Training runs on a background goroutine, never blocking the SMTP hot path.

## Bulk-Move Protection

Three layers of protection against excessive training from bulk folder moves:

1. **Channel buffer** (1000 events) — absorbs bursts, drops oldest if full
2. **Batch deduplication** — same message moved Junk → Inbox within 30s cancels both events
3. **Max batch size** — trains on ≤100 unique messages per user per 30s cycle

A user moving 500 messages to Junk in bulk generates 500 NOTIFY events, which get collected into ≤100 unique training samples over 30 seconds. A user moving messages back and forth produces zero net training samples if both moves happen within the same batch window.

## Model Persistence

Per-user models are stored as `BYTEA` in `user_spam_model`:

| Column | Type | Purpose |
|--------|------|---------|
| `user_id` | BIGINT PK | Owning user |
| `model_bytes` | BYTEA | Serialized FTRL weight table (~8MB) |
| `sample_count` | INTEGER | Number of training samples processed |
| `trained_at` | TIMESTAMPTZ | Last training cycle timestamp |
| `disabled` | BOOLEAN | Admin opt-out (skip scoring for this user) |
| `fp_count` | BIGINT | Cumulative false positives (Junk → Inbox rescues) |
| `fn_count` | BIGINT | Cumulative false negatives (Inbox → Junk corrections) |
| `classified_count` | BIGINT | Total FTRL decisions made |

Estimated false positive rate: `fp_count / classified_count`. Accuracy stats use a 30-day rolling window.

## False Positive Rate Estimation

Without ground truth labels, we estimate accuracy from user corrections:

- **False positive**: User moves message from Junk → Inbox (FTRL was wrong — this was ham)
- **False negative**: User moves message from Inbox → Junk (FTRL missed — this was spam)
- **Estimated FP rate**: `SUM(fp_count) / NULLIF(SUM(classified_count), 0)`

The counter resets naturally over time — `trained_at` timestamps allow computing 30-day rolling rates. No manual reset needed.

## Delivery-Time Decision Flow

Per-recipient, at delivery (after SMTP pipeline Checks pass):

```
1. Is sender in user_sender_list WHERE list_type='blocked'? → Junk (skip all scoring)
2. Is sender in user_sender_list WHERE list_type='safe'?    → Inbox (skip FTRL)
3. Is feature.ml_spam toggle enabled?                       → No → Inbox (default)
4. Does user have a model with sample_count >= min_samples? → No → Inbox (cold start)
5. FTRL.Predict(features) > 0.7?                            → Yes → Junk
6. Default                                                   → Inbox
```

Safe/blocked lists are per-user, configured via `GET/PUT /settings/senders` (Phase 12 gateway handlers). Admin can disable FTRL per-user via `user_spam_model.disabled = TRUE`.

## References

- Stalwart FTRL classifier: `crates/spam-filter/src/modules/classifier.rs` (AGPL-3.0, architectural inspiration only)
- FTRL-Proximal paper: McMahan et al., "Ad Click Prediction: a View from the Trenches" (KDD 2013)
- Stalwart marginal gains blog: https://stalw.art/blog/marginal-gains/
- Feature hashing: Weinberger et al., "Feature Hashing for Large Scale Multitask Learning" (ICML 2009)
- Existing antispam: `mailserver/internal/smtp/antispam.go`
- Existing safe/blocked list: `mailserver/internal/user/sender_list.go`
