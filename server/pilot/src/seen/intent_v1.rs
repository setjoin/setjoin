//! Pure P0 ordered-intent v1 validation and byte encoding.
//!
//! Validates run ID grammar, canonical identifier and generation ranges, item
//! count and uniqueness, and retains supplied item order. The fingerprint and
//! fixture hash are opaque inputs. Wire parsing, profile qualification and
//! runtime authority are outside this module.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SeenItem<'a> {
    pub message_id: &'a str,
    pub seen: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OrderedIntent<'a> {
    pub run_id: &'a str,
    pub tenant_id: &'a str,
    pub actor_id: &'a str,
    pub mailbox_id: &'a str,
    pub authority_generation: &'a str,
    pub profile_fingerprint: [u8; 32],
    pub fixture_sha256: [u8; 32],
    pub items: &'a [SeenItem<'a>],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IntentError {
    InvalidInput,
}

/// Encode the intent once and hash its canonical bytes.
pub fn digest_intent_v1(intent: &OrderedIntent<'_>) -> Result<[u8; 32], IntentError> {
    use sha2::{Digest, Sha256};

    let bytes = encode_intent_v1(intent)?;
    Ok(Sha256::digest(&bytes).into())
}

/// Validate typed ordered-intent fields and encode their v1 bytes.
///
/// This does not parse a wire request, compute a digest or qualify authority.
pub fn encode_intent_v1(intent: &OrderedIntent<'_>) -> Result<Vec<u8>, IntentError> {
    let run = intent.run_id.as_bytes();
    if !(1..=32).contains(&run.len())
        || !run
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(IntentError::InvalidInput);
    }
    let run_len = u8::try_from(run.len()).map_err(|_| IntentError::InvalidInput)?;
    if intent.items.len() > 128 {
        return Err(IntentError::InvalidInput);
    }
    let count = u16::try_from(intent.items.len()).map_err(|_| IntentError::InvalidInput)?;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"SETJOIN-P0-SEEN\0\x01");
    bytes.push(run_len);
    bytes.extend_from_slice(run);
    for value in [intent.tenant_id, intent.actor_id, intent.mailbox_id] {
        bytes.extend_from_slice(&positive_id(value)?.to_be_bytes());
    }
    let generation = if intent.authority_generation == "0" {
        0
    } else {
        positive_id(intent.authority_generation)?
    };
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes.extend_from_slice(&intent.profile_fingerprint);
    bytes.extend_from_slice(&intent.fixture_sha256);
    bytes.extend_from_slice(&count.to_be_bytes());
    let mut seen_messages = std::collections::BTreeSet::new();
    for item in intent.items {
        let message = positive_id(item.message_id)?;
        if !seen_messages.insert(message) {
            return Err(IntentError::InvalidInput);
        }
        bytes.extend_from_slice(&message.to_be_bytes());
        bytes.push(u8::from(item.seen));
    }
    Ok(bytes)
}

fn positive_id(value: &str) -> Result<u64, IntentError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || !(b'1'..=b'9').contains(&bytes[0])
        || !bytes[1..].iter().all(u8::is_ascii_digit)
    {
        return Err(IntentError::InvalidInput);
    }
    let number = value
        .parse::<i64>()
        .map_err(|_| IntentError::InvalidInput)?;
    Ok(number as u64)
}

// Test authority: P0-TRANSACTION-CONTRACT-SUCCESSOR.md, SHA-256
// a22f621e6959135861cafde47ade1ccf6fe5daefbd27a27ebfeaf4c3791716bc,
// section "Operation identity and digest v1". Independently chosen synthetic
// vectors do not prove runtime behavior or qualify a profile.
#[cfg(test)]
mod tests {
    use super::{encode_intent_v1, OrderedIntent, SeenItem};

    #[test]
    fn digests_original_order_literal_v1_vector() {
        let items = [
            SeenItem {
                message_id: "2",
                seen: true,
            },
            SeenItem {
                message_id: "10",
                seen: false,
            },
        ];
        let intent = OrderedIntent {
            run_id: "t03_metadata_20261027",
            tenant_id: "2",
            actor_id: "11",
            mailbox_id: "21",
            authority_generation: "7",
            profile_fingerprint: [0x11; 32],
            fixture_sha256: [
                0xa3, 0x98, 0xc4, 0x50, 0x1f, 0x8f, 0xd4, 0x9b, 0x5d, 0x36, 0x45, 0xc4, 0x32, 0x1c,
                0xd3, 0xa3, 0xfd, 0x59, 0xac, 0xe6, 0xd3, 0xea, 0x83, 0x53, 0x39, 0x52, 0xef, 0xd0,
                0x75, 0x83, 0xd9, 0x34,
            ],
            items: &items,
        };
        assert_eq!(
            super::digest_intent_v1(&intent),
            Ok([
                0xda, 0x8d, 0x7c, 0xcf, 0xf1, 0xa0, 0xcf, 0xfb, 0x76, 0x37, 0x85, 0x1c, 0xd3, 0xf8,
                0x17, 0xd0, 0xb2, 0x5f, 0x09, 0xda, 0x06, 0xfe, 0x8d, 0x0c, 0xbf, 0x2e, 0xa1, 0xd0,
                0x60, 0x8a, 0x21, 0x2f,
            ])
        );
    }

    fn digest_case(
        run_id: &str,
        actor_id: &str,
        items: &[SeenItem<'_>],
    ) -> Result<[u8; 32], super::IntentError> {
        let intent = OrderedIntent {
            run_id,
            tenant_id: "2",
            actor_id,
            mailbox_id: "21",
            authority_generation: "7",
            profile_fingerprint: [0x11; 32],
            fixture_sha256: [
                0xa3, 0x98, 0xc4, 0x50, 0x1f, 0x8f, 0xd4, 0x9b, 0x5d, 0x36, 0x45, 0xc4, 0x32, 0x1c,
                0xd3, 0xa3, 0xfd, 0x59, 0xac, 0xe6, 0xd3, 0xea, 0x83, 0x53, 0x39, 0x52, 0xef, 0xd0,
                0x75, 0x83, 0xd9, 0x34,
            ],
            items,
        };
        super::digest_intent_v1(&intent)
    }

    #[test]
    fn digests_reverse_order_literal_v1_vector() {
        let items = [
            SeenItem {
                message_id: "10",
                seen: false,
            },
            SeenItem {
                message_id: "2",
                seen: true,
            },
        ];
        assert_eq!(
            digest_case("t03_metadata_20261027", "11", &items),
            Ok([
                0xa2, 0xe3, 0x48, 0x3a, 0xea, 0x45, 0x06, 0xc4, 0xb7, 0x82, 0x88, 0xd1, 0xb6, 0x53,
                0x26, 0xf6, 0x48, 0x55, 0x31, 0x5e, 0xcc, 0x77, 0x58, 0xa5, 0x69, 0x1a, 0x9b, 0x57,
                0xa9, 0x76, 0xbc, 0xf2,
            ])
        );
    }

    #[test]
    fn digests_changed_actor_literal_v1_vector() {
        let items = [
            SeenItem {
                message_id: "2",
                seen: true,
            },
            SeenItem {
                message_id: "10",
                seen: false,
            },
        ];
        assert_eq!(
            digest_case("t03_metadata_20261027", "12", &items),
            Ok([
                0x3b, 0xce, 0xe6, 0xd3, 0x2c, 0xa1, 0x95, 0x20, 0x50, 0x3f, 0xec, 0xc4, 0x36, 0xce,
                0xb8, 0x38, 0xe0, 0x55, 0x2e, 0xcc, 0x16, 0xa2, 0x22, 0x8f, 0xa6, 0x59, 0x1a, 0x5f,
                0x2b, 0xee, 0x59, 0x18,
            ])
        );
    }

    #[test]
    fn digests_empty_items_literal_v1_vector() {
        assert_eq!(
            digest_case("t03_metadata_20261027", "11", &[]),
            Ok([
                0xca, 0x4f, 0x0f, 0x2e, 0x94, 0x76, 0x98, 0xa3, 0xcf, 0x80, 0xca, 0x0f, 0xf9, 0xb1,
                0x1e, 0x02, 0x07, 0xd6, 0xe9, 0x91, 0x09, 0x66, 0x00, 0xa9, 0xe7, 0x1c, 0x3a, 0x77,
                0x32, 0xe3, 0xf1, 0x6d,
            ])
        );
    }

    #[test]
    fn digests_propagate_invalid_run_id() {
        let items = [
            SeenItem {
                message_id: "2",
                seen: true,
            },
            SeenItem {
                message_id: "10",
                seen: false,
            },
        ];
        assert_eq!(
            digest_case("", "11", &items),
            Err(super::IntentError::InvalidInput)
        );
    }

    #[test]
    fn encodes_ordered_literal_v1_vector() {
        let items = [
            SeenItem {
                message_id: "2",
                seen: true,
            },
            SeenItem {
                message_id: "10",
                seen: false,
            },
        ];
        let intent = OrderedIntent {
            run_id: "t03_metadata_20261027",
            tenant_id: "2",
            actor_id: "11",
            mailbox_id: "21",
            authority_generation: "7",
            profile_fingerprint: [0x11; 32],
            fixture_sha256: [
                0xa3, 0x98, 0xc4, 0x50, 0x1f, 0x8f, 0xd4, 0x9b, 0x5d, 0x36, 0x45, 0xc4, 0x32, 0x1c,
                0xd3, 0xa3, 0xfd, 0x59, 0xac, 0xe6, 0xd3, 0xea, 0x83, 0x53, 0x39, 0x52, 0xef, 0xd0,
                0x75, 0x83, 0xd9, 0x34,
            ],
            items: &items,
        };
        let expected = vec![
            0x53, 0x45, 0x54, 0x4a, 0x4f, 0x49, 0x4e, 0x2d, 0x50, 0x30, 0x2d, 0x53, 0x45, 0x45,
            0x4e, 0x00, 0x01, 0x15, 0x74, 0x30, 0x33, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
            0x74, 0x61, 0x5f, 0x32, 0x30, 0x32, 0x36, 0x31, 0x30, 0x32, 0x37, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0xa3, 0x98, 0xc4, 0x50, 0x1f, 0x8f, 0xd4, 0x9b, 0x5d,
            0x36, 0x45, 0xc4, 0x32, 0x1c, 0xd3, 0xa3, 0xfd, 0x59, 0xac, 0xe6, 0xd3, 0xea, 0x83,
            0x53, 0x39, 0x52, 0xef, 0xd0, 0x75, 0x83, 0xd9, 0x34, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a,
            0x00,
        ];
        assert_eq!(encode_intent_v1(&intent), Ok(expected));
    }

    #[test]
    fn rejects_invalid_run_id_grammar() {
        let too_long = "a".repeat(33);
        for run_id in ["", "A", "a-b", "a b", "é", too_long.as_str()] {
            let intent = OrderedIntent {
                run_id,
                tenant_id: "2",
                actor_id: "11",
                mailbox_id: "21",
                authority_generation: "7",
                profile_fingerprint: [0x11; 32],
                fixture_sha256: [0x22; 32],
                items: &[],
            };
            assert_eq!(
                encode_intent_v1(&intent),
                Err(super::IntentError::InvalidInput),
                "invalid run_id: {run_id:?}"
            );
        }
    }

    #[test]
    fn rejects_noncanonical_or_out_of_range_positive_ids() {
        let cases = [
            ("zero tenant", "0", "11", "21", "2"),
            ("zero actor", "2", "0", "21", "2"),
            ("zero mailbox", "2", "11", "0", "2"),
            ("zero message", "2", "11", "21", "0"),
            ("tenant overflow", "9223372036854775808", "11", "21", "2"),
            ("actor overflow", "2", "9223372036854775808", "21", "2"),
            ("mailbox overflow", "2", "11", "9223372036854775808", "2"),
            ("message overflow", "2", "11", "21", "9223372036854775808"),
            ("leading zero", "2", "11", "21", "02"),
            ("plus sign", "2", "11", "21", "+2"),
            ("negative", "2", "11", "21", "-2"),
            ("empty", "2", "11", "21", ""),
        ];
        for (label, tenant_id, actor_id, mailbox_id, message_id) in cases {
            let items = [SeenItem {
                message_id,
                seen: true,
            }];
            let intent = OrderedIntent {
                run_id: "case_1",
                tenant_id,
                actor_id,
                mailbox_id,
                authority_generation: "0",
                profile_fingerprint: [0x11; 32],
                fixture_sha256: [0x22; 32],
                items: &items,
            };
            assert_eq!(
                encode_intent_v1(&intent),
                Err(super::IntentError::InvalidInput),
                "{label}"
            );
        }
    }

    #[test]
    fn accepts_positive_i64_max_for_each_identifier() {
        let items = [SeenItem {
            message_id: "9223372036854775807",
            seen: true,
        }];
        let intent = OrderedIntent {
            run_id: "r",
            tenant_id: "9223372036854775807",
            actor_id: "9223372036854775807",
            mailbox_id: "9223372036854775807",
            authority_generation: "0",
            profile_fingerprint: [0x11; 32],
            fixture_sha256: [0x22; 32],
            items: &items,
        };
        let bytes = encode_intent_v1(&intent).expect("maximum positive i64 IDs are valid");
        assert_eq!(
            &bytes[19..43],
            &[
                0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            ]
        );
        assert_eq!(
            &bytes[bytes.len() - 9..],
            &[0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
    }

    #[test]
    fn accepts_zero_authority_generation() {
        let intent = OrderedIntent {
            run_id: "r",
            tenant_id: "1",
            actor_id: "2",
            mailbox_id: "3",
            authority_generation: "0",
            profile_fingerprint: [0x11; 32],
            fixture_sha256: [0x22; 32],
            items: &[],
        };
        let bytes = encode_intent_v1(&intent).expect("zero generation is valid");
        assert_eq!(&bytes[43..51], &[0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn rejects_noncanonical_or_out_of_range_authority_generation() {
        for generation in ["00", "01", "+1", "-1", "9223372036854775808", "", " 1", "١"] {
            let intent = OrderedIntent {
                run_id: "case_1",
                tenant_id: "2",
                actor_id: "11",
                mailbox_id: "21",
                authority_generation: generation,
                profile_fingerprint: [0x11; 32],
                fixture_sha256: [0x22; 32],
                items: &[],
            };
            assert_eq!(
                encode_intent_v1(&intent),
                Err(super::IntentError::InvalidInput),
                "invalid generation: {generation:?}"
            );
        }
    }

    #[test]
    fn rejects_more_than_128_distinct_items() {
        let ids: Vec<String> = (1..=129).map(|id| id.to_string()).collect();
        let items: Vec<SeenItem<'_>> = ids
            .iter()
            .map(|id| SeenItem {
                message_id: id.as_str(),
                seen: true,
            })
            .collect();
        let intent = OrderedIntent {
            run_id: "case_1",
            tenant_id: "2",
            actor_id: "11",
            mailbox_id: "21",
            authority_generation: "0",
            profile_fingerprint: [0x11; 32],
            fixture_sha256: [0x22; 32],
            items: &items,
        };
        assert_eq!(
            encode_intent_v1(&intent),
            Err(super::IntentError::InvalidInput)
        );
    }

    #[test]
    fn encodes_literal_empty_item_vector() {
        let intent = OrderedIntent {
            run_id: "t03_metadata_20261027",
            tenant_id: "2",
            actor_id: "11",
            mailbox_id: "21",
            authority_generation: "7",
            profile_fingerprint: [0x11; 32],
            fixture_sha256: [
                0xa3, 0x98, 0xc4, 0x50, 0x1f, 0x8f, 0xd4, 0x9b, 0x5d, 0x36, 0x45, 0xc4, 0x32, 0x1c,
                0xd3, 0xa3, 0xfd, 0x59, 0xac, 0xe6, 0xd3, 0xea, 0x83, 0x53, 0x39, 0x52, 0xef, 0xd0,
                0x75, 0x83, 0xd9, 0x34,
            ],
            items: &[],
        };
        let expected = vec![
            0x53, 0x45, 0x54, 0x4a, 0x4f, 0x49, 0x4e, 0x2d, 0x50, 0x30, 0x2d, 0x53, 0x45, 0x45,
            0x4e, 0x00, 0x01, 0x15, 0x74, 0x30, 0x33, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
            0x74, 0x61, 0x5f, 0x32, 0x30, 0x32, 0x36, 0x31, 0x30, 0x32, 0x37, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0xa3, 0x98, 0xc4, 0x50, 0x1f, 0x8f, 0xd4, 0x9b, 0x5d,
            0x36, 0x45, 0xc4, 0x32, 0x1c, 0xd3, 0xa3, 0xfd, 0x59, 0xac, 0xe6, 0xd3, 0xea, 0x83,
            0x53, 0x39, 0x52, 0xef, 0xd0, 0x75, 0x83, 0xd9, 0x34, 0x00, 0x00,
        ];
        assert_eq!(encode_intent_v1(&intent), Ok(expected));
    }

    #[test]
    fn encodes_128_items_with_maximum_run_length() {
        let run_id = "a".repeat(32);
        let ids: Vec<String> = (1..=128).map(|id| id.to_string()).collect();
        let items: Vec<SeenItem<'_>> = ids
            .iter()
            .map(|id| SeenItem {
                message_id: id.as_str(),
                seen: true,
            })
            .collect();
        let intent = OrderedIntent {
            run_id: &run_id,
            tenant_id: "2",
            actor_id: "11",
            mailbox_id: "21",
            authority_generation: "0",
            profile_fingerprint: [0x11; 32],
            fixture_sha256: [0x22; 32],
            items: &items,
        };
        let bytes = encode_intent_v1(&intent).expect("128 items and 32-byte run ID are valid");
        assert_eq!(bytes.len(), 1300);
        assert_eq!(&bytes[146..148], &[0x00, 0x80]);
        assert_eq!(&bytes[148..157], &[0, 0, 0, 0, 0, 0, 0, 1, 1]);
        assert_eq!(&bytes[1291..1300], &[0, 0, 0, 0, 0, 0, 0, 128, 1]);
    }

    #[test]
    fn rejects_duplicate_message_ids_regardless_of_seen_value() {
        for (label, second_seen) in [("same value", true), ("conflicting value", false)] {
            let items = [
                SeenItem {
                    message_id: "2",
                    seen: true,
                },
                SeenItem {
                    message_id: "2",
                    seen: second_seen,
                },
            ];
            let intent = OrderedIntent {
                run_id: "case_1",
                tenant_id: "2",
                actor_id: "11",
                mailbox_id: "21",
                authority_generation: "0",
                profile_fingerprint: [0x11; 32],
                fixture_sha256: [0x22; 32],
                items: &items,
            };
            assert_eq!(
                encode_intent_v1(&intent),
                Err(super::IntentError::InvalidInput),
                "{label}"
            );
        }
    }

    #[test]
    fn rejects_nonadjacent_duplicate_message_ids() {
        let items = [
            SeenItem {
                message_id: "2",
                seen: true,
            },
            SeenItem {
                message_id: "10",
                seen: false,
            },
            SeenItem {
                message_id: "2",
                seen: true,
            },
        ];
        let intent = OrderedIntent {
            run_id: "case_1",
            tenant_id: "2",
            actor_id: "11",
            mailbox_id: "21",
            authority_generation: "0",
            profile_fingerprint: [0x11; 32],
            fixture_sha256: [0x22; 32],
            items: &items,
        };
        assert_eq!(
            encode_intent_v1(&intent),
            Err(super::IntentError::InvalidInput)
        );
    }

    #[test]
    fn preserves_reverse_order_literal_vector() {
        let items = [
            SeenItem {
                message_id: "10",
                seen: false,
            },
            SeenItem {
                message_id: "2",
                seen: true,
            },
        ];
        let intent = OrderedIntent {
            run_id: "t03_metadata_20261027",
            tenant_id: "2",
            actor_id: "11",
            mailbox_id: "21",
            authority_generation: "7",
            profile_fingerprint: [0x11; 32],
            fixture_sha256: [
                0xa3, 0x98, 0xc4, 0x50, 0x1f, 0x8f, 0xd4, 0x9b, 0x5d, 0x36, 0x45, 0xc4, 0x32, 0x1c,
                0xd3, 0xa3, 0xfd, 0x59, 0xac, 0xe6, 0xd3, 0xea, 0x83, 0x53, 0x39, 0x52, 0xef, 0xd0,
                0x75, 0x83, 0xd9, 0x34,
            ],
            items: &items,
        };
        let expected = vec![
            0x53, 0x45, 0x54, 0x4a, 0x4f, 0x49, 0x4e, 0x2d, 0x50, 0x30, 0x2d, 0x53, 0x45, 0x45,
            0x4e, 0x00, 0x01, 0x15, 0x74, 0x30, 0x33, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
            0x74, 0x61, 0x5f, 0x32, 0x30, 0x32, 0x36, 0x31, 0x30, 0x32, 0x37, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
            0x11, 0x11, 0x11, 0x11, 0x11, 0xa3, 0x98, 0xc4, 0x50, 0x1f, 0x8f, 0xd4, 0x9b, 0x5d,
            0x36, 0x45, 0xc4, 0x32, 0x1c, 0xd3, 0xa3, 0xfd, 0x59, 0xac, 0xe6, 0xd3, 0xea, 0x83,
            0x53, 0x39, 0x52, 0xef, 0xd0, 0x75, 0x83, 0xd9, 0x34, 0x00, 0x02, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
            0x01,
        ];
        assert_eq!(encode_intent_v1(&intent), Ok(expected));
    }
}
