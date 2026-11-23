# Unmatched-path oracle (#357, #378)

`bins/gateway/tests/unmatched_recorded.rs` records frozen mailserverd's root-mux answers
for `/auth/*` spellings no inventory row claims (unknown, escaped, wrong-method, bare
subtree and decoded subtree spellings, with and without an operator website) through
`tests/common/mux_oracle.rs`. Recording: gofree-record.yml, `go_upstream=none`. Replay
starts no Go process, leaves every upstream unset and requires
`setjoin_gateway_proxied_to_go_total 0`. Goldens are created exclusively and stamp
`GOFREE_GO_SOURCE`. `divergences.json` lists owner-ruled divergences.
`meet/goldens/rtc-unconfigured` uses the same harness (357c).
