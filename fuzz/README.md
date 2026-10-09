# Slate validation fuzzing

These targets exercise the untrusted v2/v3 slate boundary used by wallet
counterparties.

- `slate_json` consumes arbitrary wire bytes. Its corpus contains valid v2 and
  v3 slates so coverage-guided mutations reach the nested cryptographic fields.
- `slate_mutations` applies fuzz-controlled values and collection shapes to a
  valid slate. This keeps mutations deep enough to exercise payment proofs,
  participant IDs/counts, duplicate participants, missing signatures, and
  zero/multiple kernels.

Both targets call the production upgrade deserializer. Successfully parsed
slates are also passed through message verification, finalization, and, when
the legacy `orig_version` is serializable, a serialize/deserialize round trip.
Any panic, abort, or supported round-trip failure is a fuzz failure; malformed
input returning an error is expected.

Install `cargo-fuzz` and a nightly toolchain, then run:

```sh
cargo +nightly fuzz run slate_json -- -max_len=65536 -rss_limit_mb=2048
cargo +nightly fuzz run slate_mutations -- -max_len=4096 -rss_limit_mb=2048
```

For a bounded CI/review campaign, add `-max_total_time=300` to each command.
Keep any minimized regression input under `fuzz/corpus/<target>/` so ordinary
future campaigns replay it.

The existing controller regression remains responsible for the recipient database
atomicity invariant. These targets deliberately stop at the counterparty slate
validation boundary so fuzz iterations are deterministic and do not share
wallet database state.
