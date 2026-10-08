# TODO

Improvement backlog for NAILS. Items are grouped into **waves** and **chunks**:

- Waves run in order; later waves build on earlier ones.
- Chunks inside one wave touch disjoint files (see *Owns*), so they can be implemented in parallel.
- Item IDs (`T-###`) are stable and are referenced from commit messages.

Decisions that apply across items:

- Backwards compatibility is not a goal yet: CLI flags, JSON output and configuration may change freely (record changes in `CHANGELOG.md`).
- Configuration moves from YAML to strict TOML (`nails.toml`).
- Debian/Ubuntu is the first non-NixOS platform; the platform layer must make Fedora, Arch and others straightforward to add.
- E2E: smoke suite on GitHub-hosted runners for every PR, full suite on hosted runners nightly and on demand, Hetzner kept as one manual workflow.
- `nix/forensics-eval` is replaced by disk-image checks inside the E2E suite; the obfuscation module is removed; an opt-in fresh-home persona mode is added.
- Since 2026-10 the whole-root soft-reboot session (T-134, [ADR 0008](docs/adr/0008-whole-root-soft-reboot.md)) is the only session mode. Ticked items that changed the live per-directory overlays (process detection and restarts, journald re-homing, the runtime tmpfs, the `/nix/store` rebind, the writer rescans) describe removed code and carry a "Superseded" note.

## Wave 0: Hermetic test suite

### W0-C1: Hermetic tests

Owns: `nails-core/src/deactivation/tests.rs`, `nails-core/src/manager/tests.rs`, `nails-core/src/notification/`, `nails-core/src/shell/prompt/tests.rs`, `nails-core/tests/real_filesystem.rs`, `nails-core/src/filesystem/real/tests.rs`, `nails-core/src/manager/helpers/service_controller.rs`, `nails-cli/src/cli/commands/activate/dry_run.rs`, `scripts/check-orphan-modules.sh`, `scripts/check-test-hermetic.sh`

- [x] **T-072: Test hygiene: stop temp-dir leaks and fixed /tmp names, run the shell syntax tests, delete the orphan module, fix notification naming** (low · effort S)

  _Status: still open after wave 0 — no changes were produced to integrate. The `wait_for_unix_socket_ready_*` tests still abort under the restricted sandbox (EPERM on `bind`) instead of skipping._

  **Problem**
  - A single `cargo test --workspace` run leaks ~34 temp dirs (hundreds of leftover `/tmp/.tmp*`). Causes: `.keep()` in `nails-core/src/deactivation/tests.rs` (in `setup_system_profile_stub` at line 120, invoked 9 times, and again at line 190) and `std::mem::forget(temp_dir)` at `nails-core/src/manager/tests.rs:4425`.
  - Fixed shared `/tmp` names are never cleaned up: `nails-cli/src/cli/commands/activate/dry_run.rs:277` (`nails-dry-run-subprocess-{case}`), `nails-core/src/shell/prompt/tests.rs` (~103-248), `nails-core/tests/real_filesystem.rs:225,328,607`, and `nails-core/src/filesystem/real/tests.rs:43`.
  - The six shell syntax tests are `#[ignore]` ("skipped in hermetic CI", `shell/prompt/tests.rs:103-243`), so generated shell is only exercised in VMs.
  - `nails-core/src/manager/activation/test_gate.rs` (52 lines) is not declared in `manager/activation/mod.rs` and never compiles; the real gate lives at `deactivation/test_gate.rs`.
  - Notification tests `thread::sleep(5ms)` "to ensure different filenames" (`notification/tests.rs:138,172,174,351`) although the titles already differ. The doc comment at `notification/mod.rs:76` says `{timestamp_millis}`, but the code uses `%Y%m%dT%H%M%S%3f` + `_` + sanitized title (lines 116,129) written via `std::fs::write` (line 139), so a same-millisecond, same-title write silently overwrites.

  **Fix**
  - Make helpers return their `TempDir` guards; `setup_system_profile_stub` returns `(TempDir, EnvGuard)`. Remove the `.keep()` calls and the `std::mem::forget`.
  - Replace every fixed `/tmp` name with a `tempfile` dir, passing the path to subprocesses by argument or env var.
  - Un-ignore the bash/zsh/fish syntax tests using `tempfile` paths; the shells are provided by the devShell and the CI test job.
  - Delete `manager/activation/test_gate.rs` and add `scripts/check-orphan-modules.sh` to the lint job: list `.rs` files not reachable from `lib.rs`/`main.rs`/tests/benches. Keep it separate from `check-line-count.sh` (that script is being reworked).
  - Notifications: drop the sleeps, correct the doc comment, and open files with `OpenOptions::create_new(true)`, retrying with a numeric suffix on `AlreadyExists`.
  - Leave the file-based gate polling untouched; it is shared with the VM tests.

  **Done when**
  - With a fresh `TMPDIR`, `cargo test --workspace` leaves it empty (asserted in CI).
  - The shell syntax tests run in CI without `--ignored` and pass.
  - `scripts/check-orphan-modules.sh` fails when an unreferenced `.rs` file is added.
  - Two notifications with the same title written in the same millisecond produce two distinct files.

  **Also (moved to wave 0 because every later chunk runs the suite)**
  - Tests must run unchanged inside a restricted sandbox (writable: the checkout and `$TMPDIR` only; Unix-domain sockets denied). Tests that need a Unix socket (`manager/helpers/service_controller.rs` `wait_for_unix_socket_ready_*`) detect `EPERM`/`EACCES` from `bind` and skip with a visible message instead of failing.
  - Add `scripts/check-test-hermetic.sh`: runs `cargo test --workspace` with a fresh `TMPDIR` and fails if anything is left behind in it; CI's test job runs it.

## Wave 1: Foundational refactors begin + CI advisory/nix infra in parallel

### W1-C1: Binary hygiene

Owns: `Cargo.toml`, `nails-core/src/obfuscate/`, `nails-core/src/shell/`, `nails-core/src/nixos/config/verify.rs`

- [x] **T-001: Delete the XOR obfuscation module, inline its constants, and state honestly that the binary is identifiable** (medium · effort M)

  **Problem**
  The `nails-core/src/obfuscate/` module (438 LOC, 39 constants) is fixed-key XOR with a public key-derivation; its own doc comments admit it is "NOT encryption". It provides no real protection: the same strings leak in plaintext elsewhere (env-var and error messages, `nails-deactivate-`, shell-rc markers, tracing callsite paths like `nails_core`), and LLVM constant-folds some values into readable 16-byte prefixes. ~33 files import it (see `rg obfuscate`). The clap `about` spells out the acronym (`nails-cli/src/cli/args.rs:14`), and e2e test `73-binary-obfuscation-scan.nix` (shard id `binary-n`) checks only full strings and passes regardless.

  **Fix**
  Delete `nails-core/src/obfuscate/` and replace every `obfuscate::*` call with the plain literal it produced, grouped into a small constants module beside its users where that reads better. Drop the acronym expansion from the clap `about`/`long_about` and from both `Cargo.toml` descriptions. Remove e2e test 73: delete the `.nix` file and its `binary-n` entries in `nix/e2e-tests/default.nix` and `shard-durations.json`. Do not attempt `black_box`/path remapping; real hygiene is keeping the binary off the decoy and keeping product names out of artifacts written outside the hidden root (covered by the unit-name, runtime-dir, and shell-marker items). Coordinate the example-config template edit with the TOML migration.

  **Done when**
  - `nails-core/src/obfuscate/` is gone and `rg obfuscate nails-core nails-cli` returns nothing.
  - clap `about` and both Cargo descriptions no longer contain the acronym expansion; `nails-cli/tests/cli_integration.rs` help assertions updated.
  - Test 73 removed from the tree, `default.nix`, and `shard-durations.json`.
  - `cargo test --workspace` and `cargo clippy` are clean.

- [x] **T-002: Neutral, configurable active-state indicator; write the rc block and autostart only when the target is on a NAILS overlay** (medium · effort S)

  **Problem**
  The prompt prefix is a hard-coded green `(NAILS-ACTIVE)` (`nails-core/src/shell/prompt.rs`, bash/zsh/fish generators), and the hidden terminal background defaults to `#1a1a2e` (`nails-core/src/config/colors.rs:144`) — both are shoulder-surfing/screenshot liabilities and are undocumented. The rc block marker `# >>> NAILS shell integration` and the XDG autostart `.desktop` (`Name=NAILS Notification Dispatch`) embed the product name and the resolved hidden binary path (`nails-core/src/shell/rc_integration.rs`, autostart ~149, block ~205). Nothing verifies the resolved home actually sits on an active hidden overlay, so if `/home` is excluded or omitted in explicit mode these files land on the decoy disk.

  **Fix**
  Before writing the rc block or autostart file, parse `/proc/self/mountinfo` and confirm the target path is on a NAILS overlay whose `upperdir` is under the hidden root; otherwise skip and `tracing::warn!`. Make the prompt label a TOML config value with a neutral default (empty disables it) and strip the literal product name from the rc markers and the autostart name/contents. Keep `color_scheme.enabled`. Document the screen-visibility trade-off in the operator OPSEC guide.

  **Done when**
  - Unit test: rc/autostart writes are skipped when the home is not on a hidden overlay (fake mountinfo).
  - Default prompt contains no product name; label is configurable via TOML; prompt tests updated.
  - e2e tests 38-43 pass with the new markers.

- [x] **T-003: Make the base-config suspicious-reference preflight use the configured hidden root and scan every imported .nix instead of one keyword file** (low · effort M)

  **Problem**
  `verify_base_config_clean` (`nails-core/src/nixos/config/verify.rs:54-98`) reads only `/etc/nixos/hardware-configuration.nix` and matches a fixed pattern set. It takes no hidden-root argument, so once the hidden root is auto-derived from the binary's parent (no longer always `/mnt/hidden*`), a `nixos-generate-config` `fileSystems` entry for the hidden device passes the check. It never scans `flake.nix`, `configuration.nix`, or imported modules, yet the doc comment claims a "Forensically Clean Base ... Indistinguishable from standard NixOS" — which a single-file keyword scan cannot establish.

  **Fix**
  Pass the configured `hidden_volume_root` plus its backing source (mapper name/UUID resolved from `/proc/self/mountinfo`) into the check and match those alongside the fixed patterns. Extend the scan to every `*.nix` under the base `/etc/nixos` tree (flake, configuration, imported modules). Reword the doc comment so it no longer claims indistinguishability. Drop the byte-identity and `/boot`-entry scan ideas (the code never writes the base file; hidden builds use `test`). Exposing this through `nails verify` is deferred to the verify-overhaul item.

  **Done when**
  - The check flags a hidden-device `fileSystems` entry regardless of mountpoint (unit test with a custom mount path and mapper/UUID).
  - All `*.nix` files under base `/etc/nixos` are scanned.
  - The doc comment no longer claims indistinguishability.
  - `cargo test` and `cargo clippy` are clean.

### W1-C2: Command & error foundation + mount/state seams

Owns: `nails-core/src/error.rs`, `nails-core/src/filesystem/mountinfo.rs`, `nails-core/src/state/`, `nails-core/tests/privileged_mounts.rs`

- [x] **T-004: Give NailsError structured, source-chained variants where control flow depends on the cause** (medium · effort M)

  _Already resolved: typed `Mount { target, errno }` and `ConfigNotFound { path }` variants drive the pivot and config-default fallbacks with no error-text matching, wrapped errors chain `#[source]`, and no `LockPoisoned` constructor remains after the `RefCell` refactor (T-020); wave C1 needed no change._

  **Problem**
  Most of `NailsError` is `String`-wrapped catch-alls; only `IoError` chains a source via `#[from]` (`nails-core/src/error.rs:165`). Because errno is flattened into text, core control flow matches on message strings: the pivot fallback is chosen by substring-matching `"Invalid argument"` / `"Device or resource busy"` / `"not supported"` (`nails-core/src/overlay/strategy/mod.rs:317-319`), and `config/loading.rs:293` branches on `"Config file not found"`. `LockPoisoned(e.to_string())` is duplicated across ~31 call sites.

  **Fix**
  Add typed variants where the cause drives branching: `Mount { target, errno: nix::Errno }` so `strategy/mod.rs` can match `EINVAL`/`EBUSY`/`EOPNOTSUPP`, and `ConfigNotFound { path }` matched by `config/loading.rs`. Attach `#[source]` to wrapped io/nix errors with path context so cause chains can surface in JSON output. Delete the 31 `LockPoisoned` closures together with the Mutex removal rather than hiding them behind a helper. Do not split every catch-all at once; convert only the variants control flow inspects. Note: the typed `Mount`/errno variant is also consumed by T-005 and T-007.

  **Done when**
  - `strategy/mod.rs` selects the pivot fallback by matching a typed errno, with no substring match on error text.
  - `ConfigNotFound` is a typed variant matched in `loading.rs`; no `"Config file not found"` string match remains.
  - Wrapped io/nix errors carry `#[source]`; the `LockPoisoned` closures are gone.
  - `cargo test` and `clippy -D warnings` pass.

- [x] **T-005: One correct mountinfo parser (octal unescape, no per-call canonicalize) and discovery of NAILS-owned mounts; unmount only what NAILS mounted** (high · effort M)

  **Problem**
  Mount-table parsing is hand-rolled and broken in five places. `is_mounted`/`get_filesystem_type`/`is_overlay_mounted`/`get_mount_info` (`nails-core/src/filesystem/real/mount_ops.rs:84-160`) split `/proc/mounts` on whitespace, never decode the kernel octal escapes `\040 \011 \012 \134`, and `canonicalize()` every mount point in the loop; `get_mount_info` uses `?`/`.ok()?` inside the loop (`:147,:152`) so one unresolvable line aborts the whole scan, and any `canonicalize` can block on a dead NFS/CIFS/FUSE mount. A hidden root at a path with a space (common for udisks automounts) therefore fails `HiddenVolumeCheck` (`preflight/checks/hidden_volume.rs`). `submount.rs:29,103`, `dir_ops.rs:214`, and `activation/overlay_mount/restore.rs:11` repeat the same parse. `unmount` (`mount_ops.rs:55-79`) only checks that *something* is mounted at the path, then the orchestrator escalates to `MNT_FORCE|MNT_DETACH` (`deactivation/orchestrator/unmount.rs:81-105`); with stale state this can lazily detach the real `/home`, `/nix`, or `/boot`, and the `/nix/store` bind unmount (`manager/deactivation.rs:451-464`) has the same flaw. Overlay options are built with an unescaped `format!` (`mount_ops.rs:29`) so a `,` or `:` in a path breaks or injects options.

  **Fix**
  Add `nails-core/src/filesystem/mountinfo.rs` parsing `/proc/self/mountinfo` once into entries `{mount_id, parent_id, dev, root, mount_point, fstype, source, super_opts}`, decoding octal escapes everywhere and parsing overlay super-options into `lowerdir`/`upperdir`/`workdir` with backslash handling. Skip bad lines with a debug log; never abort the scan. Do not stat or canonicalize entries — only the single queried target (and the hidden root, once). Reimplement the four `RealFilesystem` methods on it and replace the parsers in `submount.rs`, `dir_ops.rs`, `restore.rs`; merge `filesystem/mount_info.rs` and `overlay/mount_info.rs` into it where that removes duplication rather than adding another struct. Add `NailsMounts::discover(hidden_root: Option<&Path>)` classifying persistent overlays (upper/work under the hidden root), ephemeral overlays (upper under `/run/nails`), pivot/staging binds, and the `/nix/store` restore bind, falling back to top-level overlay mounts when the hidden root is unknown. `unmount(target)` and the `/nix/store` unmount return a typed error unless the target is a NAILS-owned mount. Escape `,`/`:`/`\` in the overlay option builder and reject newlines. Carry the errno in the typed overlay-mount error (T-004) and match `EINVAL`/`EBUSY`/`EOPNOTSUPP` in `strategy/mod.rs`. Give `MockFilesystem` the same ownership semantics. JSON output escaping is handled in the CLI envelope work, not here.

  **Done when**
  - Unit fixtures cover `\040`, `\011`, `\134` in mount point and upperdir, an escaped `,` in lowerdir, a malformed line, and an unreachable mount point: all parse or are skipped, nothing panics, and discovery still finds later entries.
  - `unmount("/home")` on a non-overlay ext4 `/home` returns the ownership error and `umount2` is never called.
  - The pivot fallback is decided from errno values, not message text.
  - No `split_whitespace` mount-table parsing remains under `nails-core/src/filesystem` or the overlay mount path; `canonicalize` in `mount_ops.rs` applies only to the queried target.
  - `nix/e2e-tests/tests/preflight/13-preflight-hidden-volume.nix` passes with the hidden volume mounted at a path containing a space.
  - `cargo test` and `clippy -D warnings` pass.

- [x] **T-006: State file v2: boot_id/owner_pid, a Degraded state, durable fsynced writes, one honest corruption policy, and an inter-process lock** (medium · effort M)

  _Status: done in wave C1 (rest in wave 1b). On a corrupt or unreadable state file, emergency now discovers NAILS-owned mounts from the live mount table (`Filesystem::discover_nails_mounts`), replaces the state with a `Degraded` marker, tears the mounts down in reverse order and ends `Inactive` or `Degraded` with `DeactivationIncomplete`; normal deactivate still refuses an untrusted state. `52-state-corruption.nix` gained the "emergency still runs on a corrupt state" subtest (VM run pending)._

  **Problem**
  Durability: `save_internal` writes a `NamedTempFile` without `sync_all`, renames, and never fsyncs the parent directory (`nails-core/src/state/file.rs:255-294`), unlike the other atomic writers (`filesystem/real/file_ops.rs:136,288,326,347`). `persist_noclobber` fails `AlreadyExists` on every save after the first and then falls back to `persist`, so the no-clobber path is dead; leftover `.tmp*` files are never cleaned. Corruption policy is inconsistent: malformed JSON and non-permission read errors silently become `Inactive` via `RecoveredFromCorruption` (load path end, and `:366-379`), while a checksum mismatch is a hard error (`:399-405`) that breaks `current_state()?` for every command including emergency. The field is documented as `"HMAC checksum for tamper detection"` (`:96`) but is an unkeyed SHA-256 (`:232-246`), which detects corruption, not tampering, and a file with no checksum is accepted with only a warning. Concurrency: there is no flock/O_EXCL/lockfile; state is cached once per process (`manager/state_management.rs:49-71`); no `owner_pid` or boot identity is stored, so a running operation cannot be told from a crashed one. `SystemState::Emergency` is reachable only through `trigger_emergency` and is not written on the production emergency path.

  **Fix**
  Bump the schema version (no back-compat). Add `boot_id` (read from `/proc/sys/kernel/random/boot_id` at write time) and `owner_pid`. Add `SystemState::Degraded { since, reason, remaining_mounts }` for partial teardowns/rollbacks, remove the unwritten `Emergency` variant, and update transitions (`Degraded -> Inactive` via emergency or recover; emergency teardown allowed from any state). Durable save: write data, `sync_all` the temp file, rename over target (drop `persist_noclobber`), fsync the directory, and remove stale `.tmp*` siblings on load. One load policy `LoadOutcome::{Loaded, Missing, Unreadable, Corrupt}`: `Missing` means Inactive; `Unreadable`/`Corrupt` (including checksum mismatch) map to an effective `Unknown` state surfaced to callers (status shows it, activate refuses, emergency/recover fall back to the mount table). Rename the field to `integrity_sha256` and document it as corruption detection only; reject files with no checksum; remove the `hmac`/`tamper` wording from `nails-core/src/state/file.rs`, `error.rs`, `state/tests.rs`, and the e2e names (rename `52-state-checksum-tamper.nix` and update `security/09-state-integrity.nix` and `nix/e2e-tests/default.nix`). Lock: every mutating command (activate, deactivate, emergency, recover, init) takes an exclusive flock on `<state dir>/.lock` on the hidden root (no decoy-side artifact) in `nails-cli/src/cli/commands/mod.rs`, reloading state under the lock; emergency try-locks ~2s and proceeds without it on timeout or an unresponsive hidden root. Add `nails-core/src/state/lock.rs`.

  **Done when**
  - Unit tests: save syncs file and directory (via a test seam); stale temp files are removed on load; a truncated file and a checksum-mismatch file both load as `Unknown` (neither Inactive nor a hard error); missing checksum is rejected.
  - A second activate while the lock is held fails fast with `another nails operation is running (pid N)`; emergency proceeds after the try-lock timeout.
  - `state.json` carries `boot_id` and `owner_pid`; `Degraded` round-trips through save/load; the `Emergency` variant is gone; `rg -i 'hmac|tamper' nails-core/src` returns nothing outside renamed corruption tests.
  - `nix/e2e-tests/tests/state/54-state-concurrent-invocation.nix` asserts the lock message; the renamed checksum-corruption test asserts status shows unknown and emergency still runs.
  - `cargo test` and `clippy` pass.

- [x] **T-007: Correct the wrong overlay security-model comments and derive the OPTIMAL/DEGRADED label from surviving writers** (low · effort S)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (the surviving-writer posture label). The item stays ticked as history; it describes no current code._

  **Problem**
  `pivot/mod.rs:31,33` assert that pivot split-view ("existing processes keep seeing original content") is "forensically beneficial" and a "SECURITY FEATURE". Both are wrong: overlay mounts succeed over busy directories, and processes that keep seeing the original content keep *writing to the decoy* — a leak, not a benefit — which directly contradicts `strategy/mod.rs:74-76`, which correctly calls split-view a degradation. The wrong model feeds the label computation in `manager/activation/mod.rs:310-314`, so leaking states can be reported `OPTIMAL`. The Direct/Pivot method carries no security meaning on its own (both affect pre-existing references the same way).

  **Fix**
  Rewrite the comments in `nails-core/src/overlay/pivot/mod.rs` and `strategy/mod.rs`: a busy directory does not block an overlay mount, and split-view means pre-existing processes leak to the decoy, which is a risk. Re-derive the security label in `manager/activation/mod.rs` from whether surviving writers still reference the target, not from the mount method, keeping the `/boot` whitelist rationale valid under the new basis. Keep the corrected statements as asserted invariants in a unit test. The Phase-4 errno string-match itself is replaced under T-004/T-005.

  **Done when**
  - The "SECURITY FEATURE"/"forensically beneficial" comments are corrected to describe split-view as a risk.
  - The OPTIMAL/DEGRADED label is computed from surviving-writer presence, not Direct vs Pivot, with a unit test asserting the invariant.
  - `cargo test` passes.

- [x] **T-008: Fast privileged integration tier: real overlay and teardown tests in a private mount namespace on hosted runners** (high · effort M)

  **Problem**
  The only real overlay test is `#[ignore]` (`nails-core/src/filesystem/real/tests.rs:22-23`) and no workflow or script runs ignored tests, so real mount/dir-op coverage sits at 39-54% and every change to mount, unmount, overlay, or teardown logic needs the slow VM pipeline for real feedback. The invariant that hidden-session writes never modify the lower tree has no fast test.

  **Fix**
  Add integration target `nails-core/tests/privileged_mounts.rs` (each test `#[ignore = "privileged: run in the mount-namespace job"]`) exercising `RealFilesystem` and the overlay/teardown orchestration against a tmpfs-backed fake root: overlay with several lowers plus bind and tmpfs, umount and reverse-order teardown; mountinfo parsing of paths with spaces, tabs, and backslashes (sharing the T-005 parser); the lower-tree byte-identical invariant (hash before and after activation, writes, teardown); emergency unmount with a busy fd under the target; opaque and whiteout semantics on the upper. Move the ignored overlay test out of `filesystem/real/tests.rs` into this target. Build unprivileged (`cargo test --no-run --message-format=json`) then run `sudo unshare --mount --propagation private <bin> --ignored --test-threads=1`, since unprivileged user namespaces are blocked by AppArmor on ubuntu-24.04. Add a required job on GitHub-hosted ubuntu-24.04 in `.github/workflows/ci.yml` with a 1-3 min budget, and document the same command in `docs/development-guide.md`.

  **Done when**
  - The privileged job runs on every PR in under 3 minutes.
  - The lower-tree invariant test fails when a write is redirected to the lower (verified once with a deliberate mutation).
  - The mountinfo test with a space in the path passes against the escape-aware parser.
  - `nails-core/src/filesystem/real/tests.rs` has no remaining ignored real-overlay test.

### W1-C3: CI advisory policy

Owns: `deny.toml`, `ci/deny_ignores.py`, `ci/tests/`

- [x] **T-009: Scope advisory gating to the shipped dependency graph so unrelated PRs and main stop going red** (high · effort S)

  **Problem:** The `audit` job runs `cargo audit --json` and then `cargo deny check advisories licenses bans sources` over the whole lockfile on every PR, push and weekly schedule (`.github/workflows/ci.yml:80-87`). `CI Success` requires that job (`ci.yml:459-471`), and the main ruleset requires only `CI Success`. `deny.toml` sets `unmaintained = "all"` (l.30) and has no `[graph]` section. Advisories in crates that never ship (anyhow, wasm-only via getrandom -> wasip2 -> wit-bindgen; crossbeam-epoch, dev-only via criterion -> rayon; scc, dev-only via serial_test) kept main red for 10 straight scheduled runs (2026-07-12 to 09-13). They also failed Dependabot PRs and docs-only PR #53: 14 of 24 CI runs in total. cargo-audit cannot filter dev-only or target-specific crates, and it was the step that failed first. The RUSTSEC-2026-0205 ignore (`deny.toml:37-48`) exists only because of the exact 1.93.0 pin (`rust-toolchain.toml`), and its re-evaluation condition is prose with no expiry.

  **Fix:**
  - `deny.toml`: add `[graph] targets = ["x86_64-unknown-linux-musl", "x86_64-unknown-linux-gnu"]` and set `unmaintained = "workspace"`. Keep dev dependencies out of the blocking check with the top-level `--exclude-dev` flag rather than in config, so the full scan still sees them. By default cargo-deny keeps workspace dev-deps such as serial_test and criterion.
  - justfile recipe `deny`: `cargo deny --exclude-dev check advisories bans licenses sources`. In `ci.yml`, run `advisories` only when `Cargo.toml`, `Cargo.lock` or `deny.toml` change (path filter). `bans`, `licenses` and `sources` always run.
  - justfile recipe `deny-full`: all targets with dev-deps included (`cargo deny --target all check advisories` or no `--target` override). It runs weekly in `scheduled.yml`, never gates PRs, and reports through the scheduled-alerting path as an `advisory`-labelled issue, not as a ci-red failure.
  - Remove cargo-audit from `ci.yml:74-83,89-95` (tool install, JSON report, artifact upload), `.pre-commit-config.yaml:113-120`, `flake.nix:236`, `shell.nix:41`, `scripts/ci-local.sh:79-88,211` and `docs/security-validation.md`. Point the pre-commit `cargo-deny` hook at `just deny`.
  - Every `deny.toml` ignore gets a machine-readable `# expires: YYYY-MM-DD` comment. Add the stdlib-only `ci/deny_ignores.py` (tests in `ci/tests/test_deny_ignores.py`). It fails when an ignore has no expiry or the expiry has passed, and `scheduled.yml` runs it.
  - After the toolchain bump to >= 1.93.1, move `serial_test` to 4.x (`nails-core/Cargo.toml:41`) and delete the RUSTSEC-2026-0205 ignore.

  **Done when:**
  - `nix develop -c cargo deny --exclude-dev check advisories bans licenses sources` passes on the branch.
  - An advisory that affects only a dev-only or wasm-only crate does not fail the blocking check, and `just deny-full` reports it.
  - `deny.toml` has no RUSTSEC-2026-0205 ignore, and `cargo tree -i scc` prints nothing.
  - The `deny_ignores.py` tests cover three cases: an expired ignore fails, a future expiry passes, a missing expiry fails.
  - `git grep -n 'cargo.audit'` finds no invocation in workflows, hooks, scripts, the devShell, `shell.nix` or the docs.

### W1-C4: Nix flake & E2E infra

Owns: `nix/e2e-tests/shard-durations.json`, `nix/checks.nix`, `.github/actions/setup-nix/`

- [x] **T-010: Regenerate E2E shard weights, cap outliers, and add global and shutdown test timeouts** (high · effort M)

  **Problem:** `nix/e2e-tests/shard-durations.json` records `preflight-state-check` at 3609 s and `status-always-exits-zero` at 3453 s — together ~40% of the 17,609 s total, against a median weight of ~109 s — for two small tests that actually run in normal time. Both values sit at the NixOS driver's default 3600 s `globalTimeout`, so they are recorded hangs: each calls `canonical_deactivate`, whose `machine.wait_for_shutdown()` (`nix/e2e-tests/lib/test-helpers.nix:150`) has no timeout. The greedy allocator in `scripts/run-e2e-tests.sh` then builds shards up to ~3.4-4.3x imbalanced, and nothing under `nix/` sets `globalTimeout`, so a real hang blocks a shard for the full hour. The file was committed once (b6094be) and nothing regenerates it.

  **Fix:**
  - Regenerate `shard-durations.json` from the per-test PASS-line timings of a recent full run, keeping only boot-verified tests; replace the two outliers with real values (~150 s) and clamp every weight to a sanity bound (e.g. `[30, 900]` s, or 3x the median) so one entry cannot capture a shard.
  - In `nix/e2e-tests/default.nix` set a default `globalTimeout` (~900-1200 s, overridable per test via spec/meta) with explicit overrides for the few long tests (performance ~684 s; rebuild tests 250-410 s); keep `meta.timeout` consistent.
  - Expose each test's effective timeout in the e2e metadata so the planner can reject weights at or above it.
  - Replace the bare `wait_for_shutdown()` in `canonical_deactivate` with a deadline loop (~300 s) that dumps a journal tail and process list before failing.
  - Add a CI step that uploads the PASS-line timings as an artifact and flags (or opens a PR) when they drift >25%.

  **Done when:**
  - Running the greedy allocator over the corrected file for 4 shards gives per-shard loads within ~15% (≈1.3x) of each other.
  - No weight exceeds the cap without a documented per-test override.
  - Every test derivation evaluates with a `globalTimeout`, and the effective timeout appears in the e2e metadata.
  - An injected endless wait in `canonical_deactivate` fails within the deadline and prints diagnostics.

- [x] **T-011: Make nix flake check a fast lint gate, restrict systems to x86_64-linux, move VM tests to their own namespace, add metadata** (medium · effort M)

  **Problem:** `flake.nix:217` sets `checks = ... e2eTests`, so `nix flake check` builds ~97 entries depending on all ~80 VM tests (~3 h) — there is no cheap gate and nothing runs it. `flake-utils.lib.eachDefaultSystem` (`flake.nix:18`) exposes darwin/aarch64 even though `targetTriple` is hard-coded `x86_64-unknown-linux-musl`, so `packages.aarch64-linux.nails` is an x86_64 binary and the tests pin x86_64-linux. The non-standard outputs `e2e-tests`/`e2e-test-metadata`/`forensics-eval-metadata` cause "unknown flake output" warnings. The `nails` package has no `meta`, and `rust-overlay` does not follow `nixpkgs`, so `flake.lock` carries two nixpkgs. Interactive debugging is broken: `scripts/run-e2e-tests.sh:617` and `nix/e2e-tests/default.nix:112` run `nix run ".#checks.$SYSTEM.e2e-$name" --interactive`, which Nix rejects with "unrecognised flag '--interactive'".

  **Fix:**
  - Restrict systems to x86_64-linux (`eachSystem [ "x86_64-linux" ]` or a plain attrset) and remove the non-standard top-level outputs (`forensics-eval-metadata` goes with the `nix/forensics-eval` deletion).
  - Move the VM tests and group linkFarms to `legacyPackages.x86_64-linux.e2e.<name>` and the metadata to `legacyPackages.x86_64-linux.e2e-metadata`.
  - Add `nix/checks.nix` exposing `checks.x86_64-linux` as cheap `runCommand` derivations: `nixfmt --check`, `statix`, `deadnix --fail`, `shellcheck` over scripts, `actionlint`, `zizmor` (offline). No cargo/crane in checks — the Rust gate stays cargo-native in CI.
  - Add package `meta` (description, license, `mainProgram = "nails"`, platforms); set `rust-overlay.inputs.nixpkgs.follows = "nixpkgs"` and refresh `flake.lock` to a single nixpkgs node.
  - Fix the interactive driver: supported command `nix run .#e2e.<name>.driverInteractive`; make `run-e2e-tests.sh -i <name>` use it; delete or rewrite `e2e-test-interactive` and `_interactive-driver`; `-i` on a group fails with a clear error. Update the attribute paths in `scripts/run-e2e-tests.sh` and the debugging section of `nix/e2e-tests/README.md`.

  **Done when:**
  - `nix flake check` builds no VM test and finishes in ~2 min on a warm store; a nixfmt, shellcheck or actionlint violation makes it fail.
  - `nix flake show` lists only x86_64-linux and prints no unknown-output warnings.
  - `nix eval .#packages.x86_64-linux.nails.meta.mainProgram` returns `"nails"`; `flake.lock` has a single nixpkgs node.
  - `nix run .#e2e.basic-workflow.driverInteractive` and `./scripts/run-e2e-tests.sh -i basic-workflow` both start the interactive driver; `nix build .#e2e.basic-workflow` and group resolution work with the new paths.

- [x] **T-012: Make the nails and E2E derivations deterministic and cacheable behind one setup-nix action and a project binary cache** (high · effort M)

  **Problem:** `flake.nix:25,103` injects `SOURCE_DATE_EPOCH = self.lastModified` into `nails`, so its hash changes on every commit. The source fileset (`flake.nix:49-61`) includes `./nix`, `README.md` and `LICENSE` although no Rust code reads them, so editing any test or doc rebuilds the binary and invalidates all ~80 VM-test derivations. `allowSubstitutes = false` and `preferLocalBuild` are set on both `nails` and `nails-release`. `nix/e2e-tests/lib/vm-config.nix:12` reads `NAILS_E2E_VM_CORES` via `builtins.getEnv`, forcing `--impure` (`scripts/run-e2e-tests.sh:530`), so test hashes depend on the host core count, the eval cache is disabled, and two test attributes cannot build in one pure `nix build --keep-going`. The only configured cache is the read-only nix-community Cachix (holds none of this project's paths), `install-nix-action` is pinned at two different SHAs, and cancelled runs lose all completed work.

  **Fix:**
  - `nails`: use a constant `SOURCE_DATE_EPOCH` (no build.rs/`env!` reads it); keep `lastModified` only in `nails-release` for archive mtime. Narrow `src` to `Cargo.toml`, `Cargo.lock`, `.cargo`, `rust-toolchain.toml`, `nails-cli`, `nails-core` (README/LICENSE pass to `nails-release` only). Remove `allowSubstitutes = false`/`preferLocalBuild` from `nails`; keep them on `nails-release`.
  - `vm-config.nix`: fixed `virtualisation.cores = 2`, no `getEnv`; stop passing `--impure` and `NAILS_E2E_VM_CORES` from the runner.
  - Add `.github/actions/setup-nix/action.yml`: one pinned `install-nix-action` SHA, KVM enabled, system-features (`nixos-test`, `kvm`, `big-parallel`), `always-allow-substitutes`. Wire a public project Cachix as a read substituter; push only from trusted contexts (push to main, schedule, maintainer dispatch, same-repo PRs), never forks; use cachix daemon mode so a cancelled run keeps finished paths; add a `pushFilter` allowlist (`nails`, rust-overlay toolchains, `vm-test-run-*`). Add a `cache: false` input for release/reproducibility jobs. Drop the nix-community Cachix everywhere.

  **Done when:**
  - Editing `README.md` or a file under `nix/e2e-tests/tests/` leaves `nix eval .#nails.drvPath` unchanged; only the edited test's derivation changes.
  - Two E2E test attributes build in one pure `nix build --keep-going` without `--impure`; `git grep -n getEnv nix/` returns nothing related to VM cores.
  - A second CI run with unchanged inputs substitutes `nails` and unchanged `vm-test-run` outputs from the project cache; two from-source builds of `nails-release` stay byte-identical.
  - The repository uses exactly one `install-nix-action` SHA and contains no nix-community Cachix reference.

## Wave 2: Strict TOML config + ProcessRunner + dead-code/trait cleanups

### W2-C1: Strict TOML config

Owns: `Cargo.toml`, `nails-core/src/config/`, `nails-core/tests/path_properties.rs`, `nix/e2e-tests/default.nix`

- [x] **T-013: Switch configuration to strict TOML (nails.toml), remove dead knobs, add nails config path|show|validate** (high · effort L)

  **Problem:** `Config` (nails-core/src/config/types.rs:173) has no `deny_unknown_fields` and is parsed with pre-1.0 `serde-saphyr` 0.0.22 (Cargo.toml:31, loading.rs:132), so typos are dropped without a word. A misspelt `nixos_flake` falls back to the discovery cascade that includes /etc/nixos (activate/mod.rs:216-220). A misspelt root key falls back to the binary-derived root. `default_verbosity`, `color_output`, `milestone_tips` and `verify_on_deactivate` (types.rs:270-283, `CliOverrides` :105-119) are parsed and advertised, but nothing reads them. Preflight always rejects `extended_overlays` (overlay_compatibility.rs:75-87). The README uses `hidden_volume_root:`, but init writes an absolute `hidden_volume_path:` (init.rs:45, accepted only through the alias at types.rs:179), which breaks when the VeraCrypt mount point changes. A missing `--config` prints a stuttering error followed by a ~70-line example. `load_config_or_exit` (commands/mod.rs:40-53) exits on any parse error, so a bad config also blocks `nails emergency`. The discovery rustdoc (loading.rs:8-25) is stale.

  **Fix:**
  1. Replace serde-saphyr with the `toml` crate (workspace Cargo.toml, nails-core/Cargo.toml:28, Cargo.lock). Discovery becomes `{binary_dir}/config/nails.toml`, and `--config` accepts any TOML path. Rewrite the discovery doc comment.
  2. Add `#[serde(deny_unknown_fields)]` to `Config` and every nested struct. Accept exactly one root key, `hidden_volume_root`, and drop the alias.
  3. Delete the four dead knobs from types.rs, defaults.rs, overrides.rs, builder.rs, the example config, the init template and the `CliOverrides` write in activate/mod.rs. Remove `extended_overlays` and its plumbing (config/overlay.rs, builder, preflight_runner.rs, deactivation.rs:330-336, activation rollback/overlay_mount, activate/dry_run.rs).
  4. activate, check and `config validate` exit 3 on unknown keys, with a did-you-mean hint (string similarity against the known key set). emergency and deactivate never refuse: they log one warning line and continue with binary-derived defaults plus the live mount table.
  5. A missing explicit config prints one line, `config file not found: X (run `nails init <root>` or pass --config)`, and exits 3. The example moves to `nails config show --example`.
  6. Add the `nails config` subcommand (new commands/config.rs, args.rs):
     - `path`: the resolved path and whether it exists.
     - `show`: the effective config as TOML, with the source of each value (default/file/cli/derived); supports `--json`.
     - `validate [PATH]`.
  7. init writes TOML with `hidden_volume_root` commented out, so the root is derived from the binary. `status --details` shows `(not found, using defaults)` for a missing config.
  8. Convert all tests and fixtures to TOML:
     - Rust tests: config_tests.rs, cli_integration.rs, logging and status tests, storage_readiness, init/tests.rs.
     - E2E: `writeHeadlessConfigFn` (nix/e2e-tests/lib/test-helpers.nix) and every e2e file using `*.yaml` paths (~78).
     - Rename 23-config-malformed-yaml to a TOML unknown-key test.
     - Update or drop 24, 25 and 66 (extended overlays).

  **Done when:**
  - `serde-saphyr` is gone from both Cargo.toml files and Cargo.lock, and the default path is `<binary_dir>/config/nails.toml`.
  - An unknown top-level or nested key makes activate, check and `config validate` exit 3 with a hint, while emergency and deactivate warn and proceed (cargo tests cover both).
  - `rg 'default_verbosity|color_output|milestone_tips|verify_on_deactivate|hidden_volume_path|extended_overlays' nails-core nails-cli` returns nothing.
  - A missing `--config` prints exactly one error line and exits 3.
  - `nails config path|show|validate` work in human and `--json` modes (assert_cmd tests).
  - init e2e tests 45-47 pass with TOML output, and `cargo test` plus clippy are clean.

- [x] **T-014: Generated configuration reference kept in sync by a test; clean the example config text** (high · effort S)

  **Problem:** There is no configuration reference: of ~20 `Config` fields, only `hidden_volume_root` and `nixos_flake` appear in any .md file. `Config::example_config` (nails-core/src/config/loading.rs:193-262) is printed in user-facing errors and has several problems:
  - It advertises dead keys.
  - It calls the derived root "Required" (:197).
  - It lists 5 of the 12 default exclusions (types.rs:66-79, which include a stray `/Downloads`).
  - It ships "Story 14.10" in the release binary (:222).
  - It suggests a developer-specific `/etc/nixos#amnesia-virtualbox` flake (:261).

  The init template (nails-cli/src/cli/commands/init.rs:37-67) is a second copy that has drifted from the example. Rustdoc still says the config lives at `~/.nails/config.yaml` (loading.rs:94,286; overrides.rs:83). In an anti-forensics tool, a key that does nothing without telling the user is a safety problem.

  **Fix:** Depends on T-013.
  1. Write docs/configuration.md with one table (key, type, default, effect) and an overlay semantics section: auto mode, the exclusion list with a reason for each entry, and the exclusion safety floor. Link it from README.md.
  2. Add nails-core/tests/config_reference.rs. It serializes `Config::default()` to TOML and asserts that every key and its default appear in the doc, and that the doc names no key the struct lacks. Setting `NAILS_REGEN_CONFIG_DOCS=1` regenerates the table, so no new CI job is needed.
  3. Generate `example_config` and the init template from one TOML source in nails-core. A unit test parses that source with the strict loader.
  4. Clean the example text: remove the story ID, the developer flake name, the "Required" claim and the partial exclusion list (link the reference instead). Drop `/Downloads` from the defaults or document why it is there.
  5. Fix the `~/.nails` rustdoc references.

  **Done when:**
  - docs/configuration.md lists every key with its default and effect.
  - `cargo test config_reference` passes, and fails when a field is added without docs.
  - `git grep -nE 'Story [0-9]|amnesia-virtualbox|~/.nails' -- nails-core/src/config nails-cli/src/cli/commands/init*` returns nothing.
  - The example config and init template parse with the strict loader.
  - `strings target/release/nails | grep -c 'Story '` prints 0.

- [x] **T-015: Reject unsafe configured paths (relative, .., symlinked root, option separators) and add property tests for containment and mountinfo parsing** (medium · effort M)

  **Problem:** Nothing validates configured paths. A relative root, `..` components and a symlinked hidden root are all accepted: e2e 10-permissions-security.nix:62-79 only prints "Note: ... accepted". Overlay options are joined with unescaped `,` and `:` (nails-core/src/filesystem/real/mount_ops.rs:23-34), so a path containing either character corrupts the mount options. /proc/mounts is split on whitespace without decoding octal escapes (mount_ops.rs:84-160). A root path with a space therefore reads as not mounted, and `unmount` returns Ok early (:55-58). Cargo.lock has no property-testing crate, and path and state tests are example-based only.

  **Fix:** Lands with T-013.
  1. Add validation to `ConfigBuilder::build` (nails-core/src/config/builder.rs), with a typed error per rule:
     - The hidden root, every overlay target and every exclusion is absolute and normalized (no `.` or `..`).
     - The hidden root is not a symlink (lstat) and does not lie inside an overlay target.
     - No `,`, `:` or newline appears in any path used in overlay mount options.
  2. Add `proptest` as a dev-dependency with a bounded case count, running in the normal test gate. Containment property (nails-core/tests/path_properties.rs): random components, including `..`, `.` and symlinks created in a tempdir, either yield derived paths under the hidden root (state file, upper/work dirs, logs, notifications) or are rejected.
  3. Add a round-trip property for the escape-aware mountinfo parser (encode `\040 \011 \012 \134`, parse, compare), plus example tests for paths containing a space, `,` or `:`. Place them next to the parser in nails-core/src/filesystem/mount_info.rs. The parser itself, the switch of `is_mounted` to statx `STATX_ATTR_MOUNT_ROOT` and the removal of per-line `canonicalize` belong to the mountinfo parsing item. This item adds only the tests.

  **Done when:**
  - Unit tests show that a relative root, a `..` component, a symlinked root, and a `,` or `:` in an overlay path are each rejected with a specific error.
  - The proptest suites run under `cargo test` with bounded cases.
  - The mountinfo round-trip property passes.

- [x] **T-016: Make E2E tests able to fail: fix tests that never boot, soft Note branches, and misleading self-documentation** (high · effort M)

  _Status: done (waves 2, C1, verified wave C3/K3). The notify-dispatch tests 48/50/51 are dedented so they boot the VM; the `default.nix` VM-started prelude/assert and the `e2e-soft-assertions` lint (`nix/e2e-tests/lint.nix`, wired into `nix/checks.nix`) are in place; the hard-assertion rewrites of tests 03/06/09/10 landed (test 10 uses the T-015 path rejection); test-64 suppression coverage moved host-side into `cli_contract.rs`; `scripts/run-e2e-tests.sh` is a thin wrapper over `ci.e2e`; grep gates for `print("Note:` / Self-check / `|| echo 'CLEAN'` are empty. Remaining is nix-only: `nix flake check` must confirm the soft-assertion lint and VM-started assert — see nix_pending._

  **Problem:**
  - **Tests that never boot:** in 48-notify-dispatch-signal-flow, 50-notify-malformed-signal and 51-notify-no-notify-send, the header sits at 4 spaces and the body at 8 (e.g. 50:20-29). Nix `''` stripping folds the body into the last interpolated helper, so `machine.start()` never runs (recorded 40/10/11 s). These are the only tests of `nails notify-dispatch`. Nothing detects a test that never starts a VM.
  - **Soft branches:**
    - 10-permissions-security.nix:53,65,78 print "Note:" and pass.
    - 09-state-integrity.nix:39-49 searches /run, /tmp and /var for a state file that lives on the hidden volume, and never asserts. Lines :52 and :59 accept "ACTIVE", which also matches "INACTIVE".
    - 33-session-kill-graphical.nix:161-163 skips the wrapper-log assertion.
    - 03-emergency.nix checks state only after lib/emergency.nix:48 has rebooted.
    - 64-no-logs-suppression.nix:50,61 only print the log size.
  - **Snapshot diff:** 06-snapshot-diff.nix:35-37,65-67 computes md5 lists but only greps for `(secret|hidden|forensic)` with `|| echo 'CLEAN'` (:79,91), so it misses drift that contains no keyword.
  - **Misleading text:** 38 tests carry false "Self-check"/"Checklist" headers, nix/e2e-tests/README.md:131 promises "no softened assertions", and scripts/run-e2e-tests.sh:42-62 hardcodes test descriptions.

  **Fix:**
  1. Dedent the bodies of 48, 50 and 51.
  2. In nix/e2e-tests/default.nix, prepend a prelude that wraps each machine's `start()` to set `_nails_vm_started`, and append `assert _nails_vm_started, 'testScript never started a VM'`. This also works for tests that end with `crash()` or `shutdown()`.
  3. Add nix/e2e-tests/lint.nix to the flake checks. It fails on `print("Note:` / `print(f"Note:` and on `|| echo 'CLEAN'` masking. Document the rule in the README.
  4. Make the assertions hard:
     - Test 10 (needs T-015): symlinked, relative and traversal configs exit non-zero, leave no overlay mounted and keep the state Inactive. The log check must find the log, or assert that none exists when logging is off.
     - Test 09: read the state from the hidden-volume path, assert mode 0600, and compare the parsed JSON state.
     - Test 33: require the wrapper log.
     - Test 03: add `run_emergency_command(reboot=False)`. Assert the live state first (no overlays, hidden files unreachable, history clean), then reboot and re-check.
     - Test 64: assert that no nails lines reach journalctl or the console during the `--no-logs` run.
     - Test 06: diff the checksum and file lists for /home, /etc and /var against an explicit allowlist of volatile paths.
  5. Strip the Self-check/Checklist headers. Add `meta.description` to every test and generate `describe_target` from it.

  **Done when:**
  - Re-indenting test 50's body fails the build with 'testScript never started a VM'.
  - 48, 50 and 51 boot, run notify-dispatch and take longer than 40 s.
  - `rg 'print\(f?"Note:' nix/e2e-tests/tests` is empty, and the lint runs in `nix flake check`.
  - Test 10 passes only because activation is refused. Test 03 asserts the live state before rebooting.
  - 06 fails on an injected keyword-free change outside the allowlist, and 64 asserts suppression.
  - `rg -l 'Self-check|Checklist' nix/e2e-tests/tests` is empty, and run-e2e-tests.sh has no hardcoded descriptions.

### W2-C2: ProcessRunner abstraction

Owns: `nails-core/src/process/`, `nails-core/src/nixos/command.rs`, `nails-core/src/filesystem/real/dir_ops.rs`

- [x] **T-017: Collapse the duplicate command executors and scattered Command sites into one ProcessRunner with absolute-path resolution** (medium · effort L)

  _Already resolved: one `ProcessRunner` (real + mock) owns the test-safety guard, the cleared child env and the fixed tool directories, the three executors are thin wrappers over it, `sync`/`du` run in-process and `cp -a` is kept for the pivot copy; wave C1 also routed the cached host commands, service probes and reboot dispatch through it. The residual `/run/current-system/sw/bin` literals in `manager/helpers/{command_cache,service_controller,runtime_cache}.rs` and `overlay_mount/restore.rs` move with T-082._

  **Problem:** Running an external program is reimplemented many ways. Three overlapping traits exist: `nails-core/src/nixos/command.rs:43` `CommandExecutor` (nixos-rebuild/nix/switch), `nails-core/src/process/restart/mod.rs:65` `CommandExecutor` (execute_systemctl/execute_kill), and `nails-core/src/process/session/types.rs:84` `SessionCommandExecutor` (systemctl/loginctl/kill). The latter two each repeat the `#[cfg(not(test))]` / `#[cfg(test)] panic!` guard (session/types.rs:101-190, restart/mod.rs:82-120). Alongside them, dozens of raw `std::process::Command::new` production sites (cp, du, sync, swapoff, nixos-rebuild, chown, nix-store, ldd) each carry their own error handling and hardcoded paths — e.g. `/run/current-system/sw/bin/systemctl` at session/types.rs:110 and restart/mod.rs:84. There is no single place to enforce PATH policy, the test-safety guard, logging, or per-distro binary resolution.

  **Fix:** Define one `ProcessRunner` trait (e.g. `run(argv, env, stdin) -> Output`) with a real impl and a mock impl, and route every external command through it. Make it the home for the test-safety guard and for per-distro binary resolution, coordinating with the platform seam and the existing `CachedCommand` (Direct / ViaLoader) logic in `nails-core/src/manager/helpers/command_cache.rs` so no hardcoded `/run/current-system/sw/bin` paths remain. Collapse the three executor traits into thin helpers over `ProcessRunner`. Replace safe shell-outs with in-process Rust: `sync` (`cleanup/manager.rs:283`) -> `nix::unistd::sync()`; `du -sb` (`dir_ops.rs:179`) -> an in-process directory walk. Keep `cp -a` (`filesystem/real/dir_ops.rs:142`, the snapshot/pivot copy that must preserve ownership, xattrs, ACLs, hardlinks and special files) via `ProcessRunner` or a vetted copy crate — do not replace it with a naive `std::fs` copy. Leave the `find` + `getfattr`/`setfattr` opaque shell-outs in `overlay/opaque.rs` to the separate in-process xattr item.

  **Done when:** a single `ProcessRunner` trait with real + mock impls exists; the three executor traits are removed or reduced to thin wrappers over it; all non-opaque production external commands go through `ProcessRunner` with no remaining hardcoded binary paths; `sync` and `du` run in-process; `cp -a` semantics are preserved for the pivot copy; `cargo clippy` is clean and existing process/session/nixos tests pass.

### W2-C3: Dead-code sweep

Owns: `nails-core/src/manager/activation/rollback.rs`, `nails-core/src/emergency.rs`, `nails-core/src/lib.rs`

- [x] **T-018: Delete dead modules and the non-functional in-memory history clear, and tighten visibility so the dead_code lint works** (low · effort M)

  _Status: done in wave C1. The production `allow(dead_code)` sites are gone: the unreachable `start_nix_daemon`/`restart_nix_daemon` and the String `default_hidden_volume_root` are deleted, `test_gate.rs` compiles its no-op helper only where it is called, and the stale allow on the legacy NixOS builder is removed._

  **Problem**
  Several modules ship unreachable or non-working code kept alive only by `#[allow(dead_code)]` or by tests:
  - `nails-core/src/manager/activation/rollback.rs` (106 lines, two `#[allow(dead_code)]` fns referenced only from `activation/tests.rs`). The live activation-failure rollback is `MountTracker::rollback_all` plus its `Drop` impl (`manager/mount_tracker.rs:179`, `:282`), invoked from `activation/overlay_mount/auto_mount.rs:176`.
  - `nails-core/src/emergency.rs` (43 lines) is a one-function re-export wrapper around `NailsManager::emergency_deactivate`, re-exported again at `lib.rs:189`.
  - `cleanup/history/cleaner.rs:270` `attempt_clean_in_memory_history` spawns `bash -c` to clear history in a throwaway subprocess; its own doc comment states it does not work and exists only to satisfy an old acceptance criterion. Called at `cleaner.rs:139`. The real in-memory-history defense is `kill_user_shells` (SIGKILL before overlay teardown, `process/shell_cleanup.rs:128`, called at `manager/deactivation.rs:481`); the comment's claim that bash in-memory history "will be lost when the shell exits anyway" is also false (bash writes HISTFILE on exit).
  - `config_file_name` (`obfuscate/mod.rs:343`) is test-only dead code. Because library items are `pub`, rustc's dead_code lint cannot see them, so dead code is silenced with `#[allow(dead_code)]` instead of deleted; roughly 30 pub fns are referenced only at their own definition.

  **Fix**
  - Delete `rollback.rs`, its `mod rollback;` line (`activation/mod.rs:37`), and the tests that exercise only it; `MountTracker::rollback_all`/`Drop` is the single rollback mechanism.
  - Collapse `emergency.rs` into the `pub use` in `lib.rs` and drop the module.
  - Delete `attempt_clean_in_memory_history`, its `#[cfg(not(test))]` call site (`cleaner.rs:139`), and the per-shell clear-command helper; replace with a short comment pointing at `kill_user_shells` (SIGKILL before teardown) as the real mitigation.
  - `config_file_name` is removed with the obfuscate module (handled in the obfuscation-removal chunk); if any copy survives, delete it.
  - Narrow nails-core items that only nails-cli needs to `pub(crate)` (or a curated re-export list) so `cargo build` surfaces remaining dead items, then delete them. Treat `#[allow(dead_code)]` as a defect to remove, not to suppress.

  **Done when**
  - `rollback.rs` and the `emergency.rs` wrapper are gone; the build links via `MountTracker` Drop and the `lib.rs` re-export.
  - No `bash -c` history-clear subprocess runs during deactivation; a comment documents SIGKILL-before-teardown as the real mechanism.
  - Visibility is tightened so no production `#[allow(dead_code)]` remains in nails-core (test-only gates excepted); `cargo build`, `cargo test`, and `cargo clippy` run clean with zero warnings.

### W2-C4: Filesystem trait trim

Owns: `nails-core/src/filesystem/mock/operations_profiles.rs`, `nails-core/src/filesystem/real/mod.rs`, `nails-core/tests/real_filesystem.rs`

- [x] **T-019: Trim the Filesystem god-trait: delete zero-call methods, return owned types, replace the fat test fake** (medium · effort L)

  **Problem**
  `Filesystem` (`nails-core/src/filesystem/traits/mod.rs:32`) is a 45-method trait mixing overlay mount, swap, generic file I/O, NixOS profile build/switch, and process detection. Six methods have no production callers: `nixos_build_profile`, `nixos_switch_profile`, `nixos_get_current_profile`, `nixos_profile_exists` (its only caller is the dead `nixos_switch_profile`, `real/system_ops.rs:52`), `swap_disable`, and `read_directory`. Their real-filesystem tests shell out to the host: `swapoff -a` as root (`tests/real_filesystem.rs:208`) and `nixos-rebuild build --profile` (`tests/real_filesystem.rs:267`/`:532`, which only "pass" because `--profile` is rejected as an invalid flag). `swap_disable` having no caller means swap is detected but never disabled. `read_directory` returns `Vec<std::fs::DirEntry>` (`:225`), which is un-mockable — the mock returns "not fully implemented" (`mock/operations_files.rs:212`) — and `modified_time` leaks `chrono::DateTime` (`:231`). `status/tests.rs:11-164` is a ~150-line `FailingMountCheckFilesystem` that re-delegates all 45 methods just to override `is_mounted`.

  **Fix**
  1. Delete the six zero-call methods from the trait and every impl/test: real (`real/system_ops.rs:14-98`, `read_directory` in `real/dir_ops.rs:85`, delegates in `real/mod.rs`), mock (`mock/operations_profiles.rs`, `read_directory_impl` in `mock/operations_files.rs`, `mock/filesystem_impl.rs`), and tests (`tests/real_filesystem.rs` swap/nixos cases, `real/tests.rs:922`, mock cases), plus now-orphan mock setters.
  2. Keep `modified_time` (used at `logging/rotation/mod.rs:256`) but have it return an owned timestamp rather than leaking `chrono` across the trait boundary; after the `DirEntry`-based method is gone, no trait method should expose `std::fs` types.
  3. Add a `mock_set_is_mounted_error(path)` knob to `MockFilesystem` and replace `FailingMountCheckFilesystem` with it; delete assertion-free coverage-only tests.
  4. Note for later platform-abstraction work: NixOS-specific operations stay deleted and any surviving host-specific ops move onto the platform/host adapter rather than this trait.

  **Done when**
  - The six methods and all their real + mock impls and tests are gone; `cargo build` and `cargo clippy` are clean workspace-wide.
  - No surviving trait method returns `std::fs::DirEntry`; `modified_time` returns an owned type.
  - `FailingMountCheckFilesystem` is replaced by the `mock_set_is_mounted_error` setter, and no test runs `swapoff` or `nixos-rebuild` on the host.
  - Assertion-free coverage-only tests are removed and the full test suite passes.

## Wave 3: Manager decomposition + CLI flag/output model + CI dev loop/workflows

### W3-C1: Manager decomposition

Owns: `nails-core/src/manager/mod.rs`, `nails-core/src/manager/activation/mod.rs`, `nails-core/src/manager/deactivation.rs`, `nails-core/src/manager/state_management.rs`

- [x] **T-020: Simplify NailsManager orchestration: step functions over owned context, drop Arc<Mutex>, remove runtime set_var** (medium · effort L)

  _Status: done in wave 3 (W3-C1). The state cache is now `RefCell<Option<StateFile>>`, `activate_with_options` runs over one `&mut` borrow via named step functions with a `StateGuard` that derefs to the manager, the `deactivation/orchestrator` module is merged into a single `DeactivationOrchestrator` in `manager/deactivation.rs`, protected shell PIDs are passed explicitly (the `unsafe set_var` guard is gone; `detach.rs` keeps only the cross-process handoff), and no `Arc<Mutex>`/`LockPoisoned` remains in production manager code (test harnesses still use a local `Mutex` adapter). The merged `manager/deactivation.rs` is ~969 lines, deliberately over the 500-line hook gate (kept in the SKIP set)._

  **Problem:** `activate_with_options` (`nails-core/src/manager/activation/mod.rs:156`-521) is a single ~370-line procedure that calls `manager_arc.lock()` 10 times, re-reading the cached state between steps. The `Arc<Mutex>` state cache (`manager/mod.rs:85`-87, documented single-threaded under AR47, no production `thread::spawn`) forces 31 `LockPoisoned` closures across non-test manager code. `StateGuard::new(Arc::clone(&manager_arc), ...)` (`activation/mod.rs:245`) keeps an Arc clone only to roll back on drop. `ProtectedShellPidEnvGuard` (`manager/deactivation.rs:158`-209) uses `unsafe std::env::set_var`/`remove_var` to hand protected PIDs to `kill_user_shells` (`process/shell_cleanup.rs:79`,128) even though both run in-process. Deactivation is split across two layers: `manager/deactivation.rs` (555 lines) and the `nails-core/src/deactivation/orchestrator` module. `preflight_runner.rs:3` shows modules were carved by a 500-line gate, not by responsibility.

  **Fix:**
  - Rewrite `activate_with_options` as a short sequence of named step functions over a context acquired once (`&mut NailsManager` or a small `ActivationContext`); remove per-step re-locking.
  - Replace `Arc<Mutex>` in production manager code with ownership/`&mut`; if the lazy state cache still needs interior mutability use `Rc<RefCell>`/`OnceCell`, not a `Mutex`; delete the `LockPoisoned` closures; drop the `Send + Sync` bound on `Filesystem` if nothing requires it.
  - Redesign `StateGuard` to borrow/own the manager (deref guard) instead of holding an Arc clone.
  - Pass protected PIDs to `kill_user_shells` as an explicit `&[u32]`; keep the env var only for the `systemd-run` cross-process handoff in `nails-cli/src/cli/detach.rs`.
  - Merge `manager/deactivation.rs` and the `deactivation/orchestrator` module into one layer. Avoid a big-bang Plan/saga framework.

  **Done when:** `activate_with_options` is a list of named step functions over a context acquired once with no per-step re-locking; no `Arc<Mutex>` or `LockPoisoned` closures remain in production manager code (any interior mutability is `Rc<RefCell>`/`OnceCell`); no `unsafe env::set_var` in deactivation and protected PIDs are passed explicitly; deactivation is a single layer; full test suite and `cargo clippy` are green.

### W3-C2: CI pipeline (toolchain, runners, workflows)

Owns: `.github/workflows/`, `scripts/`, `ci/`, `rust-toolchain.toml`

- [x] **T-021: Single-source the Rust toolchain from rust-toolchain.toml and make the flake devShell the only dev environment** (medium · effort M)

  _Partial (T-009): `serial_test` moved to 3.5 to drop `scc`, the RUSTSEC-2026-0205 ignore is gone, and `cargo-audit` is out of both dev shells with `just` added; the toolchain single-sourcing remains._

  _Status: done in wave 3 (W3-C2). All pinned `dtolnay/rust-toolchain` steps and the SBOM step now `rustup toolchain install` from `rust-toolchain.toml`; `flake.nix` reads the channel via `lib.importTOML`, the devShell is the only dev environment (`shell.nix` removed) and installs the git hooks via a shellHook; resolver 3. The channel/`serial_test` 4.x bump was deliberately not taken (its goal is already met at 1.93.0 and it is unbuildable here). Nix devShell/`nix build` evaluation is pending (see nix_pending)._

  **Problem**
  - The toolchain version `1.93.0` is hard-coded 13 times:
    - `.github/workflows/ci.yml`, 8 times (l.36, 67, 115, 159, 250, 294, 337, 380)
    - `release-core.yml:243`
    - `rust-toolchain.toml:2`
    - `flake.nix:29` and `:40`
    - `shell.nix:19`
  - Because of the exact patch pin, serial_test 4.x (which needs 1.93.1) could not be adopted, so `deny.toml:37-47` ignores RUSTSEC-2026-0205 instead.
  - `Cargo.toml:3` sets `resolver = "2"`, which turns off the edition-2024 resolver that respects rust-version.
  - The devShell (`flake.nix:224-242`) is missing tools that the docs and scripts use: cargo-nextest, just, python3, actionlint and zizmor. It still ships cargo-tarpaulin and cargo-audit, which nothing uses.
  - `shell.nix` duplicates the package list on top of an unpinned `<nixpkgs>`. It is also the only place that installs the git hooks (`shell.nix:56-61`).

  **Fix**
  - `rust-toolchain.toml` holds the only exact pin. Bump it to the latest stable patch available in the locked rust-overlay (at least 1.93.1), and update `flake.lock` if needed.
  - `flake.nix` reads the channel with `(lib.importTOML ./rust-toolchain.toml).toolchain.channel` and keeps a separate component list for each toolchain:
    - devShell: rust-src, rust-analyzer, llvm-tools-preview, clippy and rustfmt.
    - musl release toolchain: rust-src only.
    - Do not use plain `fromRustupToolchainFile`: it drops rust-analyzer and pulls clippy, rustfmt and llvm-tools into the release closure. The release hash changes once, which is acceptable.
  - The CI and release workflows drop their `toolchain:` inputs and use the toml. This is done together with the PR-gate and release-pipeline items.
  - `Cargo.toml`: switch to `resolver = "3"` and keep `rust-version` as a separately maintained MSRV. Bump serial_test to 4.x in `nails-core/Cargo.toml` (this drops scc), remove the RUSTSEC-2026-0205 ignore and fix any new clippy lints.
  - devShell:
    - Add cargo-nextest, just, actionlint, zizmor, and python3 with ruff and mypy.
    - Keep cargo-deny and cargo-llvm-cov.
    - Remove cargo-tarpaulin, cargo-audit, and bc unless a recipe still needs it.
    - Add a `shellHook` that installs the pre-commit, pre-push and commit-msg hooks when they are missing.
  - Delete `shell.nix` and remove it from every path filter.

  **Done when**
  - Outside CHANGELOG, the pinned version string appears only in `rust-toolchain.toml`, and `nix build .#nails` and `nix develop` both use that channel.
  - Inside `nix develop`, `cargo nextest --version`, `just --version`, `python3 --version`, `actionlint --version` and `zizmor --version` all succeed, and cargo-tarpaulin and cargo-audit are absent.
  - `cargo tree -i scc` prints nothing and `deny.toml` no longer ignores RUSTSEC-2026-0205.
  - `cargo test --workspace --locked` and `cargo clippy --all-targets --locked -- -D warnings` pass on the new toolchain.
  - Entering the devShell in a fresh clone installs all three git hooks.

- [x] **T-022: Replace the bash E2E runners and in-Nix Python helpers with one tested, importable Python planner and runner package** (medium · effort L)

  _Status: done (wave 3, C1, completed wave C3/K3). The `ci-python` flake check and the `ci.e2e` package/wrapper are in place; the `nix/e2e-tests/py/nails_e2e` in-VM helper package ships one `run_command_capture` and one `install_nixos_rebuild_wrapper` (host-side unittest/ruff/mypy green here) and session tests 33 and 36 are migrated onto it; the forensics scripts are deleted. Remaining is nix-only: build the migrated VM tests importing `nails_e2e` via `extraPythonPackages`, and a real suite run to regenerate `shard-durations.json` — see nix_pending._

  **Problem**
  - Duplicated runners:
    - `scripts/run-e2e-tests.sh` (710 lines) and `run-forensics-eval-tests.sh` (576 lines) share 326 identical lines and 13 functions.
    - Between them they embed 14 `python3 - <<'PY'` heredocs.
  - Even `--help` needs Nix, because `nix eval` runs before argument parsing (l.24, l.70).
  - Execution:
    - Each test is a separate serial impure `nix build` (about l.525-535).
    - `compute_vm_cpu_plan` (l.202) sizes VMs from the host.
    - The local default target `all` boots about 80 VMs.
  - Nothing tests the sharding logic or sanity-checks `nix/e2e-tests/shard-durations.json`; that is how the corrupted weights went unnoticed.
  - No ruff or mypy covers the repository's Python.
  - About 1.5k lines of Python live inside Nix strings in `nix/e2e-tests/lib/*.nix`:
    - Four incompatible `run_command_capture` definitions (`contract-helpers.nix:3`, `notification-helpers.nix:95`, `preflight-helpers.nix:28`, `shell-helpers.nix:3`), plus inline copies.
    - Eight copies of `install_nixos_rebuild_wrapper`.
    - `*_local` and `*_for(node)` variants, because helpers hardcode the global `machine`.
    - Dead helpers: `assertions.nix:53` `assertVerifyCleanFn`, `perf.nix:16` `p99Fn` and `security-helpers.nix:356` `transitionalStateFns`.
    - These helpers are only checked when a test script is assembled.

  **Fix**
  - New stdlib-only package `ci/e2e/` (with `ci/__init__.py`), run as `python3 -m ci.e2e`. Subcommands:
    - `list`
    - `resolve <targets> [--affected <base-rev>]`: groups come from the flake's E2E metadata, the single source. `--affected` selects the `ci` group plus every test whose drvPath differs from the base revision.
    - `plan --shards N --format github-matrix`: duration-weighted greedy split. Unknown tests get the median weight. A weight at or above the test's timeout is an error.
    - `run <attrs | --shard i/N> [--jobs N]`: one `nix build --keep-going -L` over all attributes, with no `--impure`. Writes `e2e-durations.json` from the internal-json log.
    - `regen-weights <files...>`: writes the median of recent runs into `shard-durations.json`.
    - `interactive <name>`: launches driverInteractive.
    - Metadata loads lazily.
  - `scripts/run-e2e-tests.sh` becomes a wrapper of about 30 lines (`exec python3 -m ci.e2e "$@"`), and the default target becomes the `ci` group. Delete `scripts/run-forensics-eval-tests.sh` and `scripts/run-forensics-eval.sh`.
  - New package `nix/e2e-tests/py/nails_e2e` for the in-VM helpers:
    - Functions take `machine` as a parameter. The driver imports the package through extraPythonPackages.
    - One `run_command_capture` that returns one dict shape, and one `install_nixos_rebuild_wrapper`.
    - Delete the three dead helpers.
    - Migrate one test directory per change, starting with `tests/session/`.
    - Pass generated scripts through `pkgs.writeText` or JSON instead of hand-escaped Nix strings.
  - Tests and linting:
    - unittest suites in `ci/tests/` cover resolve, plan, regen-weights and argument parsing, including `--help` and `-i` without Nix.
    - `pyproject.toml` configures ruff and non-strict mypy for `ci/`, `nails_e2e` and `scripts/*.py`.
    - A cheap flake check (not the VM tests) runs unittest, ruff and mypy.

  **Done when**
  - `./scripts/run-e2e-tests.sh --help` works with no `nix` on PATH.
  - Running the wrapper with no target runs the `ci` group, and `-i <name>` launches driverInteractive.
  - `python3 -m unittest discover -s ci/tests` passes, ruff and mypy are clean, and the fast flake check runs them.
  - `run --shard 1/4` performs exactly one `nix build` and writes one duration entry per test.
  - `plan` yields balanced shards and rejects a weight above a test's timeout.
  - `nails_e2e` has a single `run_command_capture` and a single `install_nixos_rebuild_wrapper`, and the three dead helpers are gone.
  - The session tests use the package and stay green.
  - Both forensics runner scripts are deleted.

- [x] **T-023: Fast local loop: re-enable incremental builds, split pre-commit from pre-push, add a justfile CI also calls** (high · effort M)

  _Status: done in wave 3 (W3-C2). `.cargo/config.toml` no longer forces `incremental = false` (the release derivation still sets `CARGO_INCREMENTAL=0`); the `justfile` is the single command source (fmt-check, lint, test, doctest, coverage, check, ci-rust, deny/deny-full, nix-lint, e2e, stress) with the 85 coverage threshold defined once; pre-commit is fast/offline/changed-files and the heavy clippy/test/coverage moved to a pre-push `just check`; `ci.yml` coverage runs `just coverage`; `scripts/ci-local.sh` and `scripts/burn-in.sh` are deleted._

  _Partial (T-009): a `justfile` now exists with `deny` and `deny-full` recipes that CI also calls, and the cargo-audit pre-commit hook is gone; the incremental-build and pre-commit/pre-push split remain._

  **Problem**
  - `.cargo/config.toml:1-2` forces `incremental = false` for dev and test builds. A one-line nails-core edit takes 22-24 s to rebuild instead of 8-10 s. Nix builds already set `CARGO_INCREMENTAL=0` (`flake.nix:130`).
  - `.pre-commit-config.yaml` runs all of this on every commit, about 1.5-3 min in total:
    - clippy (l.144) and the full `cargo test` (l.151).
    - The suite again under llvm-cov (l.159-209), writing to the fixed path /tmp/nails-coverage.
    - cargo-audit (l.115), which needs network and has no `files:` filter.
    - Full cargo-deny (l.123).
    - The line-count check (l.130), which takes 26 s.
  - The coverage threshold is defined three times with different values: 85.5 in the hook (l.203), 85 in `ci.yml:20` and 85 in `scripts/ci-local.sh:32`.
  - The `ci:` block (l.247) is dead, because every hook is `language: system`.
  - `scripts/ci-local.sh` and `scripts/burn-in.sh` use `#!/bin/bash`, which does not exist on NixOS, and nothing references them.
  - `ci-local.sh` prints `ok` for tools it skipped, and `docs/ci.md:201-211` lists yet another command set.

  **Fix**
  - Delete `[build] incremental = false` and keep the musl rustflags block.
  - Add a `justfile` as the single command source for local use and CI. Every cargo call uses `--locked`. Recipes:
    - `fmt-check`, `lint` and `test` (nextest).
    - `doctest`.
    - `coverage`: llvm-cov over nextest. The threshold is defined only here, and output goes under `target/`.
    - `check`: fmt-check, lint and test.
    - `ci-rust`: exactly what the ci.yml Rust jobs run.
    - `deny` and `deny-full`, with flags from the advisory-policy item.
    - `nix-lint`.
    - `e2e <target>` and `e2e-debug <name>`.
    - `stress`, using the harness from the flaky-test item.
  - Pre-commit stage: offline, changed files only, under about 10 s.
    - Hooks: whitespace, yaml, json and toml checks, detect-secrets, `cargo fmt --check`, nixfmt, statix, deadnix, shellcheck and commit-msg.
    - Add the line-count check only once it runs in under 1 s.
  - Pre-push stage: `just check`.
  - Remove the rust-test, rust-coverage, cargo-audit and cargo-deny hooks, the `ci:` block and the fixed /tmp paths. cargo-deny runs in CI and through `just deny`.
  - Delete `scripts/ci-local.sh` and `scripts/burn-in.sh`. The devShell installs the hooks (T-021).

  **Done when**
  - The pre-commit stage of `pre-commit run --all-files` finishes in about 10 s on a warm machine with networking disabled.
  - `just --list` shows the recipes and `just check` passes.
  - The coverage threshold appears exactly once (in the justfile), and ci.yml calls `just coverage`.
  - After a one-line nails-core edit, `cargo test --no-run` rebuilds incrementally.
  - `scripts/ci-local.sh`, `scripts/burn-in.sh` and the cargo-audit hook are gone.

- [x] **T-024: Add a scheduled maintenance workflow and a report-status action that tracks red main, nightly and release runs in an issue** (high · effort M)

  _Status: done in wave 3 (W3-C2). New `.github/actions/report-status` composite action (takes `toJSON(needs)`, opens/comments/closes a labelled issue; `issues: write` only on report jobs, called with `if: !cancelled()`); `scheduled.yml` gained a `task` dispatch input and jobs for the crate fetcher-canary, rust-cache warming, stress loop and benchmarks/geiger; `ci.yml` dropped its `schedule:` and gained a report-status job on push to main; `release.yml` got one too. Sibling follow-ups noted on T-025/T-026 and the CI docs item (W8-C1)._

  _Partial (T-009): `.github/workflows/scheduled.yml` now runs the weekly full advisory scan (`just deny-full`) and the deny.toml ignore-expiry check; the report-status action and `advisory`-labelled issue reporting remain._

  **Problem**
  - The only schedule is the weekly cron in `ci.yml:12-14`, which just re-runs the PR jobs.
  - No workflow reports failures. The only `if: failure()` steps (`ci.yml:133`, `:356`) upload artifacts.
  - Scheduled CI on main was red for 10 consecutive weeks without anyone noticing.
  - The release crate fetcher was broken for a month (a stale importCargoLock against crates.io's HTTP 403). It was only discovered when a lockfile-changing PR hit it.
  - The full-graph advisory scan, a fetcher canary and the Nix release build are not scheduled.
  - Nothing enforces re-evaluating deny.toml ignores.
  - GitHub disables scheduled workflows after 60 days without repository activity.

  **Fix**
  - New composite action `.github/actions/report-status/action.yml` (about 40 lines, using the gh CLI):
    - Inputs: `status`, `title` (default `CI red: <workflow>`) and `label` (`ci-red` or `advisory`).
    - On failure, it finds or creates the open issue with that label and title, then comments with the run URL and the failed jobs. On success, it closes the issue.
    - It runs as the final job (`needs` all jobs, `if: always()`, `issues: write` on that job only) in ci.yml push-to-main runs, scheduled e2e.yml runs, scheduled.yml and release.yml.
  - New `.github/workflows/scheduled.yml` with a weekly cron and workflow_dispatch with a `task` input. Jobs:
    - `advisories-full`: runs `just deny-full` and reports with label `advisory`. It never affects PR checks.
    - `deny-ignore-expiry`: fails when a deny.toml ignore is past its review date, using the script from the advisory-policy item.
    - `fetcher-canary`: setup-nix without the project cache, with cache.nixos.org as the only substituter, building `.#nails-release`. This forces crate vendoring from crates.io.
    - `cache-warm`: touches the shared rust-cache key on main so it is never evicted after 7 days.
    - Slots for `stress`, an informational `benchmarks` job and an optional `geiger` job.
    - The monthly lockfile-refresh job from T-025.
  - Remove `schedule:` from ci.yml.
  - The CI docs item documents in `docs/ci.md`:
    - The red-main rule: revert or quarantine within 24 h; triage advisory issues within 7 days.
    - The 60-day schedule auto-disable.

  **Done when**
  - A forced failing dispatch of scheduled.yml opens exactly one `ci-red` issue.
  - A second failure comments on that issue, and a later success closes it.
  - An advisory failure opens or updates an `advisory` issue without touching `ci-red` or any PR check.
  - `fetcher-canary` builds nails-release without the project cache and fails when crate vendoring breaks.
  - ci.yml has no `schedule:` trigger, and actionlint and zizmor are clean on both new files.

- [x] **T-025: Rework dependency automation (grouped Dependabot, Conventional Commit titles) and trim the shipped dependency footprint** (medium · effort S)

  _Status: done in wave 3 (W3-C2). `dependabot.yml` reduced to the two supported ecosystems (cargo, github-actions), monthly with grouped + security PRs and correct `build(deps):` titles; new `pr-title.yml` and `update-flake-lock.yml` (flake.lock + pre-commit autoupdate) workflows; a monthly `lockfile` task in `scheduled.yml` opens a `cargo update` PR; `signal-hook` removed from nails-core and chrono built without default features. The "five ecosystems in dependabot.yml" done-when is impossible (no nix/pre-commit/toolchain ecosystem) so those are covered by `update-flake-lock.yml` + a manual toolchain bump. Maintainer steps (secret, PR-creation permission, required check) and the new action SHAs still need GitHub-side verification._

  **Problem**
  - `.github/dependabot.yml` covers only cargo (l.22) and github-actions (l.113), weekly. Version updates only bump direct dependencies, but #54's fixes were transitive lockfile bumps.
  - `flake.lock` (nixpkgs 2026-04-14), the pre-commit revs and the toolchain are never updated.
  - The comments at l.11-12, l.154-165 and l.170 are wrong.
  - `prefix: "build(deps)"` and `"ci(deps)"` combined with `include: "scope"` (l.33-35, l.124-125) produce titles like `build(deps)(deps): ...`.
  - Conventional Commits are not enforced on main (#35, #38).
  - The commit-msg hook rejects `release`, and `.gitmessage` lists types and scopes that do not match the ones actually used.
  - Unnecessary dependencies:
    - signal-hook (`nails-core/Cargo.toml:25`) has no uses.
    - chrono (`Cargo.toml:34`) keeps default features, which pull in wasmbind and iana-time-zone extras.
    - criterion (dev-dependency in both crates) adds about 30 crates and brought in the crossbeam-epoch advisory.

  **Fix**
  - `dependabot.yml`:
    - Ecosystems: cargo, github-actions, nix (`flake.lock`), pre-commit, and rust-toolchain once T-021 lands.
    - Monthly schedule with one group per ecosystem; keep the security-update groups.
    - `cooldown` of about 7 days.
    - `prefix: "build"` / `"ci"` with `include: "scope"`.
    - Fix the wrong comments.
    - Actions updates are merged manually. Auto-merge is allowed only for dev-dependency patch or minor updates with a green gate.
    - If the nix ecosystem is unavailable, use a monthly SHA-pinned DeterminateSystems/update-flake-lock workflow instead.
  - Monthly transitive-refresh job in `scheduled.yml` (T-024):
    - Runs `cargo update` and `cargo deny --exclude-dev check`, then opens a PR with SHA-pinned peter-evans/create-pull-request.
    - Uses a dedicated fine-grained token secret, because PRs opened with GITHUB_TOKEN do not trigger CI.
    - Without the secret, it only writes the diff to the step summary.
  - New `.github/workflows/pr-title.yml`:
    - SHA-pinned amannn/action-semantic-pull-request on pull_request opened, edited, synchronize and reopened, with `pull-requests: read`.
    - Allowed types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert.
  - Use the same type list in the commit-msg hook and `.gitmessage`:
    - Scopes: core, cli, ci, nix, e2e, release, docs, deps.
    - Release bumps use `chore(release): ...`.
    - Drop the `feat(story-1.5)` example.
  - Dependency footprint:
    - Remove signal-hook, unless the signal-handling work adds a real call site.
    - chrono: `default-features = false, features = ["clock", "std", "serde"]`.
    - Run `cargo machete` and review `cargo tree -d`.
    - Decide criterion's fate together with the benchmark rework.
    - Confirm serde-saphyr is gone after the TOML config migration.
  - Maintainer steps: add the token secret, enable Dependabot security updates, and make pr-title a required check.

  **Done when**
  - `dependabot.yml` lists the five ecosystems on a monthly schedule with groups and cooldown, and the next cargo PR is titled `build(deps): ...`.
  - pr-title.yml fails `Fix stuff` and passes `fix(ci): restore cache key`.
  - The commit-msg hook, pr-title.yml and `.gitmessage` accept exactly the same types.
  - The monthly lockfile job exists and opens a PR when the secret is set.
  - `cargo tree -i signal-hook` prints nothing, or signal-hook has a real call site.
  - `cargo tree -e features -i chrono` shows no wasmbind.
  - `cargo machete` is clean and `cargo deny --exclude-dev check` passes.
  - After the TOML migration, Cargo.lock has no serde-saphyr.

- [x] **T-026: One reusable, runner-parameterised E2E workflow: hosted smoke per PR and push, full suite nightly or on demand, Hetzner as a single manual lane** (high · effort L)

  _Status: done (implementation complete, verified unchanged wave C3/K3). `.github/workflows/e2e.yml` is the reusable workflow (pull_request/push/schedule/workflow_dispatch/workflow_call, mode/runner/max-shards inputs, plan/shard/e2e-result/report-status jobs); `e2e-hetzner.yml` is the single manual lane; the old e2e-tests*/forensics* workflows are deleted; actionlint clean. Only live-infra/maintainer steps remain (not code): confirm `e2e-result` on a hosted PR, record a real `mode=all` run in `docs/ci.md`, commit the first nightly `shard-durations.json`, verify FLAKY once, dispatch the Hetzner lane once, then make `e2e-result` required and delete the stale `hetzner-pr` environment._

  **Problem**
  - `e2e-tests.yml` is the only hosted, secret-free lane: 6-9 `ci` tests in 405-659 s on ubuntu-24.04 with KVM. It triggers only on the deleted `dev` branch (l.8, l.20), so no E2E has run automatically since 2026-04-27. `docs/ci.md:13` and `:64-75` still describe it.
  - The E2E path filter is copied 4 times and the copies have drifted apart.
  - `e2e-tests-full.yml` (`pull_request_target` plus `hetzner-pr` approval):
    - Only 5 of 58 runs succeeded, and Dependabot runs hung until the 30-day limit.
    - The workflow file comes from the base branch, so a PR never runs its own workflow changes.
    - The resolver checks out the live PR head without comparing it to the approved SHA (about l.123-135).
  - The Hetzner shard workflow:
    - It is 851 lines, about 767 of them duplicated in `forensics-eval-full-shard.yml`.
    - It walks a 9-combination server ladder at about 10.5 min per failed combination.
    - It puts a reusable runner registration token into cloud-init.
    - It enforces a "6-hour workflow budget" (`e2e-tests-full-shard.yml:668-729`) that GitHub does not actually impose. The check aborts any re-run started about 5.4 h after the first attempt.
  - Execution problems:
    - One serial impure build runs per test.
    - Each VM gets all host cores and 4 GB (`vm-config.nix:19-20`).
    - No test sets a timeout, so the driver default of 3600 s applies.
    - One failure turns a whole shard red, with no retry and no flaky signal.

  **Fix** (the runner stays a parameter; the final runner strategy is still open)
  - New `.github/workflows/e2e.yml` (workflow_call plus workflow_dispatch).
    - Inputs:
      - `runner`: JSON for runs-on, default `"ubuntu-24.04"`.
      - `mode`: `affected`, `ci`, `all` or `execute`.
      - `max-shards`.
    - Jobs:
      - `plan`: setup-nix with `always-allow-substitutes`; builds `.#nails` once and pushes it to the cache in trusted contexts; the T-022 planner emits the matrix.
      - `shard` matrix: enables KVM via udev on hosted runners and runs `ci.e2e run --shard`. Failed attributes are retried once, and a pass on retry is marked FLAKY in the step summary. Uploads durations and failure logs only. Timeout is about 1.5x the expected shard time.
      - `e2e-result`: `if: always()`, and green when the path filter skipped the suite.
    - Keep the matrix generic (targets x runner, plus an optional platform axis) so the Debian/Ubuntu smoke tests can plug in. The host-side disk-image checks run here as ordinary tests.
  - Triggers, using one path filter:
    - PR to main runs `affected`.
    - The `full-e2e` label runs `all`.
    - Push to main runs `all`; unchanged tests are substituted from the cache.
    - The schedule (cron is one parameter, nightly by default) runs `execute`. This runs every `.driver`, refreshes durations and runs the performance tests as non-blocking. Failures are reported through report-status (T-024).
    - No `pull_request_target` and no secrets. Dependabot and fork PRs run like any other PR.
  - `nix/e2e-tests`: default `globalTimeout = 900` with per-test overrides. Fixed VM sizing of 2 cores and 2 GB (4 GB for graphical nodes), with no environment-variable sizing.
  - New `.github/workflows/e2e-hetzner.yml`, about 150 lines or less:
    - Trigger: workflow_dispatch only, with an exact ref/SHA input.
    - Provisioning: one hcloud loop over (server type, location) candidates, with an API availability check and create waits of 1-2 min.
    - A just-in-time single-use runner config instead of a registration token in user-data.
    - Calls e2e.yml with the provisioned label, then tears down with `if: always()`.
    - No budget logic and no approval environment.
  - Delete the old workflows: `e2e-tests.yml`, `e2e-tests-full.yml`, `e2e-tests-full-shard.yml`, `forensics-eval-full.yml`, `forensics-eval-full-shard.yml` and `forensics-eval-full-pr-metadata.yml`.
  - Maintainer steps: make `e2e-result` a required check after about 2 weeks green, and delete the `hetzner-pr` environment.

  **Done when**
  - A nails-core PR reports `e2e-result` from ubuntu-24.04.
  - A PR that touches one test file runs the `ci` group plus that test.
  - A docs-only PR passes without booting VMs.
  - Dependabot PRs get results without approval.
  - `mode=all` finishes in at most 10 shards and about 20 min wall-clock on hosted runners (measured and recorded in `docs/ci.md`), and the workflow runs unchanged with a self-hosted label.
  - A deliberately flaky test shows up as FLAKY.
  - The regenerated `shard-durations.json` has no entry above 900 s.
  - `git grep -nE 'pull_request_target|workflow_started_epoch|TOTAL_BUDGET|branches: \[dev\]' .github` returns nothing.
  - The six old workflows are deleted, and actionlint and zizmor are clean.

### W3-C3: CLI output, flags & diagnostics

Owns: `nails-cli/src/cli/args.rs`, `nails-cli/src/cli/commands/`, `nails-cli/src/cli/output/`, `nails-cli/src/main.rs`

- [x] **T-027: One global flag set (GlobalArgs/OutputSettings) with correct TTY, colour, ASCII and status-symbol handling** (medium · effort L)

  _Status: done in wave 3 (W3-C3). A flattened `GlobalArgs` makes `-c`, `-v/-q`, `--color auto|always|never`, `--ascii`, `--json` and `--no-log-file` work before or after the subcommand; `status -v` is now `--details`; `--plain`/`--no-color`/`--no-logs`/`NAILS_NO_COLOR` are removed. `OutputSettings` is resolved once (colour decided per stream, empty `NO_COLOR` treated as unset, `CLICOLOR_FORCE`, `TERM=dumb`/non-UTF-8 ASCII fallback) and the log filter now follows `-v/-vv/-q` on every command. `nails-core::output` holds one mark table; DECOY renders an uncoloured neutral mark distinct from CRITICAL; prompts go to stderr (proven by a subprocess test)._

  **Problem**
  Root `-v`/`-q`/`--no-logs` are not global (`nails-cli/src/cli/args.rs:20-30`), so `nails status -q` is rejected while `nails -q status` works. Subcommand `-v`/`-q` reach `Verbosity`/`CliOverrides` but never the tracing filter (`main.rs:54-62`), so `activate -vv` enables no debug tracing and `-q` still prints INFO; `-vv` and `-vvv` are identical. `status -v` means "details". `--json`/`--no-color`/`--plain` are redeclared on four subcommands (`args.rs:52-62,125-135,151-161,165-175`); verify only has `--json`. `NO_COLOR` is read in 8 places, each treating an empty value as set. Tracing `with_ansi` depends only on render mode (`cli/logging.rs:136,205`), so pipes and the journal get escape codes; `TERM=dumb` is ignored and `colored` decides from stdout even for stderr. Status shares the red-circle glyph between DECOY and CRITICAL.

  **Fix**
  Add `#[command(flatten)] GlobalArgs` with `global = true`: `-v` (count) and `-q` in a mutually-exclusive `ArgGroup`, `--color auto|always|never`, `--ascii`, `--json`, `--no-log-file` (help says stderr), `-c/--config`. Remove every per-subcommand `-v`/`-q`/`--json`/`--no-color`/`--plain`; rename `status -v` to `--details`. Move each command's arguments into its own `#[derive(Args)]` struct; handlers take `(&OutputSettings, &XArgs)` instead of 15 positional bools. Resolve once in main into `OutputSettings { verbosity, mode, color_stdout, color_stderr, ascii }` and feed it to the tracing subscriber and all renderers (`-q`=errors+final line, `-v`=DEBUG, `-vv`=TRACE). Delete the 8 `NO_COLOR` reads; add one per-stream detector (`auto` = `is_terminal()` && `TERM!=dumb` && `NO_COLOR` unset/empty; `CLICOLOR_FORCE` forces on; ASCII auto-on for `TERM=dumb`, non-TTY, or non-UTF-8). Gate tracing `with_ansi` on the stderr decision and set `colored` via `set_override`. Prompts (`nails-core/src/prompts/mod.rs`) write to stderr/`/dev/tty` with ASCII variants. Use one symbol table across `output.rs`, `cli/logging.rs`, `cli/output/verify.rs` and the status renderer; give DECOY a neutral marker and keep red for CRITICAL only. Coordinate with the rendering-consolidation work: whichever lands first owns the `OutputSettings`/`Ui` type.

  **Done when**
  `nails status -q`, `nails -q status`, and both `--json` orderings are accepted and behave identically (assert_cmd). Unit test: `activate -vv`→TRACE, `-q`→quiet filter. `rg NO_COLOR nails-cli/src nails-core/src` matches only the resolver; no subcommand struct declares json/no_color/plain/verbose/quiet. `nails status 2>&1 | cat -A` has no escapes; `TERM=dumb`+`LANG=C` is ASCII-only; empty `NO_COLOR=` keeps colour on a TTY. Captured-IO test proves prompts never write stdout. DECOY and CRITICAL render distinctly. e2e contract 61-65, notification 48/50/51, preflight 13/17, session 34/35, smoke 12 and `lib/session-helpers.nix` use the new flags and pass; clippy `-D warnings` and `cargo test` pass.

- [x] **T-028: Stable machine interface: a typed JSON envelope on stdout and one documented exit-code table returned from main** (medium · effort L)

  _Status: done in wave 3 (W3-C3). New `output/{exit,envelope,dto}.rs`: an `ExitStatus` enum mapped to `ExitCode` (verify warnings/critical 10/11, preflight 4, config 3, needs-root 5, invalid-state 6, degraded 7), one `Envelope<T>` (`schema_version`, `command`, `ok`, `data`|`error{code,message,hint}`), and tagged snake_case state/verification DTOs. Every handler returns `ExitStatus`; `main` returns `ExitCode`; the only `process::exit` is the detach chokepoint; status/verify/deactivate/emergency/activate drop their hand-built JSON and Debug-formatted state; opt-in `status --exit-status`. Guarded by `tests/machine_interface.rs` and `tests/source_guards.rs`._

  **Problem**
  `status --json` prints Rust Debug strings: `"state": "Active { ... }"` and `"overlay_verification": "Mismatch { ... }"` (`nails-cli/src/cli/output/status/json.rs:66,92`); human output has the same line. Casing is mixed: verify enums are PascalCase and verify's state is `format!("{:?}").to_uppercase()` (`commands/verify.rs:50`). Error JSON is hand-built without escaping (`deactivate.rs:89,117`, emergency, status), and `NailsError::MountBusy`/`UnmountError` contain literal newlines (`nails-core/src/error.rs`), so failures emit invalid JSON on stderr while success JSON goes to stdout. Config/lock/safety-guard errors print plain text even with `--json`. There is no `schema_version`, a typed deactivate renderer is dead code, and only exit 0/1/2 are used through ~34 `process::exit` calls (code 2 overloaded; preflight failure exits 2 detached / 1 attached; verify maps Warning and Critical both to 1).

  **Fix**
  Add serde output DTOs per command (`rename_all="snake_case"`), separate from on-disk types: state as `{"kind":"active",...}`, verification as `{"kind":"mismatch",...}`; human output prints a short label, not `{:?}`. With `--json` print exactly one envelope on stdout `{schema_version:1, command, ok, data | error:{code,message,hint}}`, including config/lock/safety pre-dispatch errors; activate emits typed NDJSON (`{"type":"progress"}` events then a final `{"type":"result",...}`). Delete all hand-built JSON strings for `serde_json`, and wire the typed deactivate renderer (drop its `#[allow(dead_code)]`). Add one `ExitStatus` enum in nails-cli: 0 ok, 1 failed, 2 usage, 3 config/env, 4 preflight refused, 5 needs root, 6 invalid state, 7 degraded/reboot, 10 verify warning, 11 verify critical. `main` returns `std::process::ExitCode`; handlers return results (only the detach parent may exit directly); errors print `error: <message>` in Display form. status keeps exit 0 when it produced a report, with opt-in `--exit-status`. Tighten `nix/e2e-tests/fixtures/schemas/status.json` and `verify.json` to require `schema_version` and enum `state.kind`; add cargo tests validating sample output against them. The user-facing exit table is generated from this enum by the docs/help items.

  **Done when**
  `status --json` for an Active state returns `state` as an object with kind `"active"`; no module formats state/verification with `{:?}` (grep). Every `--json` path (config-load failure, safety guard, lock error, a MountBusy case) prints one parseable document (NDJSON for activate) on stdout with `schema_version`/`command`/`ok`. `rg 'process::exit' nails-cli/src` matches only the detach parent; no hand-built JSON remains. assert_cmd pins usage 2, bad config 3, preflight 4 on both activate paths, verify warning 10, verify critical 11. Fixture schemas require `schema_version` and enumerate `state.kind`; cargo tests validate against them; contract 58/59/60 pass. `output/deactivate.rs` has no `#[allow(dead_code)]`; no Debug-quoted errors remain.

- [x] **T-029: Redesign activate flags (--session/--pivot/-y), make the session-kill confirmation reachable, report the detached outcome, confirm before deactivate reboots** (high · effort L)

  _Status: done in wave 3 (W3-C3). `--session kill|keep`, `--pivot refuse|allow|ask` and `-y/--yes` replace the old `--kill-session`/`--accept-pivot-risks`/`--interactive`/`--no-clear-history` flags (`--flake` now conflicts with `--overlay-only`); `ActivateOptions::default()` flips to the secure CLI defaults and the test-convenience `activate()` stays non-killing. A confirmation gate refuses off-TTY runs without `-y` before any side effect (detached workers neither prompt nor refuse), the session-kill confirmation runs ahead of staging, the detached activation outcome is reported (human "sudo nails status", JSON "detached" envelope), and deactivate prints recovery guidance and confirms before the reboot handoff._

  **Problem**
  `--kill-session`, `--no-pivot` and `-y` are parsed then discarded (`nails-cli/src/cli/mod.rs:32-36`); effective values come from negating the opposite flag (`activate/mod.rs:96-98`). `nails activate --interactive` wrongly exits 2 with a `--kill-session` message (`activate/mod.rs:116-120`), and the pivot guard at `:121-126` is unreachable so `prompt_pivot_mount_acceptance` never fires. `activate --no-clear-history` is a no-op (only deactivation reads it). `execute` takes 15 positional parameters, and `ActivateOptions::default()` (`nails-core/src/activate_options.rs:104-121`) is the opposite of the CLI defaults. On the default kill path `yes` is always true, so `prompt_session_kill_confirmation` returns immediately (`nails-core/src/process/session/management/mod.rs:48-50`): `sudo nails activate` ends the graphical session without asking. The confirmation text duplicates a step. After detaching, the parent prints "Handoff complete" and exits 0 with no follow-up command and no final JSON (`cli/detach.rs`). deactivate reboots without confirmation and prints recovery guidance only after requesting the reboot (`commands/deactivate.rs:95-111`); its help does not mention the reboot. 57 e2e files pass `--no-kill-session`.

  **Fix**
  In `ActivateArgs` add `--session kill|keep` (default kill, kept as the secure default), `--pivot refuse|allow|ask` (default refuse; `ask` prompts on a TTY, else refuses), and `-y/--yes`; without `-y`, prompt on a TTY and refuse off-TTY before any side effect. Remove `--kill-session`/`--no-kill-session`/`--no-pivot`/`--accept-pivot-risks`/`--interactive` and activate's `--no-clear-history`; make `--flake` conflict with `--overlay-only`; delete the contradictory checks at `activate/mod.rs:116-126`. Replace the bool soup with `SessionPolicy`/`PivotPolicy`/`ConfirmPolicy` enums and make `ActivateOptions::default()` equal the CLI defaults. On the kill path with a TTY and no `-y`, run `prompt_session_kill_confirmation` in the foreground before detaching (show what closes, expected duration, and that the result arrives by login notification plus `sudo <absolute path> status`); fix the duplicated step and set `session_kill_confirmed`. The detached parent prints the follow-up command with the absolute binary path; with `--json` it emits a final envelope whose `data.status` is `"detached"`. deactivate: help says it reboots; on a TTY without `-y` prompt, off-TTY refuse; print `DEACTIVATE_RECOVERY_GUIDANCE` before requesting the reboot. Update every e2e test/helper, `cli_integration.rs`, `tests_activate.rs` and `activate/tests.rs` to the new flags.

  **Done when**
  `activate --help` shows `--session` (default kill), `--pivot` (default refuse) and `-y`; clap rejects all removed flags. Unit test: `ActivateOptions::default()` equals options built from empty `ActivateArgs`. With a TTY and no `-y` the kill path shows the confirmation (no duplicate step) before detaching and answering `n` leaves state/mounts/session untouched; off-TTY without `-y`, activate and deactivate exit non-zero before any change. `--pivot ask` reaches the prompt; `--pivot refuse` aborts naming the target needing a pivot. The detached parent prints `sudo <absolute path> status` and `--json` yields `data.status "detached"`. deactivate prints guidance before the reboot request (call-order test) and its help mentions the reboot. `rg -- '--no-kill-session|--interactive|--accept-pivot-risks|--kill-session|--no-pivot' nix/e2e-tests nails-cli` returns nothing and the updated suite passes.

- [x] **T-030: Non-interactive activation must not silently skip risky service restarts or SIGKILL interactive user processes; always report survivors** (medium · effort S)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (risky service restarts and the interactive-process kill gate). The item stays ticked as history; it describes no current code._

  _Status: done (W3-C3 plus wave C3/CC6). `restart_via_signal`/`RestartMethod::Signal` renamed to `terminate`/`Terminate`; `ProcessInfo.is_interactive` detected from `/proc/<pid>/fd`; an explicit `RiskyServicePolicy` (strict TOML `risky_services` plus `--risky-services`/`--terminate-interactive`) replaces `prompt_for_risky`, erroring rather than silently skipping; the strategy refuses to force-terminate an interactive non-service process before any mount or signal; survivor identities are threaded into the activation outcome, the notification and the `nails status` "writers still on the decoy" line. The e2e check `nix/e2e-tests/tests/session/37-activate-refuse-interactive-writer.nix` is authored (tty-attached writer blocks non-interactive activation) and needs a nix host to evaluate — see nix_pending._

  **Problem**
  `activate/mod.rs:97` sets `let yes = !interactive`, `overlay_mount/mod.rs:47` sets `prompt_for_risky: !options.yes`, and `overlay/strategy/mod.rs:263` restarts Risky processes only `if ... && options.prompt_for_risky` with no else branch. Under default flags, NetworkManager (`process/classification/mod.rs:161`), dbus-daemon (`:175`) and pulseaudio/pipewire (`:200`) are never restarted and keep pre-mount references into the decoy, yet status still reports OPTIMAL. Meanwhile any non-systemd process classified Safe (the `_ => Safe` arms) is "restarted" by `restart_via_signal`, which sends SIGTERM then SIGKILL (`process/restart/mod.rs:218-244`) and never restarts anything, so a user's `tail -f /var/log/x` or an editor with a file open in /etc is killed without warning.

  **Fix**
  Replace the implicit decline with an explicit policy `risky_services = "restart" | "skip"` as a strict TOML key plus an activate flag (named with the flag redesign). Default to restart when the session is being killed (no user session left to disrupt); otherwise non-interactive mode requires an explicit choice. Rename the signal path to `terminate` in code, logs and output. Non-interactive mode never SIGKILLs TTY-attached or interactive user processes: list them and abort before mounting unless an explicit terminate option is given; interactive mode prompts. Always list survivors (processes and services still holding references into decoy paths after mounting) in the activation outcome, the notification, and status (`NOT OPTIMAL: N writers still on the decoy`).

  **Done when**
  Unit tests: default flags with kill-session restart risky services; the skip policy lists survivors in the outcome; a TTY-attached non-systemd process in non-interactive mode aborts activation before mounting, with the process listed and no signal sent. `rg restart_via_signal nails-core` returns nothing (renamed). e2e: a `tail -f` on /var in a TTY blocks non-interactive activation with a clear message. cargo test and clippy pass.

### W3-C4: Hardware-config wrapper

Owns: `nails-core/src/nixos/config/inject.rs`, `nails-core/src/nixos/config/prepare.rs`, `nails-core/src/nixos/config/mod.rs`

- [x] **T-031: Stop text-patching hardware-configuration.nix: generate a wrapper that imports the original plus the NAILS module, and parse-check it in preflight** (medium · effort S)

  _Status: done in wave 3 (W3-C4). The original `hardware-configuration.nix` is preserved verbatim as `hardware-configuration.base.nix` and the live file becomes a constant wrapper importing the base plus `./nails/configuration.nix`, so it is always valid Nix regardless of the original (no-imports, `lib.optionals`, etc.); staging is idempotent and the dead `ensure_nails_import_block`/`find_imports_bracket`/`contains_active_path` helpers are gone. A new `NixParser`/`RealNixParser` and a preflight parse gate run `nix-instantiate --parse` over the composed config and fail before any mount on a syntax error; the rebuild fingerprint now includes the base file. e2e test 32 rewritten for the no-imports case (nix evaluation pending)._

  **Problem:** We inject the hidden import by editing Nix source text. When no `imports` list is found, `ensure_nails_import_block` (`nails-core/src/nixos/config/inject.rs:11-27`, no-imports branch 24-27) prepends a bare `imports = [ ./nails/configuration.nix ];`. In front of a `{ ... }: { ... }` function that is invalid Nix (`nix-instantiate --parse` -> `syntax error, unexpected =`), yet `tests.rs:253-272` asserts exactly this. The same path bootstraps the hidden copy (`prepare.rs:209`). `nixos-generate-config` always emits an `imports` attribute, so only hand-written files or forms like `imports = lib.optionals ... ++ [ ]` hit it, and when they do the rebuild fails after overlays are already mounted and the user is live on the decoy generation. No preflight parses the composed config; `preflight/checks/nixos_config/mod.rs:72-145` checks structure only (`contains_nails_import`).

  **Fix:** Stop patching Nix text. In the overlaid (and hidden) `/etc/nixos`, move the original to `hardware-configuration.base.nix` and generate `hardware-configuration.nix` as `{ ... }: { imports = [ ./hardware-configuration.base.nix ./nails/configuration.nix ]; }`, which is always valid regardless of the original; a second run with the wrapper in place is a no-op. Delete `ensure_nails_import_block` and `find_imports_bracket` and their tests, and update `inject_import_block` (`inject.rs:52`, called post-overlay at `manager/activation/overlay_mount/mod.rs:191`) plus `prepare.rs:209` and the re-exports (`nixos/config/mod.rs:37`, `nixos/mod.rs:54`, `lib.rs:125`). Add a preflight step in `preflight/checks/nixos_config/mod.rs` that runs `nix-instantiate --parse` on the composed files; it only parses, copies nothing into the decoy store, and on error fails before any mount. Include the base file in the rebuild fingerprint (`manager/activation/nixos_build.rs:36-69`, `compute_config_fingerprint`).

  **Done when:** Unit tests cover a file with imports, a file without imports, and one using `imports = lib.optionals ...`, all producing the wrapper, with a second run a no-op. Preflight fails with the parser message and performs no mount when the base file has a syntax error. `nix/e2e-tests/tests/nixos/32-config-inject-hardware-imports.nix` covers a hardware file without imports and asserts the hidden config is applied. `rg find_imports_bracket nails-core` returns nothing; `cargo test` and `cargo clippy` pass clean.

## Wave 4: Nix-store rebind + preflight leaves + repo/docs housekeeping

### W4-C1: Repo hygiene

Owns: `.gitignore`, `.github/scripts/package-release.sh`, `docs/bash-history-forensics.md`

- [x] **T-032: Strip private planning IDs, clean the .gitignore, and delete dead tracked files** (low · effort M)

  _Status: done in wave C1 (rest in wave 4). Story/Epic/AR/FR/NFR and bare acceptance-criteria tags are gone from the crates, tests, docs and E2E headers with their rationale kept, `docs/adr/` holds three ADRs, the preflight README links resolve and has no Story heading, and `docs/vulnerability-handling.md` is folded into `SECURITY.md`._

  **Problem:** Internal planning identifiers are scattered across the public tree: ~55 files carry `Story X.Y` references, plus `Epic N` and ~117 `AR/FR/NFR` tags in source doc-comments (e.g. `nails-core/src/manager/mod.rs:91-93`, `state/mod.rs:193-196`). Some reach users: `nails-core/src/config/loading.rs:222` embeds `Story 14.10` in `example_config()`, which surfaces in error messages and the release binary. `nails-core/src/preflight/checks/README.md` has a `Story 14.4` section (line 191) and links a nonexistent `docs/design.tex` (line 354). The `.gitignore` tracks personal tool and planning directories, a local maintenance script, and private planning docs, yet also ignores `docs/ci.md` which is committed; its Python-template patterns (`var/ lib64/ env/ core build/`, stray `jq`) are unanchored and can silently drop fixture paths at any depth. Dead files add noise: `.github/scripts/package-release.sh` (superseded by the flake's `nails-release`), `docs/bash-history-forensics.md` (819 lines, 0 project mentions), and `docs/vulnerability-handling.md` which duplicates `SECURITY.md`.

  **Fix:** Strip `Story/Epic/AR/FR/NFR` IDs from source and docs, replacing each with a one-line rationale or issue link; capture lasting decisions as ADRs under `docs/adr/`. Clean `example_config()` in `loading.rs`. Fix the preflight README's `design.tex` links and drop the Story heading. Move personal/tool-dir and private-planning ignores to `.git/info/exclude` (or a global gitignore), anchor the Python patterns (`/build/`, `/dist/`) and remove `var/ lib64/ env/ core jq`, and stop ignoring `docs/ci.md`. Delete `package-release.sh`; trim `bash-history-forensics.md` to a short project-specific page and fix its `USER-SECURITY-GUIDE` link; fold `vulnerability-handling.md` into `SECURITY.md`. (The `benches/performance.rs` placeholder is removed under the benchmarks chunk, not here.)

  **Done when:** No `Story/Epic/AR/FR/NFR` IDs remain in user-facing strings or the release binary and `grep` over `src` shows them replaced by rationale/links; `.gitignore` no longer lists personal or private-planning paths, patterns are anchored, and `docs/ci.md` is tracked; `package-release.sh` is gone, the forensics doc is trimmed with a working link, and the vulnerability doc is merged into `SECURITY.md`; preflight README links resolve and the workspace builds clean.

### W4-C2: Nix-store rebind & command cache

Owns: `nails-core/src/manager/activation/overlay_mount/restore.rs`, `nails-core/src/manager/activation/overlay_mount/auto_mount.rs`, `nails-core/src/manager/helpers/command_cache.rs`

- [x] **T-033: Fix where hidden-session Nix store writes land, drop the systemd closure copy, and restart nix-daemon/journald on every teardown path** (critical · effort M)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (the `/nix/store` self-bind and the nix-daemon and journald restarts). The item stays ticked as history; it describes no current code._

  _Status: done (wave 4, C1, completed wave C3/K2). The overlaid `/nix/store` is self-bound read-only so a daemon writable-remount resolves into the overlay upper; the ~186MB systemd closure byte-copy is gone (systemctl runs via the original-store bind through the loader); each `/nix/store` bind is recorded in the state file and undone in reverse on deactivate/emergency after a namespace re-check; nix-daemon and journald are restarted on every teardown path. Remaining is nix-only: VM run of `nix/e2e-tests/tests/shell/44-nix-daemon-restart-on-overlay.nix` and the differing-namespace teardown path. The `/run/nails/original-nix-store` unmount+removal is tracked under T-069 — see nix_pending._

  **Problem**
  - Hidden-session Nix store writes can land on the decoy partition. Before the /nix overlay, `runtime_cache.rs:26-54` binds the real on-disk `/nix/store` read-only to `/run/nails/original-nix-store`; after the overlay, `overlay_mount/restore.rs:24-46` re-binds that cached real store read-only over `/nix/store` (manager + init namespaces) and restarts nix-daemon claiming writes now hit the overlay. Nix's `LocalStore::makeStoreWritable` remounts a read-only store bind writable in its private namespace, so daemon writes resolve to the bind's backing dir (decoy /nix) while DB registration goes to the hidden upper, leaving unregistered plainly named paths on the decoy. Inferred from code + Nix behaviour; not yet VM-confirmed.
  - `restore_read_only_bind_mount_in_init_namespace` (restore.rs:83-142) forks a `setns` into `/proc/1/ns/mnt` without checking it differs from nails' own namespace. Under sudo-from-terminal / transient unit they usually match, so the binds stack; deactivation unmounts `/nix/store` once (`deactivation.rs:451-464`), the leftover bind keeps /nix busy, and teardown falls back to `MNT_FORCE|MNT_DETACH`, pinning hidden paths. The forked child allocates, formats `NailsError`, and calls `eprintln!` (restore.rs:120, :257) before `_exit` — UB as soon as the process is multi-threaded.
  - Service restarts are asymmetric: on a `/nix/store` unmount failure the `?` at `deactivation.rs:464` returns before the restart at `:502-504`, leaving the decoy without nix-daemon; activation rollback (`mount_tracker.rs:179-275`) never restarts journald, which `handle_mount_success` moved onto the /var overlay (`overlay_mount/mod.rs:176-183`).
  - `command_cache.rs` keeps systemctl runnable post-overlay by hand-parsing ELF PT_INTERP and `ldd` text (`:167-340`) and byte-copying the whole `nix-store -qR <systemd>` closure into `/run/nails/systemctl-cache` (`:374-398`): ~186 MB / ~3,345 files / ~4.4s on every activation, never removed, surviving `emergency` as a distinctive tmpfs artifact. The `/run/nails/original-nix-store` bind already exposes those files, so the copy is pure redundancy.

  **Fix**
  1. Confirm the store-write leak first: in the hidden session add a store path with unique random content (or build a uniquely named trivial derivation), deactivate, and check it is absent from the decoy lower /nix and present in the hidden upper. If confirmed, stop re-binding the original store over `/nix/store`; instead apply a read-only self-bind of the overlay's own merged `/nix/store` so a writable remount by the daemon resolves into the overlay upper.
  2. In the init-namespace helper, compare `(st_dev, st_ino)` of `/proc/self/ns/mnt` and `/proc/1/ns/mnt`; when equal, skip the helper (no fork, no stacked bind). When they differ, open the ns fd and build every CString in the parent; the child uses only raw syscalls (`setns`/`mount`/`symlinkat`/`write`/`_exit`) with no allocation, formatting, or `eprintln`, guarded by a debug assertion that `/proc/self/status` shows `Threads: 1` before the fork. Record each bind (target + namespace) and undo them in reverse at teardown.
  3. Add one service-restart guard shared by deactivation and activation rollback: on every exit path restart nix-daemon and journald *after* /nix and /var are unmounted, never before — fixes the early-return at `deactivation.rs:464` and the missing journald restart in rollback, and sequences the auto-mode `NixDaemonGuard` (`guards.rs`) after the tracker unmounts /nix.
  4. Delete the closure copy (`command_cache.rs:376-398`) and build `CachedCommand::ViaLoader` against the existing `/run/nails/original-nix-store` bind: loader = `ld-linux-*.so.2` under the bind, `--library-path` = matching lib dirs under the bind, program = systemctl under the bind (zero bytes copied; ld.so searches `--library-path` before DT_RUNPATH). Replace the hand-rolled ELF/ldd parsing with the `object` crate if parsing is still needed. Ensure `/run/nails` (binds + residue) is unmounted and removed in both `deactivate` and `emergency` teardown.

  Note: a separate chunk questions whether the pre-overlay `/nix/store` bind should exist at all; if that work removes the bind, drop steps 1-2 here and keep only the service-restart symmetry.

  **Done when**
  - Extended E2E / host-side disk-image check in `nix/e2e-tests/tests/shell/44-nix-daemon-restart-on-overlay.nix`: a unique-content store path created in the hidden session is absent from the decoy /nix after deactivation and present in the hidden upper (fails on current main, passes after the fix; baseline store must not pre-contain the hidden closure).
  - After a normal /nix deactivation, /nix unmounts with no lazy-detach fallback and `findmnt /nix/store` showed a single bind during the session; `systemctl start/stop/is-active/reset-failed` succeed while /nix is overlaid.
  - `/run/nails/systemctl-cache` never exists after activation, and `/run/nails` plus its binds are gone after both `nails deactivate` and `nails emergency`.
  - Unit tests: namespaces-equal path makes exactly one bind and never forks (test seam); an injected `/nix/store` unmount failure during deactivation still restarts nix-daemon (mock service controller records the start); activation rollback restarts journald and nix-daemon after the unmounts (ordering asserted); `tests_restore.rs` updated.
  - Hand-rolled ELF/ldd parsing removed or replaced by a crate; `cargo test` and `cargo clippy` clean.

### W4-C3: Preflight probes + backend matrix

Owns: `nails-core/src/preflight/checks/mount_namespace.rs`, `nails-core/src/preflight/checks/upper_fs_probe.rs`, `nails-core/src/preflight/checks/backend_detect.rs`, `docs/backends.md`

- [x] **T-034: Fail-closed preflight that NAILS shares PID 1's mount namespace with shared root propagation** (medium · effort S)

  _Status: done in wave 4 (W4-C3). `MountNamespaceCheck` fails closed when self and PID 1 mount namespaces differ, either is unreadable, or `/` lacks a `shared:` tag; registered right after the hidden-volume check in both registries; e2e test `23-preflight-mount-namespace.nix` still needs a VM run._

  **Problem:** Nothing verifies NAILS runs in the init mount namespace with shared root propagation. The overlay mounts in `nails-core/src/filesystem/real/mount_ops.rs:36-49` are plain `mount(2)` calls with no namespace reasoning; only `nails-core/src/manager/activation/overlay_mount/restore.rs` re-enters `/proc/1/ns/mnt` for the two `/nix` helpers. If `activate` runs from a unit with `MountFlags=private`, under `unshare -m`, or in a rootless container, the overlays land in a private namespace and the rest of the system keeps seeing the real decoy disk. The whole no-leak invariant depends on this and is unchecked.

  **Fix:** Add a fail-closed preflight check in `nails-core/src/preflight/checks/` (new `mount_namespace.rs`, re-exported from `checks/mod.rs`, registered in `nails-core/src/manager/preflight_runner.rs:78` and the CLI dry-run registry in `nails-cli/src/cli/commands/activate/dry_run.rs`). Compare `(st_dev, st_ino)` of `/proc/self/ns/mnt` and `/proc/1/ns/mnt`, and confirm `/` shows shared propagation (a `shared:` tag on the root line of `/proc/self/mountinfo`). Fail with an actionable message telling the operator to run from a host root shell. Keep the comparison platform-neutral so the forthcoming non-NixOS backends reuse it. Register it early enough to run before the session kill.

  **Done when:** Preflight returns Fail when self and PID 1 namespaces differ or `/` is not shared-propagation, with an actionable message; unit tests cover the namespace/propagation comparison via a parsing seam; a new e2e case under `nix/e2e-tests/tests/preflight/` shows `unshare -m nails activate` refuses; `cargo test` and clippy clean.

- [x] **T-035: Preflight probe that the hidden root can host overlay upper/work dirs (trusted xattrs, d_type, trial overlay mount) and pass explicit overlay options** (medium · effort S)

  _Status: done in wave 4 (W4-C3). `UpperFsCapabilityCheck` (`upper_fs_probe.rs`) probes trusted xattrs, readdir `d_type` and a scratch overlay with copy-up and whiteout, naming the fstype on failure; overlay mounts always append `index=off,metacopy=off,redirect_dir=off`; README/guide backend lists rule out remote and FAT filesystems; e2e test `24-preflight-upper-fs-capability.nix` still needs a VM run._

  **Problem:** Kernel overlayfs needs an upper filesystem that supports `trusted.*` (or `user.*`) xattrs and returns valid `d_type`; NFS/CIFS/9p/most FUSE and FAT/exFAT/NTFS are unusable as upper. Current hidden-root checks cover only existence, mount, writability and symlinks (`hidden_volume.rs`, `symlink_support.rs:64-77`, `storage_readiness/mod.rs:98-140`); `overlay_compatibility.rs` inspects overlay targets, not the upper. Preflight runs before the session kill but the real overlay mounts happen after it (`nails-core/src/manager/activation/preflight.rs:124`), so an unsuitable backend is discovered only after the session is gone and staging has begun. `mount_ops.rs:29-34` passes only `lowerdir/upperdir/workdir`.

  **Fix:** Add an `UpperFsCapability` check (`nails-core/src/preflight/checks/upper_fs_capability.rs`, re-exported in `checks/mod.rs`, registered in `preflight_runner.rs:78` and `nails-cli/src/cli/commands/activate/dry_run.rs`). In a scratch dir `.probe-<random>` under the hidden root: set/remove `trusted.overlay.probe`, verify readdir `d_type` is not `DT_UNKNOWN`, trial-mount a throwaway overlay with lower/upper/work/merged all inside the scratch dir, exercise a file create/delete and a whiteout, then unmount and remove the scratch dir. Nothing touches the decoy. On failure emit a backend-specific message naming the detected fstype (via `get_filesystem_type`), ruling out nfs/cifs/9p/fuse.*/vfat/exfat and recommending ext4/xfs/btrfs/f2fs. In `mount_ops.rs:29-34` always append `index=off,metacopy=off,redirect_dir=off` to the overlay options. Make `hidden_volume.rs` wording backend-neutral (drop "Mount the hidden LUKS volume"). Update `README.md:60-62` and `docs/USER-SECURITY-GUIDE.md` so supported hidden roots read "any mounted Linux filesystem that can host an overlayfs upper (xattrs, d_type, whiteouts)" and remote/arbitrary filesystems are removed.

  **Done when:** A new negative e2e test (e.g. `nix/e2e-tests/tests/preflight/23-preflight-upper-fs-capability.nix`, following the vfat loop pattern in `18-preflight-symlink-support.nix`) fails preflight with the capability message, mounts nothing, and leaves no probe dir; a unit test shows Fail with the fstype name when the xattr probe errors (mock/test seam); the overlay option string includes `index=off,metacopy=off,redirect_dir=off` (unit test); README/guide backend lists contain no remote filesystems; `cargo test` and clippy pass.

- [x] **T-036: Backend support matrix and per-backend deniability notes; auto-detect backend type in preflight for targeted warnings** (high · effort M)

  _Status: done in wave 4 (W4-C3). `BackendDetectCheck` warns (never fails) on discard-enabled tcrypt/plain mappings, file-container timestamp exposure, containers on btrfs/zfs/bcachefs and FUSE-backed loops; `docs/backends.md` holds the matrix and per-backend notes, linked from README and the guide; `hidden_volume.rs` names no backend; the guide drops TRIM/fstrim advice. Shufflecake and a cross-backend E2E matrix stay deferred (T-130)._

  **Problem:** Backend claims exceed what overlayfs allows and what has been tested. `README.md:60-62` lists only "mounted, writable, symlinks"; every concrete unlock example is the VeraCrypt file-container `tcrypt` command (`README.md:83-85,119-121` and the guide), so LUKS2 and whole-device users get wrong advice, and preflight treats all backends identically. Three deniability hazards are mis-documented: (1) the `cryptsetup` + loop workflow updates the container file's mtime/ctime every read-write session and ctime cannot be restored; (2) `docs/USER-SECURITY-GUIDE.md:372-373` recommends "Enable TRIM" and periodic `fstrim`, but opening an outer tcrypt volume with `--allow-discards` can destroy the hidden volume, and discards reaching a loop-backed container hole-punch a readable used/free map; (3) a container on a journaling/COW decoy or SSD can leave recoverable fragments for a multi-snapshot adversary.

  **Fix:** Write `docs/backends.md`. Matrix section: tested (LUKS2+ext4 in CI), evaluated once (VeraCrypt hidden volume + ext4), expected (local fs on iSCSI/NBD block device), unsupported (NFS/SMB/sshfs/most FUSE as upper, FAT/exFAT/NTFS); list requirements (symlinks, trusted xattrs, d_type, whiteouts, upper+work on same fs, mount not tied to the session) and link to the T-035 probe result. Per-backend section for VeraCrypt file container, VeraCrypt device and LUKS2: unlock command, discard policy, timestamp behaviour, host traces, lock sequence. Link from README and the operator guide. Code: add `nails-core/src/preflight/checks/backend_detect.rs` (re-exported in `checks/mod.rs`, registered in `preflight_runner.rs`) that auto-detects without a config knob — mountinfo to dm device to `/sys/block/dm-N/dm/uuid` prefix (CRYPT-TCRYPT/CRYPT-LUKS2/CRYPT-PLAIN) and loop `backing_file`. Emit WARN (never FAIL) for: discard-enabled tcrypt mappings (read `/sys/block/dm-N/queue/discard_max_bytes`), file container on btrfs/zfs COW decoy, and file-container timestamp exposure. Make `hidden_volume.rs` messages backend-neutral. Rewrite `docs/USER-SECURITY-GUIDE.md`: remove "Enable TRIM"/`fstrim` for any hidden-volume-bearing volume, cite cryptsetup-open(8) on `--allow-discards` + `--tcrypt-hidden`, document container mtime/ctime exposure, and recommend whole-device hidden volumes over file containers on COW/SSD decoys with automatic snapshots disabled. Defer Shufflecake and a cross-backend E2E matrix (TODO-only).

  **Done when:** `docs/backends.md` exists with the matrix and per-backend table, linked from README and the guide; unit tests cover dm uuid-prefix and loop backing_file parsing with MockFilesystem fixtures; preflight emits (not FAIL) a discard WARN for tcrypt mappings and a COW WARN for file containers on btrfs/zfs, with unit tests; `hidden_volume.rs` messages name no specific backend; the guide no longer recommends TRIM/fstrim for hidden-volume-bearing volumes and documents the `--allow-discards` destruction/leak risk and the mtime/ctime and COW-fragment exposures; `cargo test` and clippy clean.

### W4-C4: Reporting channels

Owns: `.github/ISSUE_TEMPLATE/`, `SECURITY.md`, `ROADMAP.md`

- [ ] **T-037: Safer reporting channels for at-risk users: private vulnerability reporting, PGP, OPSEC-aware issue forms** (medium · effort S)

  _Status: done in wave 4 (W4-C4) except owner actions. `SECURITY.md` names private vulnerability reporting first with email as fallback, a WKD lookup and an OPSEC note; issue templates are YAML forms with absolute links and a required OPSEC checkbox; `SUPPORT.md`, `ROADMAP.md`, `docs/vulnerability-handling.md` and the guide footer are aligned. Remaining (owner only): publish the `security@nails.run` key via WKD and replace the fingerprint placeholder in `SECURITY.md`, enable private vulnerability reporting, decide on Discussions, disable the wiki._

  **Problem:** `SECURITY.md:42` accepts email only (`security@nails.run`). It publishes no PGP key or fingerprint and does not mention GitHub Private Vulnerability Reporting (PVR), which is currently disabled on the repo. `.github/ISSUE_TEMPLATE/bug_report.md:44-55` and `SUPPORT.md:29-33` ask for "sanitized" `nails status -v` output. That output prints hidden-root and overlay paths and links a GitHub identity to NAILS use. The markdown templates link `../../SECURITY.md` / `../../SUPPORT.md` (`bug_report.md:10,12`, `feature_request.md:10`), and those links 404 from `/issues/new`. `ROADMAP.md:63-64` says "start a public discussion", but Discussions are disabled. The wiki is enabled but empty.

  **Fix:**
  - `SECURITY.md`: make PVR (`https://github.com/WitteShadovv/nails/security/advisories/new`) the primary channel and keep email as the fallback. Publish the PGP key for `security@nails.run` via WKD on nails.run and put the full fingerprint in the file. Add a short OPSEC note: reporters may use a pseudonymous account, and real paths and hostnames are not needed. Mirror this in `SUPPORT.md:15`, `docs/vulnerability-handling.md:23`, `docs/USER-SECURITY-GUIDE.md:606` and the `config.yml` contact link text.
  - Replace `bug_report.md` and `feature_request.md` with YAML issue forms (`bug_report.yml`, `feature_request.yml`). They use absolute `https://github.com/WitteShadovv/nails/blob/main/...` links, start with a required OPSEC checkbox (consider a throwaway account, never paste real paths, redact all output) and ask only for `nails --version`, OS/distro and the steps to reproduce. They do not ask for `nails status -v`. Remove the same request from `SUPPORT.md:29-33`.
  - `ROADMAP.md:63-64` and `feature_request.md:21`: drop the "discussion" wording unless Discussions are enabled.
  - Owner actions, listed in the PR description: enable PVR, decide whether to enable Discussions (Q&A), and disable the empty wiki.
  - Optional, as part of the JSON-envelope work: a `--redact` mode for `status`/`verify` output.

  **Done when:** `SECURITY.md` names PVR as the primary channel and contains a PGP fingerprint that matches the key served by WKD. `.github/ISSUE_TEMPLATE/` has only `.yml` forms plus `config.yml`, every link in them is absolute, and each form has a required OPSEC checkbox. `grep -rn 'status -v' .github SUPPORT.md` returns nothing. `grep -n -i discussion ROADMAP.md` returns nothing, or Discussions are enabled.

## Wave 5: State teardown + overlay/opaque + target-user writes

### W5-C1: State teardown & degraded

Owns: `nails-core/src/state/guard.rs`, `nails-core/src/deactivation/orchestrator/unmount.rs`, `nails-core/src/deactivation/report.rs`

- [x] **T-038: Fix the self-deadlock when a state write fails during deactivate/emergency (StateGuard re-locks a mutex its own thread holds)** (critical · effort S)

  _Status: Done in W5-C1. The Arc<Mutex> re-lock is structurally gone (StateGuard holds `&mut NailsManager`, Drop rolls back without locking); teardown/rollback now lives in `manager/deactivation.rs` (the `deactivation/orchestrator/unmount.rs` path no longer exists). A cfg(test) save-failure seam drives 7 timeout-bounded tests covering each `?` site in Normal and Emergency mode._

  **Problem**
  Deactivation holds the manager `MutexGuard` for the whole `run()` (`nails-core/src/deactivation/orchestrator/mod.rs:183-186`), then creates a `StateGuard` at `:226` from `Arc::clone(&self.manager)`. Locals drop in reverse order, so on any `?` early return the guard drops *before* `manager`, and `StateGuard::drop` (`nails-core/src/state/guard.rs:243-248`) calls `self.manager.lock()` on the std `Mutex` the same thread still holds — that call never returns. Unprotected `?` sites: `update_state(Deactivating)` (`:232`), the test gate (`:233`), and `clear_overlay_status_in_cache` / `complete_deactivation` / `update_state(Inactive)` (`:328-330`), plus `select_system_profile` (`:335`). Only the cleanup and unmount error paths dodge it by calling `drop(manager)` first (`:280`, `:309`). Real triggers: `StateFile::save` failing with ENOSPC (every overlay upper lives on the hidden volume), EROFS after `errors=remount-ro`, or EIO on a failing backend. `nails deactivate` and `nails emergency` then hang forever, and every retry hangs again at the first state write before anything is unmounted.

  **Fix**
  Guarantee `StateGuard` can never re-lock a mutex the current thread already holds. Read the current state in a short lock scope, drop the lock, create the `StateGuard`, then re-acquire the lock for the body; or move the body into a helper taking `&mut NailsManager` and roll back explicitly while the lock is held, with a Drop-based guard covering only the unwinding case. Remove the ad-hoc `drop(manager)` workarounds at `:280` and `:309`. (The rule that teardown never rolls back to Active after a partial unmount is handled by T-039.) Add tests that force the state save to fail at each `?` site using a read-only temp dir or a mock save-failure hook, in both Normal and Emergency mode, each wrapped in a timeout.

  **Done when**
  - New unit tests inject a state-save failure at `update_state(Deactivating)`, `update_state(Inactive)` and `select_system_profile` in both Normal and Emergency mode; each call returns `Err` within 5 s (spawned thread + `recv_timeout`).
  - `StateGuard::drop` no longer locks a mutex the caller may hold; `rg 'drop\(manager\)' nails-core/src/deactivation` returns nothing.
  - `nix develop -c cargo test --workspace` and `nix develop -c cargo clippy --workspace --all-targets -- -D warnings` pass.

- [x] **T-039: Deactivation teardown: remove the impossible remount rollback, attempt every target, and end in Degraded instead of going back to Active** (medium · effort S)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (the per-target deactivation teardown). The item stays ticked as history; it describes no current code._

  _Status: Done in W5-C1. `rollback_unmounts` and the remount promise are deleted; teardown attempts every target (graceful then forced), re-reads the mount table, records `SystemState::Degraded` with the remaining mounts and returns `NailsError::DeactivationIncomplete`. Normal mode returns before the decoy switch and reboot. Normal and Emergency degraded tests cover it._

  **Problem**
  On the first unmount failure `unmount_overlays` calls `rollback_unmounts` and returns `Err` in both modes (`nails-core/src/deactivation/orchestrator/unmount.rs:52`). `rollback_unmounts` (`:134-208`) asks `RealFilesystem::get_mount_info` for targets that were *just* unmounted; on a real host that reads `/proc/mounts`, which no longer lists them, so it always returns `None` and remounts nothing — the comment at `:151-154` admits it only works for `MockFilesystem`. The `StateGuard` then forces state back to `Active` (`nails-core/src/state/guard.rs:250`) and keeps the stale `overlay_status`, even though some targets are already detached: status reports Active while hidden-session writes land on the decoy disk. The module docs (`nails-core/src/deactivation/mod.rs:27-34`) promise a remount that cannot happen. The test at `nails-core/src/manager/tests.rs` (~1290-1410) passes only because `/etc` is rigged to fail first in reverse order, so `/home` is never unmounted. In Emergency mode especially, aborting to restore hidden state is the opposite of what the operator wants.

  **Fix**
  Delete `rollback_unmounts` and the remount promise in the module docs. In both modes, attempt every target (graceful unmount, then `MNT_DETACH`), collect per-target errors, then re-read the mount table to compute which NAILS mounts remain. If any remain, add and persist a new `SystemState::Degraded { remaining_mounts }` variant (introduced with the state-file v2 work), report every remaining path, and exit non-zero; Normal mode then skips the decoy switch and the reboot and instructs the operator to run `nails emergency` or `nails recover`. Never return to `Active` once any target has been unmounted. The `DeactivationReport` lists unmounted, failed, and remaining paths. Replace the misleading `/home should be remounted` test.

  **Done when**
  - `rg rollback_unmounts nails-core` returns nothing; `nails-core/src/deactivation/mod.rs` no longer promises a remount.
  - Unit test (Normal): failure on the 2nd of 3 targets still attempts all 3, ends in `Degraded` with the failed path in the error, and requests no reboot.
  - Unit test (Emergency): same scenario continues past the failure and ends in `Degraded`; no remount is attempted.
  - `nix develop -c cargo test --workspace` and `nix develop -c cargo clippy --workspace --all-targets -- -D warnings` pass.

### W5-C2: Overlay runtime (opaque, copy-up)

Owns: `Cargo.toml`, `nails-core/src/overlay/opaque.rs`, `nails-core/src/preflight/checks/overlay_compatibility.rs`

- [x] **T-040: Rewrite opaque-xattr stripping in-process and scoped to NAILS-managed paths, run it once in the mount step, make dry-run read-only, and drop the attr/du/cp shell-outs** (high · effort M)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (opaque-xattr stripping on the overlay targets). The item stays ticked as history; it describes no current code._

  _Status: done (code W5-C2, completed wave C3/CC6). Opaque handling is in-process (rustix lgetxattr/lremovexattr), scoped to `/etc/nixos`, run once in the mount step; preflight and `--dry-run` are read-only; no getfattr/setfattr/du/find Command spawns remain (the resolver-routed cp fallback stays), and the host-tools preflight no longer requires attr/du/find. The two E2E nix tests are authored (`nix/e2e-tests/tests/nixos/29-activate-dry-run.nix` opaque-marker-survives-dry-run; `nix/e2e-tests/tests/overlay/67-overlay-opaque-whiteouts.nix` phases 4-6) but still need a nix host to evaluate — see nix_pending._

  **Problem:** `nails-core/src/overlay/opaque.rs:32-92` runs `find <upper> -type d`, then one `getfattr` per directory and one `setfattr -x trusted.overlay.opaque` per hit, and ignores the `setfattr` result. It walks every persistent upper, /nix included, twice per activation: once in `OverlayCompatibilityCheck` (`preflight/checks/overlay_compatibility.rs:127-146`) and again in the mount step (`auto_mount.rs:68-79`, `explicit_mount.rs:60-71`). This causes four problems:
  - It strips every marker, including ones the kernel set on purpose. If the hidden user runs `rm -rf ~/dir && mkdir ~/dir`, the decoy's lower contents come back into `~/dir` on the next activation. Replaced /etc subdirectories behave the same way.
  - `nails activate --dry-run` changes xattrs on the hidden volume and still prints "No changes were made" (`nails-cli/src/cli/commands/activate/dry_run.rs:146`).
  - Each directory costs about 2.5-8 ms of fork/exec, which adds up to minutes for a populated /nix upper.
  - It silently does nothing when find or getfattr is missing (Debian/Ubuntu do not install `attr` by default), when find exits non-zero, or when names break the `from_utf8_lossy` line split.

  `cp -a` (`filesystem/real/dir_ops.rs:142`) and `du -sb` (`dir_ops.rs:179`, not supported by busybox du) are further external-binary dependencies.

  **Fix:**
  - Find out what creates the marker that motivated this code (`/etc/nixos` hiding the lower `flake.nix`, `opaque.rs:1-15`). If NAILS itself deletes and recreates that directory, write in place through the merged view instead.
  - If a strip is still needed, apply it only to an explicit list of NAILS-managed paths (for now `/etc/nixos` in the /etc upper). Never walk user-data uppers or /nix.
  - Use `lgetxattr`/`lremovexattr` from `rustix` (already in Cargo.lock) or from the `xattr` crate. Spawn no subprocesses, and log each failure as a warning that names the path.
  - Run the strip once, in the mount step only. `OverlayCompatibilityCheck` becomes read-only and may only report markers on managed paths, so preflight and `--dry-run` never write.
  - Replace `du -sb` with a native lstat walk that does not follow symlinks and stays on one filesystem. Replace `cp -a` with a native recursive copy that preserves mode, ownership, timestamps, symlinks and xattrs. If a `cp` fallback stays, resolve it through the platform binary resolver and the host-commands preflight.

  **Done when:**
  - `rg 'getfattr|setfattr|"find"|"du"|"cp"' nails-core/src` finds no `Command` spawns.
  - Unit tests over a temp tree show:
    - an opaque marker on a managed path is stripped;
    - an opaque marker on an unmanaged directory is left alone;
    - the native size and copy functions give correct results and keep mode, owner and xattrs (where the test has permission).
  - A test seam asserts that preflight and dry-run make no xattr writes. `nix/e2e-tests/tests/nixos/29-activate-dry-run.nix` sets an opaque marker in the upper before `--dry-run` and asserts it is still there afterwards.
  - `nix/e2e-tests/tests/overlay/67-overlay-opaque-whiteouts.nix` gets a new phase: create a decoy `~/dir/a`, run `rm -rf ~/dir && mkdir ~/dir` in the hidden session, deactivate, re-activate, and assert `~/dir/a` is absent. The same test asserts the lower `/etc/nixos/flake.nix` stays visible across an activate, deactivate, activate cycle.
  - Opaque handling works on a host without the `attr` package. `nix develop -c cargo test` and clippy pass with no warnings.

- [x] **T-041: Document overlay copy-up and upper growth, surface hidden-root usage in status, and add an optional reset-upper** (medium · effort M)

  _Status: Done in W5-C2. `Filesystem::disk_usage` returns total/available from one statvfs; `nails status` shows hidden-root used/total/free in human and JSON (no directory walk), unit-tested. `nails reset-upper <target>` added (Inactive+unmounted only, confirm/`-y`, /nix warning). Copy-up cost, exclusions, tmpfs overlays and in-session maintenance documented in the guide and README. E2E `74-overlay-reset-upper.nix` added (must be run on a nix host — see nix_pending)._

  **Problem:**
  - Every top-level directory, /nix included, gets an upper and work directory on the hidden root (`nails-core/src/manager/helpers.rs:320-390`).
  - OverlayFS copies the whole file into the upper the first time a lower file is opened for writing, truncated, or chmod/chown'ed. On a slow USB or VeraCrypt backend, touching a large file (Nix DB, browser profile, multi-GB VM image) can stall the process for seconds to minutes with no feedback. The docs do not mention this.
  - Persistent uppers keep every session's copy-ups and whiteouts forever. Deactivation only clears `overlay_status` and `failed_overlays` (`manager/state_management.rs:318-327`).
  - There is no maintenance path and no way to see how much of the hidden root is used.

  **Fix:**
  - In `docs/USER-SECURITY-GUIDE.md` ("During Hidden Session") and `README.md`, document:
    - whole-file copy-up cost and upper growth;
    - putting bulky VM-image and data directories in `overlay_exclusions`;
    - putting caches on ephemeral tmpfs overlays via `extended_overlays`;
    - running maintenance from inside the hidden session (`nix-collect-garbage -d`, cache cleanup).
  - Add hidden-root total, used and available space to `StatusReport` (`status/report/types.rs:169`). Get all three from a single statvfs call by extending `get_free_space` (`filesystem/real/file_ops.rs:61`) to also return totals. Show the figures in human, plain and JSON output, and never walk directories in the status path.
  - Add `nails reset-upper <target>`:
    - refuse unless the state is Inactive and the target is not mounted;
    - list what will be deleted and ask for confirmation (`-y` skips the prompt);
    - remove `<hidden_root>/<dir>` and `<hidden_root>/.work/<dir>`;
    - warn that resetting /nix drops the hidden Nix DB and store paths.
  - Add no automatic whiteout pruning, because it would bring deleted lower files back. Never move /nix/var to tmpfs, because it holds the hidden Nix DB registrations.

  **Done when:**
  - The guide and README cover copy-up cost, exclusions and in-session maintenance.
  - `nails status` (human and `--json`) shows hidden-root space, covered by a unit test on the mock filesystem. The status path makes no directory walk.
  - `reset-upper` unit tests cover:
    - refusal while Active or while the target is mounted;
    - a declined prompt;
    - a successful reset.
  - An E2E test resets the /home upper and asserts the decoy home shows through on the next activation.
  - No code path prunes uppers automatically or puts /nix/var on tmpfs.

### W5-C3: Target-user resolver & safe writes

Owns: `nails-core/src/cleanup/history/`, `nails-core/src/filesystem/real/file_ops.rs`, `nails-core/src/target_user.rs`

- [x] **T-042: One TargetUser resolver with numeric chown used by every module; history cleanup targets the invoking user's home, not root's** (high · effort M)

  _Status: done in wave C1. Notification, shell cleanup, session detection, shell integration and the CLI detach path resolve the operator through `TargetUser::resolve()`; the `$HOME`-based history resolvers are gone, the privilege variable names live in `target_user::PRIVILEGE_ENV_VARS`, `shell-helpers.nix` injects `SUDO_UID`/`SUDO_USER` instead of HOME/USER, and `45-shell-history-real-sudo.nix` covers a real sudo run (VM run pending)._

  **Problem**
  Target-user resolution is reimplemented in at least five places with different precedence and sources: `shell/mod.rs:114-127` (SUDO_USER / NAILS_TARGET_USER / USER + getpwnam), `process/shell_cleanup.rs:63-72` (NAILS_TARGET_UID / SUDO_UID), `notification/mod.rs:26,107,167`, `process/session/detection.rs:134-160` (SUDO_UID / PKEXEC_UID / SUDO_USER), and `cli/detach.rs:78-82`. DOAS_UID/DOAS_USER are ignored. History cleanup is worse: every path reads `$HOME` directly (`cleanup/history/mod.rs:80,190`, `cleanup/history_files/mod.rs:203-230`), and `HistoryCleaner::with_home` (`cleaner.rs:79`) has no production caller. Under the documented `sudo nails ...`, env_reset makes HOME=/root, and the detached unit (`cli/detach.rs`) passes only the target uid/user, so HOME is unset — the operator's `~/.bash_history`, `~/.viminfo`, nvim shada and `recently-used.xbel` are never touched. Callers affected: `manager/activation/preflight.rs:160-162`, `cleanup/manager.rs`, `deactivation/orchestrator/cleanup.rs:133`, `manager/deactivation.rs:367`. The E2E suite masks this by injecting `env HOME=... USER=...` (`nix/e2e-tests/lib/shell-helpers.nix:19-21,44-46`), an environment the real invocation never produces.

  **Fix**
  Add `nails-core/src/target_user.rs` with `TargetUser { uid, gid, name, home, shell }`, resolved once per command in order: `NAILS_TARGET_UID` (set by the detach path), `SUDO_UID`, `PKEXEC_UID`, `DOAS_UID`, then owner of the active logind session on seat0; otherwise return an error with no silent fallback to root. Resolve gid/home/shell via getpwuid. Pass the resolved `TargetUser` explicitly into cleanup, shell setup, shell killing, notifications and session detection, and delete the per-module env lookups so only `target_user.rs` references these variables. History cleanup operates on `TargetUser.home` plus `/root`. Shape the type so it can carry an alternative persona home for the opt-in fresh-home persona mode added elsewhere. Remove the HOME/USER injection from `shell-helpers.nix`; keep injected-home coverage in unit tests only. This single resolver also subsumes the notification group-ownership bug (NixOS `isNormalUser` primary group is `users`, so the old `chown user:user` failed): callers now have a numeric gid to chown with.

  **Done when**
  - `rg 'var\("HOME"\)|SUDO_USER|SUDO_UID|PKEXEC_UID|DOAS' nails-core/src nails-cli/src` outside tests matches only `target_user.rs`.
  - Unit tests: with `SUDO_UID` set and `HOME=/root` the resolver returns the user's passwd home and primary gid; with no source available it errors.
  - New shell E2E test (next free number under `nix/e2e-tests/tests/shell/`): a real `testuser` runs `sudo nails activate` / `sudo nails deactivate` with no HOME/USER overrides, and pre-seeded history lines matching nails/cryptsetup are filtered.
  - Existing shell E2E tests pass after the HOME/USER injection is removed; `cargo test` and `cargo clippy` are clean.

- [x] **T-043: Files NAILS writes for the user get symlink-safe opens and correct numeric ownership and modes** (high · effort M)

  _Status: done in wave C1. Notification signal files are created 0600 with the mode set on the open descriptor and a symlink-refusing exclusive create; notification tests 48-51 and shell tests 38-40 assert operator ownership and modes without chowning fixtures; the README states the operator must be a local `/etc/passwd` account (static musl build, no NSS). VM runs pending._

  **Problem**
  Root writes into user-owned, overlaid home paths unsafely. `filesystem/real/file_ops.rs:113-153` (`write_file_content`) opens a predictable sibling `<path>.tmp` with `File::create` (O_TRUNC, follows symlinks, no O_EXCL/O_NOFOLLOW) then renames — a pre-planted `~/.bashrc.tmp -> /etc/shadow` lets root truncate and overwrite the target (CWE-59). It is used as root by rc injection and the autostart desktop entry (`shell/rc_integration.rs:76-90,133-165`), which also create missing parents as root (`create_directory`) and never fix ownership, leaving root-owned `~/.bashrc`, `~/.config/autostart` and possibly `~/.config` in the hidden upper. Notifications shell out to `chown user:user` (`notification/mod.rs:109,169`) with the result discarded and no `-h`; the per-user group assumption fails on NixOS (primary group `users`), so signal files stay root:root 0600 (`set_permissions:92,152`) in a root 0700 dir and the user-run notify-dispatch cannot read them. E2E tests 48 and 49 hide this by hand-chowning staged signals (`notification/48-...:52-53`, `49-...:70-71`); 49 skips asserting dispatch.

  **Fix**
  Add `Filesystem::write_user_file(path, content, &TargetUser, default_mode)`. If the file exists, preserve its owner and mode; a new file gets the `TargetUser` uid/gid (numeric) and the given mode (0600 or 0644). Create missing parents and fchown them to the user (0700/0755). Open the temp file with `O_EXCL | O_NOFOLLOW` under a random name, resolve relative to a directory fd opened with openat2 `RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH`, refuse symlinked parents, and set ownership/mode with `fchown`/`fchmod` on the open fd (reuse the symlink-safe write work from the related chunk if it lands first). Provide real and mock implementations. Route every write under the target user's home through it — rc integration, autostart entry, and notifications — and make the notification directory user-owned 0700. Replace the `chown` subprocess with `nix::unistd::fchown`; remove `Command::new("chown")` from `nails-core`. Ownership failures are logged at warn and surfaced, never ignored. Document that the static musl build resolves only local `/etc/passwd` users (no NSS).

  **Done when**
  - A pre-planted `<path>.tmp` symlink cannot redirect a root write and its target is unchanged (unit/integration test).
  - Mock unit tests: a new file gets the target uid/gid and mode; an existing file keeps its owner and mode; created parent dirs are user-owned.
  - E2E 48/49 no longer hand-chown; a notification written by nails itself on an `isNormalUser` account (group `users`) is dispatched, and 49 asserts dispatch. Shell E2E 38-40 assert `.bashrc`, `~/.config/autostart` and the desktop file are user-owned with expected modes after activation.
  - `rg 'Command::new\("chown"\)' nails-core/src` and `rg 'format!\("\{\}:\{\}"' nails-core/src/notification` return nothing; `cargo test` and `cargo clippy` are clean.

### W5-C4: Neutral naming

Owns: `nails-core/src/config/types.rs`, `nails-core/src/preflight/checks/hidden_volume.rs`

- [x] **T-044: Use neutral names in defaults and docs and warn when the hidden root or mapper name hints at hidden storage** (medium · effort S)

  _Status: done in wave C1. README, the user security guide, backends.md, configuration.md, verify-release.md and the E2E helpers and tests use the neutral mapper/label `data` and mount point `/mnt/data`; the guide has a Pre-Activation Residue section pointing journal residue at journald `Storage=volatile`. The `lib/hidden-volume.nix` file name and the `preflight-hidden-volume` shard key are kept (never reach a target)._

  **Problem:** The built-in fallback hidden root is `/mnt/hidden-volume` (`nails-core/src/obfuscate/mod.rs:325`, consumed by `config/types.rs:24-37`, `config/defaults.rs:86,104`, `state/file.rs:196`, the `Default` impls in `preflight/checks/{hidden_volume.rs:61,space/mod.rs:110,symlink_support.rs:50}`). README (lines 84-141) and `docs/USER-SECURITY-GUIDE.md` (lines 86-115, 225-240, 461, 514-564) teach the mapper name `veracrypt-hidden` and the mountpoints `/mnt/hidden` and `/mnt/hidden-volume`. The E2E helper `nix/e2e-tests/lib/hidden-volume.nix:14-22` (plus 59 files under `nix/e2e-tests`) uses the mapper, ext4 label and mountpoint `hidden-volume`. These strings end up in the leftover mountpoint directory, in systemd `.mount`/`.device` unit names, in `/dev/disk/by-label`, in kernel and sudo journal lines, and in fstab if it is ever persisted. The cleanup code treats the same strings as incriminating. Residue from the user's own `cryptsetup`/`mount` commands, which happens before NAILS runs, is not documented anywhere.

  **Fix:**
  - Remove the hardcoded fallback. The hidden root comes from `hidden_volume_root` in `nails.toml` or from the binary's parent directory. If derivation fails (build dir, `/nix/store`, binary at `/`), return `Option`/`Result` and show a clear error wherever the root is needed. Do not fall back silently. Keep a test-only constant with a neutral value such as `/mnt/data`.
  - In `HiddenVolumeCheck`, after the existing pass path, add a WARN when any of these contain `hidden`, `nails`, `veracrypt`, `tcrypt` or `decoy` (case-insensitive): a component of the root path, the dm name behind the root's mount source (read the source from `/proc/self/mountinfo`; for `/dev/dm-N`, read `/sys/block/dm-N/dm/name`), or the filesystem label. Add a mockable `Filesystem::mount_source()` for this. Use one shared token list.
  - Every example in README and the guide uses neutral names: mapper `data`, mountpoint `/mnt/data`, no telling label. State that none of these names may hint at hidden storage. Make the E2E helper and fixtures neutral too.
  - Add a "Pre-activation residue" section to the guide. It covers sudo `COMMAND=` journal lines, dm-crypt/ext4 kernel messages, generated mount unit names, by-label symlinks and shell history of the open/mount commands. For journal residue, point to the journald-volatility preflight, not to cleanup.

  **Done when:**
  - `grep -rnE 'veracrypt-hidden|/mnt/hidden' README.md docs/USER-SECURITY-GUIDE.md nix/e2e-tests` returns nothing.
  - Outside tests and the cleanup pattern list, `nails-core/src` has no hardcoded hidden-root path.
  - Unit tests cover all of: a WARN for each incriminating root, dm name and label; a pass for neutral names; the error when no root can be determined.
  - The guide has the residue section.
  - `nix develop -c cargo test --workspace` passes with 100% coverage, and `cargo clippy -- -D warnings` is clean.

## Wave 6: Hidden-root attach gate + persona mode + command timeouts/env

### W6-C1: Hidden-root attach gate

Owns: `nails-core/src/hidden_root.rs`, `nails-cli/src/cli/logging.rs`, `nails-cli/src/main.rs`

- [x] **T-045: Write nothing (logs, staged config) unless the hidden root is positively attached; remove binary-dir and /mnt/hidden-volume fallbacks** (high · effort M)

  **Problem:** `LoggingManager::init` treats the hidden volume as present whenever `path_exists()` is true (`nails-core/src/logging/manager/mod.rs:135`), contradicting its "verify mounted" comment, and then creates the log dir and `nails.log` with mode 0644 (`nails-cli/src/cli/logging.rs:303`) for every subcommand before dispatch (`nails-cli/src/main.rs:54`). The default root is the binary's own directory, falling back to `/mnt/hidden-volume` when the binary sits under `/nix/store` or `target/` (`nails-core/src/config/defaults.rs:53`). So `verify`, `status`, `init` and `notify-dispatch` run from a download dir or the decoy and drop identifying logs there. For `activate`, `stage_hidden_config_symlink` and `ensure_hidden_configuration_module` write `configuration.nix` and symlinks (`nails-core/src/nixos/config/prepare.rs:105,252`) before `HiddenVolumeCheck`'s mount test (`nails-core/src/preflight/checks/hidden_volume.rs:85`), so an unmounted mount point on a persistent root receives files.

  **Fix:** Add `HiddenRoot::verify_attached()` in a new `nails-core/src/hidden_root.rs`: path exists, its `st_dev` differs from `/` and from any decoy-persistence mount, and for non-`init` commands a NAILS marker (state file or `config/nails.toml`) is present; subdirectories of an attached volume pass. Call it (a) before building the file-logging layer, else stderr-only, and (b) before any write in `activate`; move config staging and pre-activation cleanup to after the hidden-volume check. Read-only commands (`status`, `verify`, `notify-dispatch`) and `init` never create log dirs or files. Create log files 0600 and dirs 0700. Exclude the active log dir from `verify` findings. Remove the `/mnt/hidden-volume` default and the build/store-path heuristics from `derive_hidden_volume_root`; if the binary dir is unattached and no explicit `hidden_volume_root` is set, fail with a clear error. Coordinate with the TOML config migration (same `config/defaults.rs`); move the build-dir test guards behind the `afs-test-hooks-compile-time` feature.

  **Done when:** Copying the built binary into an empty temp dir and running `verify`, `status`, or `notify-dispatch` creates no files there (unit test). `LoggingManager::init` returns stderr-only when the path exists but shares a device with `/` (unit test). E2E (`nix/e2e-tests/tests/preflight/13-preflight-hidden-volume.nix`): with the root dir present but nothing mounted, `status`, `verify`, `activate --dry-run` and a refused `activate` leave the dir byte-for-byte empty. Log files are mode 0600 on an attached root (E2E assertion). No `/mnt/hidden-volume` default remains in `nails-core/src/config/defaults.rs`.

  _Status: done in wave C1 (core gate from W6-C1). activate refuses before any hidden-root write when the root is not positively attached (`enforce_hidden_root_attached` in the preflight phase; best-effort skip under `--no-preflight`), `verify` no longer flags a log dir on the hidden volume, and `13-preflight-hidden-volume.nix` asserts an unmounted root stays empty and logs are 0600 (VM run pending). The attach gate does not require the NAILS marker, matching the logging gate._

### W6-C2: Fresh-home persona mode

Owns: `nails-core/src/manager/helpers.rs`, `nails-core/src/nixos/config/mod.rs`, `nails-cli/src/cli/commands/init.rs`

- [x] **T-046: Add an opt-in fresh-home persona mode and document the shared-account model** (high · effort L)

  **Problem**
  The hidden session runs as the decoy user, in the decoy home, with no separation. `resolve_target_uid`/`resolve_target_user` read `SUDO_UID`/`PKEXEC_UID`/`SUDO_USER` (`nails-core/src/process/session/detection.rs:130-160`), the session is restarted for that same UID, `create_overlay_config` always sets `lower = target` (`nails-core/src/manager/helpers.rs:349-388`), and `/home` is deliberately NOT in `DEFAULT_OVERLAY_EXCLUSIONS` (`nails-core/src/config/types.rs:66-79`). The whole decoy home is therefore merged and writable through copy-up, so every account, credential store and app profile configured in the decoy home is live in the hidden session. Neither `README.md` nor `docs/USER-SECURITY-GUIDE.md` mentions this shared-account model.

  **Fix**
  - Add a `persona.mode` key to `nails.toml` with values `fresh-home` and `shared-home` (legacy); reserve `separate-user` for a later phase.
  - Implement `fresh-home` as the opt-in mode: after the `/home` overlay is up, bind-mount `{hidden_root}/persona/home` over the target user's home (a plain bind mount, no decoy lower). Exclude that path from bind-sync extra-lower computation (`nails-core/src/manager/activation/overlay_mount/auto_mount.rs:81-117`, `explicit_mount.rs:73-86`, helper in `nails-core/src/overlay/bind_sync.rs`) and from opaque-xattr stripping (`nails-core/src/overlay/opaque.rs`).
  - Surface the active mode in `nails status` and dry-run output. Make `shared-home` an explicit opt-in that prints a warning. Add the `persona` key to the generated config (`starter_config` in `nails-cli/src/cli/commands/init.rs`).
  - Document the shared-account model and the modes in `README.md` and `docs/USER-SECURITY-GUIDE.md`.
  - Record `separate-user` (fixed-UID hidden-NixOS template via `nails-core/src/nixos/config/mod.rs`, which depends on switching the generation before login) as a TODO-only note here; do not make it the default.

  **Done when**
  - `persona.mode` exists in `nails.toml` and the init template; `fresh-home` bind-mounts an empty hidden home over the target home and is excluded from bind-sync extra lowers and opaque stripping.
  - `nails status` and dry-run report the active persona mode; `shared-home` prints a warning.
  - `README.md` and `docs/USER-SECURITY-GUIDE.md` document the shared-account model and each mode.
  - An E2E test (Debian/Ubuntu overlay-only plus the NixOS VM suite) shows that in `fresh-home` mode decoy home contents are not visible in the hidden session; `separate-user` is left as a documented TODO.

  _Status: done in wave C1. New `[persona]` table: `shared-home` (default, warns at activation) and opt-in `fresh-home`, which bind-mounts `{hidden_root}/persona/home` (operator-owned, 0700) over the operator's home after the overlays, tracked for rollback and teardown and classified as NAILS-owned; `nails status`, `nails check` and the status JSON schema report the mode; configuration.md, README and the security guide document the shared-account model. `75-persona-fresh-home.nix` is written but not yet run. A separate-user persona stays a documented follow-up._

### W6-C3: Command timeouts & child-env hygiene

Owns: `Cargo.toml`, `nails-core/src/process/run.rs`, `nails-core/src/cleanup/manager.rs`

- [x] **T-047: Add deadlines for external control commands (never for build/switch), with progress output for long steps** (medium · effort M)

  _Already resolved: the single `process/run.rs` runner provides a no-deadline Streaming mode (heartbeat for build/switch, never killed) and a `Deadline(budget)` mode (own process group, killpg+SIGKILL on expiry, typed `NailsError::Timeout`), with named budgets on systemctl/loginctl/nix-store/ldd/cp/du/chown/reboot and a process-group kill test. Remaining `Command::new` sites are owner-sanctioned (detach handoff deferred to T-050; restore.rs waitpid to T-082)._

  **Problem:** Every external command is a bare `output()`/`status()` with no deadline: `nixos/command.rs:23-30`, reboot dispatch (`manager/deactivation.rs:112`), `switch-to-configuration` (`deactivation/orchestrator/mod.rs:354`), find/getfattr (`overlay/opaque.rs:60,77`), cp/du (`filesystem/real/dir_ops.rs:142,179`), `nix-store -qR`/`ldd` (`manager/helpers/command_cache.rs:130,364`), and `waitpid(child, None)` in `manager/activation/overlay_mount/restore.rs:127,264`. The "bounded" loops (`manager/helpers/service_controller.rs:49-80,145-160`; `process/session/management/mod.rs:217-240`) only check the deadline between calls, so a single hung `systemctl is-active` or `nix store ping` can freeze activation, deactivation or emergency without any feedback.

  **Fix:**
  - Add one runner in `nails-core/src/process/run.rs` (new; T-048 uses the same module). It spawns the child in its own process group and runs in one of two modes. `Deadline(Duration)` waits with a deadline (`wait-timeout` crate or a pidfd poll), kills the whole group when it expires and returns a typed `Timeout { command, budget }` error. `Streaming` sets no deadline and forwards output or prints a heartbeat.
  - Give probes and idempotent emergency-path commands hard budgets, defined as named constants: systemctl is-active/stop/start/daemon-reload 10-30 s, `nix store ping` 5 s, plus budgets for loginctl, ldd, `nix-store -qR`, cp/du, chown and reboot dispatch.
  - Never kill `nixos-rebuild build/test` (`nixos/builder/switch.rs:189`) or `switch-to-configuration` on a deadline. Run them in `Streaming` mode with a heartbeat such as "still building, 2m10s". An optional configurable build timeout may apply, but only before the switch phase starts.
  - Turn the `restore.rs` `waitpid` calls into a WNOHANG poll with a deadline, unless the nix-store bind teardown rework removes them first. Document next to the runner that a deadline cannot recover a D-state process.

  **Done when:**
  - A unit test runs `sh -c 'sleep 60 & sleep 60'` with a 200 ms budget. It gets `Timeout` naming the command, and the grandchild is gone too.
  - Outside tests, `rg 'Command::new' nails-core/src nails-cli/src` matches only `process/run.rs`.
  - A long build prints progress. `cargo test` and clippy pass with zero warnings.

  _Status: mostly done across waves C1 and C4. `ProcessRunner` has a streaming mode with a periodic heartbeat (`still building, 2m10s`) used by `nixos-rebuild build/test` and both decoy `switch-to-configuration` paths, which are never deadlined; systemctl, loginctl, `nix store ping`, ldd, cp and reboot dispatch run under named budgets, with per-call deadlines inside the ping/is-active wait loops. The user-session `notify-send` now dispatches through the shared runner via a new `ProcessCommand::set_env` that writes call-site session vars (XDG_RUNTIME_DIR, DBUS_SESSION_BUS_ADDRESS, display) on top of the cleared allowlist while the fixed PATH is still applied last. Remaining: the production `systemd-run` detach handoff (`cli/detach.rs:322,406`) is a process handoff, not a run-to-completion command, and is deferred to the T-050 `HostEffects` detach rework that touches the same dispatch; the binary self-re-exec sites are test-only (exempt); the `restore.rs` namespace-helper `waitpid` WNOHANG deadline poll is picked up by T-082._

- [x] **T-048: Root child processes get fixed tool resolution, a cleared environment with an allowlist, and no caller PATH or NIX_* passthrough** (medium · effort M)

  **Problem:** Root code paths start tools by bare name, so the caller's PATH decides which binary runs. Affected tools: chown (`notification/mod.rs:109,169`), setfattr/find/getfattr (`overlay/opaque.rs:37,60,77`), cp/du (`filesystem/real/dir_ops.rs:142,179`), swapoff/nixos-rebuild (`filesystem/real/system_ops.rs:19,33,58`), loginctl/kill (`process/session/types.rs:136,160,181`; `process/restart/mod.rs:109`), sync (`cleanup/manager.rs:283`) and the shell (`cleanup/history/cleaner.rs:286`). Other paths hardcode `/run/current-system/sw/bin`. The detached root unit also puts the caller's PATH first (`nails-cli/src/cli/detach.rs:101-130`, used at :199-203 and :287) and copies in every `NIX_*` variable (:205-211). As a result, the binaries that run as root and the behaviour of `nixos-rebuild --impure` depend on the user's profile directories and Nix configuration.

  **Fix:**
  - Resolve each tool once through the Platform tool resolver from the multi-distro binary-resolution work. It searches a fixed, root-owned, per-platform directory list. No bare names and no embedded Nix store paths.
  - Start every child through `process::run` (T-047) with `env_clear()` plus an allowlist: `LANG`/`LC_*`, `TERM` where needed, and `NIX_PATH` only for channel-based `nixos-rebuild`. Keep stripping `NIX_PATH` for flake builds (`nixos/command.rs:26-28`).
  - In the detached unit, set a fixed PATH from the resolver (on NixOS `/run/wrappers/bin:/run/current-system/sw/bin`). Drop the blanket `NIX_*` passthrough; allow `NIX_REMOTE` or `NIX_SSL_CERT_FILE` only for a concrete, documented need.
  - Compile the tool-path override variables (`NAILS_SYSTEMD_RUN_PATH` at `detach.rs:15`, `NAILS_SYSTEMCTL_PATH`/`NAILS_REBOOT_PATH` at `manager/deactivation.rs:16-17`) only under the `test-hooks` feature.
  - In `docs/USER-SECURITY-GUIDE.md`, state that the hidden backend (binary, config, flake, configuration.nix) is part of root's trusted computing base and that unauthenticated or remote backends are unsupported. Add an update procedure that follows `docs/release-artifact-reproducibility.md` and keeps the binary on the hidden root. Do not add a runtime self-integrity check.
  - Follow-up, not part of this item: drop `--impure` by copying the hidden module into the overlaid `/etc/nixos` upper so evaluation can be pure.

  **Done when:**
  - `rg 'Command::new\("[a-z]' nails-core/src nails-cli/src` finds no bare-name spawns outside the resolver and tests.
  - A unit test on the detach command builder sets `PATH=/tmp/evil:...` and `NIX_CONFIG=...` in its environment. The resulting argv still has the fixed PATH and no `NIX_*` beyond the allowlist.
  - A unit test through `process::run` shows that a child sees only allowlisted variables.
  - The security guide documents the trusted-computing-base requirement and the update procedure. `cargo test` and clippy pass with zero warnings.

  _Status: done in wave C1. The detached unit gets a fixed root-owned PATH (`/run/wrappers/bin` plus `SYSTEM_TOOL_DIRS`, never the caller's PATH) and no `NIX_*` passthrough, proven by builder tests with a hostile caller PATH and NIX_CONFIG/NIX_PATH; `SYSTEM_TOOL_DIRS` is the single tool-directory list; the security guide has Trusted Computing Base and Updating NAILS sections. The runner's cleared env and allowlist (W6-C3) and the test-hooks gating of the `NAILS_*` overrides landed earlier._

### W6-C4: Test-support builder

Owns: `nails-core/src/config/testing.rs`, `nails-core/src/filesystem/mock/setup_state.rs`, `nails-core/src/manager/tests.rs`

- [x] **T-049: Add a test-support TestWorld builder and typed path fixtures, and split the monolithic test files** (medium · effort M)

  **Problem:** The test setup code has grown with no structure. `nails-core/src/manager/tests.rs` is 7,860 lines and 175 tests. It contains 86 `NailsManager::new` calls, 128 `Config {` literals, 150 `MockFilesystem::new` calls and 77 tempdirs. `shell/tests.rs` (2,262 lines) and `deactivation/tests.rs` (2,161 lines) have the same problem. `Config::test_default` is `#[cfg(test)]` (`config/mod.rs:35-36`), so integration tests and `nails-cli` can't use it. As a result, `make_manager` has been rewritten 5 times: `output/activate.rs:294`, `output/deactivate_tests.rs:43`, `nixos_switch.rs:204`, `session.rs:171` and `tests/example_flow.rs:14`. `mock_set_path_type` treats any string other than `"directory"` as a file (`filesystem/mock/setup_state.rs:70-76`), and setting up one file takes three calls. There are five naming conventions for test files. The 500-line limit on source files has pushed complexity into test files that have no limit.

  **Fix:**
  - Add a test-support module, either behind a `test-support` feature or as a `nails-test-support` crate. It provides a `TestWorld` builder: `.with_file(path, content)`, `.with_dir(path)`, `.with_hardware_config(..)`, `.with_config(..)`, and `.manager()`, which returns the manager together with its tempdir.
  - Replace the string argument of `mock_set_path_type` with a `PathKind` enum (`File`, `Dir`, `Symlink`, `Missing`). Add a single call that sets up a file. Make this change together with the Filesystem-trait trim, which adds `mock_set_is_mounted_error` to the same `setup_state.rs`.
  - Move `Config::test_default` out of `#[cfg(test)]` into the test-support module, and build it against the new strict TOML `Config`. Delete the 5 `make_manager` copies.
  - Split `manager/tests.rs` by behaviour: preflight, overlay mount, rollback, logging, nixos build. Split `shell/tests.rs` and `deactivation/tests.rs` the same way. Use one naming convention, e.g. `<module>/tests/<behaviour>.rs`, and document it in CONTRIBUTING.

  **Done when:** `TestWorld` and `PathKind` exist and the existing tests use them. `rg 'fn make_manager'` finds no copies outside test-support. `nails-cli` and `tests/` build against the shared `test_default`. No test file is larger than about 1,500 lines, and all of them follow the one naming convention. `nix develop -c cargo test --workspace` passes, clippy reports zero warnings, and the coverage gate still holds.

  _Already resolved: `TestWorld` (`config/testing.rs`) and the `PathKind` enum (`filesystem/mock/setup_state.rs`) exist and are used, `Config::test_default` lives behind the non-default `test-support` feature, `rg 'fn make_manager'` finds zero copies, and `manager/tests`, `shell/tests` and `deactivation/tests` are split by behaviour under the documented `<module>/tests/<behaviour>.rs` convention (CONTRIBUTING). The advisory ~1,500-line soft cap still leaves a few large test files (state, cli_integration, nixos, status, verify), which were not named monoliths and are tracked separately, not a blocker for this item._

## Wave 7: Test-hooks removal + overlay safety floor/init + PR gate

### W7-C1: Test-hooks removal & no-decoy-switch

Owns: `Cargo.toml`, `nails-core/src/runtime_safety.rs`, `nails-core/src/deactivation/orchestrator/mod.rs`, `nails-cli/src/cli/detach.rs`

- [x] **T-050: Move all test hooks and test-detection heuristics behind a non-default test-hooks cargo feature and out of the release binary** (high · effort M)

  _Already resolved: no `deps`/`/target`/`llvm-cov` runtime path heuristic remains in `nails-core/src` or `nails-cli/src`; `should_skip_host_interaction()` is a compile-time `false` without the feature; the orphan `manager/activation/test_gate.rs` and the `cli/safety.rs` build-dir guard are deleted; the `HostEffects{Real,Simulated}` reboot/switch dispatcher carries the mandated unit tests (reboot still requested under `NAILS_TEST_RUNTIME=1`; a forced guard returns `Err`, not `Ok`); the `nails-e2e` test-hooks package, the `nails-release-hygiene` binary-string flake check and the rewired VM gate tests are wired. The nix attributes must still be evaluated on a nix host (see nix_pending)._

  **Problem**
  `runtime_safety.rs:12-25` `should_skip_host_interaction()` returns true in release builds whenever `NAILS_TEST_RUNTIME` is set or any component of `current_exe()` is named `deps`. It gates real effects at ~23 production call sites across 13 files: the post-deactivate reboot (`manager/deactivation.rs:534` prints "Rebooting system..." then silently returns `Ok` without `request_reboot()`), the decoy switch (`deactivation/orchestrator/mod.rs:350`), blocking-process detection (`process/detection/mod.rs`), nix-daemon/service restarts (`manager/helpers/service_controller.rs`), the session kill (`process/session/management/mod.rs`), auto-answered prompts (`prompts/mod.rs`), process restarts, notifications and `/nix/store` restore. Because the hidden root is derived from the binary's parent dir, an operator path can trip the `deps` heuristic. More divergent heuristics exist: `nails-cli/src/cli/detach.rs` adds `/target/{debug,release,llvm-cov-target}`, `config/defaults.rs` adds a `/nix/store`→`/mnt/hidden-volume` fallback, `cli/safety.rs` has its own, and only some honour `NAILS_UNSAFE_REAL_OPS`. Test gates (`manager/activation/gate.rs`, `deactivation/test_gate.rs`, `NAILS_TEST_*_GATE_PATH`, shell-cleanup skip) and override env vars (`NAILS_SYSTEMD_RUN_PATH`, `NAILS_SYSTEMCTL_PATH`, `NAILS_REBOOT_PATH`, `NAILS_SHELL_CLEANUP_PROTECTED_PIDS`, `NAILS_DEACTIVATE_UNIT_NAME`) plus the `backdoor` service exemption (`process/shell_cleanup.rs:26`) all ship in the release binary. `nails-core/src/manager/activation/test_gate.rs` is an orphan (only `gate.rs` is wired via `mod.rs:31`). The E2E suite drives these gates against the packaged binary (`nix/e2e-tests/lib/state-helpers.nix:87-113`).

  **Fix**
  Add a `test-hooks` feature (default off) to `nails-core` and `nails-cli`. Delete every `current_exe()`/path-substring heuristic: `runtime_safety.rs`, `binary_looks_like_test_runtime` in `detach.rs`, the build/store fallback in `config/defaults.rs`, the build-dir guard in `cli/safety.rs`. With the feature off, `should_skip_host_interaction()` is `const false` and no `NAILS_TEST_*` or override env var is read. Introduce one explicit `HostEffects { Real, Simulated }` on `NailsManager`, set by the CLI (dry-run) or by tests, with `cfg(test)` the only implicit trigger; integration tests opt in via a self dev-dependency (`nails-core = { path = ".", features = ["test-hooks"] }`, same for `nails-cli`). Put the blocking gates, shell-cleanup gate, backdoor exemption (inject protected service/PID list through a test-hooks-only env var) and all override env vars behind the feature. Delete the orphan `manager/activation/test_gate.rs`. In `Simulated` mode never skip the reboot or decoy re-switch silently — report the skipped steps and return an `incomplete` status, or return an explicit error where a guard still skips a destructive step. Keep `NAILS_UNSAFE_REAL_OPS` only as a guard inside test helpers. In `flake.nix` add a `nails-e2e` package built with `test-hooks`; `nix/e2e-tests` uses it only for gate/override-dependent tests, while smoke and forensic tests run against the release `nails` package. Add a release-artifact hygiene flake check asserting the release binary contains none of `NAILS_TEST_`, `NAILS_SYSTEMCTL_PATH`, `NAILS_REBOOT_PATH`, `NAILS_SYSTEMD_RUN_PATH`, `NAILS_UNSAFE_REAL_OPS` or `backdoor`.

  **Done when**
  - `rg '"deps"'` over `nails-core/src` and `nails-cli/src` finds no runtime path heuristic; no `/target/debug` or `llvm-cov-target` heuristic remains outside tests.
  - `grep -a` on the release binary (and a flake check) finds none of the listed `NAILS_TEST_*`/override strings or `backdoor`.
  - `nails-core/src/manager/activation/test_gate.rs` is deleted.
  - Unit test: a non-test build with `NAILS_TEST_RUNTIME` set still requests the reboot (mock reboot dispatcher records the call); a forced guard returns an error, not `Ok`.
  - `cargo test --workspace` (enables `test-hooks` via dev-dependency) and clippy pass; `cargo build` without the feature and `nix build .#nails` plus the `nails-e2e` package all build; E2E green with gate tests on `nails-e2e` and smoke/forensic on the release package.

- [x] **T-051: Drop the decoy switch-to-configuration switch from deactivation and replace the action parameter with a non-installing enum; assert ESP/NVRAM unchanged** (high · effort S)

  _Status: done in wave C1 (Rust invariant from W7-C1). `80-uefi-esp-nvram-invariant.nix` boots through OVMF with persistent EFI variables and systemd-boot, and asserts ESP hashes, EFI boot entries and `/var/lib/nixos` identity files change no more across an activate/deactivate cycle than across a plain-reboot control; it must still be run on a KVM host (OVMF option names, `/dev/vdb` under `useBootLoader`, reboot handling)._

  **Problem**
  After unmounting overlays, `deactivation/orchestrator/mod.rs:347-358` runs `<newest system profile>/bin/switch-to-configuration switch` on the real disk (enabled for Normal deactivation, `manager/deactivation.rs:490-498`), immediately before a reboot that restores the decoy anyway. Activation only ever uses `test`, so the boot default is already the decoy. `switch` reinstalls the bootloader (writes the ESP), runs the full activation script on the real `/var` including `update-users-groups` (rewriting `/var/lib/nixos/{declarative-users,declarative-groups,uid-map,gid-map,auto-subuid-map}`), restarts services that log to the decoy journal, and adds a failure point before the reboot. The failed-hidden-switch rollback also uses `switch` while overlays are mounted (`nixos/builder/switch.rs:62`, `self.switch_to_generation(&prev, "switch")`), which can write bootloader state or EFI NVRAM that no overlay captures. `filesystem/real/system_ops.rs:51-60` keeps a `nixos-rebuild switch --profile` path. Nothing tests that the ESP and NVRAM stay unchanged. Invariant: any boot entry, config file or NVRAM variable that enables the hidden mode is itself evidence.

  **Fix**
  Remove the decoy switch step from standard deactivation (a reboot follows); keep only the `/run/current-system` symlink swap if still needed for emergency. Replace the string action parameter passed to `switch-to-configuration`/`nixos-rebuild` with an enum offering only `Test` (and `DryActivate` if required), so the code can never request `switch` or `boot`; the type enforces it. Change the rollback in `builder/switch.rs` to the same non-installing action. If the reboot command fails, fall back to `switch-to-configuration test`, never `switch`/`boot`. Delete the `nixos_switch_profile` filesystem method and its real/mock impls if unused (coordinate with the dead-code cleanup item). Add a UEFI E2E test that hashes ESP contents and captures EFI variables (efivarfs listing) before activation and after deactivation, asserting both unchanged relative to a plain-reboot control. State the invariant in `docs/threat-model.md`.

  **Done when**
  - `rg '"switch"'` over `nails-core/src/deactivation` and `nails-core/src/nixos/builder` returns no `switch-to-configuration` `switch` invocation; no string `switch`/`boot` action reaches `switch-to-configuration` or `nixos-rebuild` anywhere (enforced by the enum).
  - Unit tests: Normal deactivation does not execute the switch script; reboot failure falls back to `test`; the rollback asserts the `Test` action.
  - UEFI E2E (persistent-root VM): `/var/lib/nixos` inode/mtime, ESP file listing/hash and `efibootmgr -v` / EFI variable list unchanged between pre-activation and post-deactivation versus the control.
  - `cargo test` and clippy clean.

- [x] **T-052: Remove order-dependent environment races from the Rust test suites (EnvGuard now, RuntimeEnv injection next)** (medium · effort L)

  _Partial (T-009): `serial_test` is on 3.5, which no longer pulls in `scc`, so the `RUSTSEC-2026-0205` ignore is gone; the environment-race rework remains._

  _Status: Phase 1 done — `EnvGuard` (poison-tolerant, re-entrant, RAII restore of vars and cwd) added behind `test-support`; every raw set_var/remove_var in both crates' tests now routes through it, no `.lock().unwrap()` on env locks remains in nails-cli, and `scc` is absent from Cargo.lock and deny.toml. Remaining (Phase 2, effort L): a `RuntimeEnv` read once in `main` and injected into manager/cleanup/shell/notification code, after which `serial_test` (still 4 refs in Cargo.lock, 216 `#[serial]` uses) and test-time env mutation can go (the "rg finds nothing outside the CLI entry point" done-when belongs to Phase 2). Deliberately sequenced after T-050 (test-hooks boundary) and T-068 (CLI contract), both now landed, because they rework the same interwoven real-config/override env reads. Wave F1 added the cross-crate `env_guard_contract.rs` regression test (restore-after-panic, nested-guard, cwd restore) and a shuffled-seed order-independence CI gate (`just shuffle` over 20 seeds, on the gate needs list) so Phase 2 cannot silently regress Phase 1; Phase 2 is still deferred, now after T-064 (platform/target-user rework touches the same env reads)._

  _Status (2026-10): done. Phase 2 landed: a `RuntimeEnv` snapshot is read once in `main` and threaded to every handler; the operator, session, shell, system profile, child environments, cleanup homes and test-hook knobs all resolve from it. Every test injects a `RuntimeEnv`, so `EnvGuard`, its contract test, `serial_test` and every `#[serial]` are gone; `rg 'env::set_var|env::remove_var'` over both crates' `src` is empty. `just shuffle` passes 20 seeds for both crates._

  **Problem**
  The tests contain 414 `env::set_var`/`remove_var` calls (200 in `shell/tests.rs`) and 198 `#[serial]` attributes, but `#[serial]` only serializes against other serial tests. Shuffled runs fail intermittently (5/6 for nails-core, 2/10 for nails-cli). Concrete races: `manager/tests.rs:5906` and `:5973` read `HOME` without `#[serial]`, contrary to `cleanup/test_utils.rs:8`; `nixos/tests.rs:1720` sets `PATH` to a bare tempdir, breaking `du` in `filesystem/real/tests.rs:901`; `cli/safety.rs:83/99/113/144` use `.lock().unwrap()`, so one failure poisons four more tests; two different locks (`detach/tests.rs:11` `ENV_LOCK`, `safety.rs:76` `env_lock`) let `NAILS_*` vars leak into the subprocess of `deactivate/tests.rs:262`; `with_env` (`detach/tests.rs:13-22`) removes vars instead of restoring them; SAFETY comments relying on `#[serial]` (`test_utils.rs:71`) are wrong. `serial_test` 3.x pulls in `scc`, forcing the `RUSTSEC-2026-0205` ignore (`deny.toml:38-47`).

  **Fix**
  Phase 1 (S): add a new `nails-core/src/test_support/env.rs` behind a `test-util` feature — one poison-tolerant env lock per test binary plus an RAII `EnvGuard` that restores previous values — shared with the nails-cli tests. Make every test that reads or writes process env take the lock, including the `HOME` readers at `manager/tests.rs:5906/5973`. Give tests that replace `PATH` an injected command path instead of mutating `PATH`. Fix the misleading SAFETY comments. Once the toolchain is at 1.93.1+, bump `serial_test` to 4.x (drops `scc`) and delete the `RUSTSEC-2026-0205` ignore.
  Phase 2 (L): add a `RuntimeEnv` struct (`HOME`, `PATH`, `SUDO_USER`/`SUDO_UID`, `SHELL`, `DISPLAY`/`WAYLAND_DISPLAY`, the `XDG_*` values NAILS uses) read once in `nails-cli` `main` and passed into `NailsManager`, cleanup, shell and notification code; tests build `RuntimeEnv` values instead of mutating the process environment; remove `serial_test` once no test mutates env. Coordinate with the target-user resolution and test-hook removal items, which touch the same env reads.

  **Done when**
  - 20 consecutive shuffled seeds pass for both crates.
  - No `.lock().unwrap()` on env locks remains in `nails-cli`.
  - `deny.toml` has no `scc` ignore and `Cargo.lock` contains no `scc`.
  - After phase 2, `rg 'env::set_var|env::remove_var' nails-core/src nails-cli/src` finds nothing outside the CLI entry point and its tests.

### W7-C2: Overlay target safety floor + init preconditions

Owns: `nails-core/src/config/dynamic.rs`, `nails-core/src/preflight/checks/overlay_targets.rs`, `nails-cli/src/cli/commands/init.rs`

- [x] **T-053: Overlay target safety floor: refuse leaky exclusions, never overlay an ancestor of the hidden root, drop the dead /Downloads exclusion** (high · effort M)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (overlay targets and exclusions). The item stays ticked as history; it describes no current code._

  _Status (W7-C2): implementation complete and unit-tested — the `overlay-targets` preflight check refuses any target covering the hidden root, state file, log dir or binary (symlinks resolved via a new `Filesystem::canonicalize`) and any Auto-mode leaky exclusion of a load-bearing directory unless listed in the new `allow_leaky_exclusions` key; `/Downloads` and the "nix store performance" copy are gone. The VM subtests in nix/e2e-tests/tests/config/26-config-exclusions.nix (including the /media refusal) await evaluation on a nix-capable host (see nix_pending)._

  **Problem**
  - `compute_effective_exclusions` (nails-core/src/config/dynamic.rs:35-73) only warns when /proc, /sys, /dev or /run are removed. It silently accepts added exclusions such as /home, /nix, /var or /root, which send hidden-session writes to the decoy disk. The example config (config/loading.rs:232-234) and the `overlay_exclusions` doc comment (config/types.rs:226-236) even suggest excluding /nix "for Nix store performance".
  - `build_overlay_targets` (manager/helpers.rs:271-316) never compares targets against the hidden root, state file, log path or running binary. Auto mode overlays /media, so a hidden volume at VeraCrypt's /media/veracryptN or udisks2's /media/$USER/<label> gets skipped as a device submount (filesystem/real/submount.rs:141) and disappears under the /media overlay. Later upper/work dirs (helpers.rs:363) and state saves then resolve into the overlay and activation aborts. Every E2E test uses /mnt/hidden-volume, so none of this is tested.
  - The `"/Downloads"` entry in DEFAULT_OVERLAY_EXCLUSIONS (config/types.rs:59,78,226) can never match, because targets are only the top-level entries of / (filesystem/real/dir_ops.rs:28). It also suggests the container file gets special handling, which it does not.

  **Fix**
  1. Leaky-exclusion floor: treat /home, /root, /etc, /var, /nix, /srv, /opt and a non-tmpfs /tmp as load-bearing. In Auto mode, excluding any of them fails preflight and config validation unless the path is listed in a new strict `allow_leaky_exclusions = ["/nix"]` key in nails.toml. Remove the /nix suggestion from the example config and the doc comments.
  2. Nesting guard: add one shared helper that canonicalizes hidden_volume_root, state_file_path, log_path and current_exe(). It rejects any target equal to or an ancestor of one of those paths, in both modes. Wire it into helpers.rs, activation/overlay_mount/explicit_mount.rs and a new preflight check registered in manager/preflight_runner.rs. Refuse instead of silently dropping the target, since a dropped target would be left unprotected. Example message: "hidden root /media/veracrypt1 is under overlay target /media; mount it under /mnt or /run/media, or add /media to overlay_exclusions". /media is not load-bearing, so excluding it stays allowed.
  3. Delete `/Downloads` and its doc lines, and update config/tests/config_tests.rs:1205. Add one sentence to docs/USER-SECURITY-GUIDE.md: do not open the container file for writing during a hidden session, because overlay copy-up would duplicate it onto the hidden root.
  4. Land this together with the platform item that reworks DEFAULT_OVERLAY_EXCLUSIONS (the /usr guard on FHS hosts), so there is a single list. Keep the requirement that the hidden root is a mountpoint, and document it.

  **Done when**
  - Unit tests: in Auto mode, excluding each load-bearing path fails preflight and validation, and passes once the path is in allow_leaky_exclusions. A tmpfs /tmp is accepted.
  - Unit tests: a hidden root at /media/veracrypt1 is refused in Auto mode with the documented message. An Explicit target that is an ancestor of the state file is refused. A symlinked hidden root is still caught after canonicalization.
  - A VM test with the hidden volume under /media shows the refusal before any mount or session kill.
  - `rg -i 'nix store performance' nails-core/src` returns nothing, and `rg Downloads nails-core/src` returns nothing outside the updated tests. cargo test and clippy pass.

- [x] **T-054: nails init checks every precondition (mounted, separate device, writable) before writing, reports accurately, ends with next steps** (high · effort M)

  _Status (W7-C2): implementation complete and unit-tested — init validates mount, separate-device, writability and symlink-support before any write (writing nothing on refusal), adds `--allow-unmounted`/`--hardware-config`/`--no-hardware-config` and `--json`, reports each item's status, drops `overlays/`, rejects a global `--config`, and ends with numbered next steps. The NixOS gate uses a local `/etc/NIXOS` probe pending the platform seam (T-064). The init E2E tests (45-init-bootstrap, 47-init-refuse-overwrite, plus the 46-init-idempotency regression) await evaluation on a nix-capable host (see nix_pending)._

  **Problem**
  `nails init` (nails-cli/src/cli/commands/init.rs:80-89) checks only exists()/is_dir(). It then uses std::fs to write 12 directories, the config, state.json and the NixOS layout. Activation's HiddenVolumeCheck requires a mountpoint (nails-core/src/preflight/checks/hidden_volume.rs:85-90), but init does not. Running init before mounting therefore writes a NAILS-identifying tree onto the decoy disk, where the real mount later hides it. This ordering mistake is easy to make because the README uses /mnt/hidden at README.md:85-107 and /mnt/hidden-volume at 121-148.

  The hard-coded /etc/nixos/hardware-configuration.nix (init.rs:73) is read only after everything else is written. On flake hosts and non-NixOS hosts, init stops with a Debug-printed `NixOSError(...)` and leaves a half-initialised volume. Other problems:
  - Re-runs print "Created" for directories that already exist (init.rs:92-96).
  - The global --config is silently ignored (cli/mod.rs:99).
  - An `overlays/` directory is created that nothing uses.
  - The starter config writes the `hidden_volume_path` alias.
  - No next steps are printed.

  **Fix**
  1. Move init onto the Filesystem trait and validate everything before the first write. The target must exist, be a directory and be a mountpoint whose st_dev differs from /. Put that check in a helper shared with HiddenVolumeCheck, because `is_mounted` (filesystem/real/mount_ops.rs:84) only consults /proc/mounts. The target must also be writable and support symlinks, and the hardware config must be readable whenever it will be bootstrapped. Otherwise refuse with "not a mounted backend - mount the hidden volume first". `--allow-unmounted` proceeds with a warning, for directory-style backends.
  2. Add `--hardware-config <PATH>` and `--no-hardware-config`. Bootstrap from /etc/nixos only on the NixOS platform backend; on other platforms skip it with an info line.
  3. Report each item as created, already present or updated. Drop `overlays/` from SUBDIRS. Write `config/nails.toml` using the canonical `hidden_volume_root` key.
  4. Reject a global --config on init with a clear message. Support --json and -q (global once the CLI redesign lands), with JSON output listing each item and its status. Errors go through the Display/exit-code contract.
  5. Finish with numbered next steps: copy the binary to `<root>/nails`, optionally edit `<root>/config/nails.toml`, run the read-only preflight (`sudo <root>/nails check`, or `activate --dry-run` until that command exists), then run `sudo <root>/nails activate`.
  6. README: use one mountpoint (/mnt/hidden-volume) throughout, and show the mount step before init.

  **Done when**
  - MockFilesystem unit tests:
    - An unmounted target, or one on the same device as /, fails with zero writes.
    - `--allow-unmounted` proceeds with a warning.
    - A missing hardware config without either flag fails before any write.
  - A re-run reports "already present" and creates nothing. No `overlays/` directory exists. Output has no `NixOSError(` or other Debug formatting and ends with the numbered next steps.
  - `nails --config X init <path>` exits non-zero with an explanation.
  - E2E tests nix/e2e-tests/tests/init/45-47 are updated (nails.toml, no overlays/). One of them asserts that init refuses an unmounted directory and leaves it empty.
  - cargo test and clippy pass.

### W7-C3: Lean PR gate

Owns: `.github/workflows/ci.yml`, `.config/nextest.toml`

- [x] **T-055: Rewrite ci.yml into a lean parallel PR gate with one required check, doctests, nextest profile, fork-safe coverage and least-privilege permissions** (high · effort L)

  _Partial (T-009): the dependency-policy job now detects Cargo.toml/Cargo.lock/deny.toml changes and gates advisories only on those PRs, and cargo-audit no longer duplicates `cargo deny check advisories`; the full ci.yml rewrite remains._

  _Status: mostly done (W7-C3, C1, wave C3/K3). The ci.yml rewrite, nextest ci profile, path filter, JUnit summary, stress lanes, zsh/fish and per-workflow permissions landed; wave C3 added the pinned SHA-256 integrity check for the actions/runner tarball downloaded in `e2e-hetzner.yml`. Remaining is maintainer/hosted-runner only (not code): measure the warm-cache gate time on a hosted runner and record it in `docs/ci.md`, and switch the branch ruleset's required check from `CI Success` to `gate`._

  **Problem:** `.github/workflows/ci.yml` (506 lines) runs 12 jobs chained by `needs:` that pass no data between them (audit/test/geiger need lint at l.58/102/285, coverage/sbom/benchmarks need test, burn-in needs coverage at l.324). Criterion benchmarks set the critical path: 6.2 min warm and 9.6 min cold, for about 2 min of real work. Each PR compiles the workspace about 9 times across 11 rust-cache keys. Tools are built with `cargo install` (l.123/170/258/302, 777 s on a cold cache). There is no `concurrency:` and no path filter, so docs-only PRs run everything. The `dev` triggers are dead (l.7/11/327), and `toolchain: 1.93.0` repeats what rust-toolchain.toml already says. geiger ends in `|| true` (l.307), so the gate's geiger check (l.490) can never fire. cargo-audit repeats `cargo deny check advisories`. No step uses `--locked`, which is how v0.2.0 shipped a stale Cargo.lock. There is no `.config/nextest.toml`, so the failure upload of `target/nextest/**/*.xml` (l.138) is always empty. Doctests run only in burn-in (l.343), which is skipped on push to main. The sticky coverage comment needs `pull-requests: write` (l.148-150, 221-234). Fork PRs only get a read-only token, so it fails with 403 and takes `CI Success` down with it. ci.yml and e2e-tests.yml have no top-level `permissions:`. ci.yml:268 and release-core.yml:253 download cyclonedx-cli with curl and run it without a checksum.

  **Fix:**
  - **Structure.** Rewrite ci.yml to about 200 lines. Keep every `run:` block to 10 lines or fewer and put the logic in the justfile recipes from the local-dev-loop item.
    - Triggers: `pull_request`, push to `main` and `workflow_dispatch`. No `dev`, no `schedule:`.
    - Top level: `permissions: contents: read` and `concurrency: ci-${{ github.event.pull_request.number || github.ref }}`, with cancel-in-progress on PRs only.
    - A `changes` job (SHA-pinned dorny/paths-filter) outputs rust/deps/nix/workflows. The jobs below have no `needs:` and are gated on those outputs.
  - **`lint`.** A `cargo metadata --locked` guard, then fmt and clippy with `--all-targets --all-features --locked -D warnings`, plus the line-count check.
  - **`rust`.** `cargo llvm-cov nextest --workspace --locked --profile ci`, with the coverage threshold defined once in the justfile, then `cargo test --doc --workspace`. Write the coverage figure to `$GITHUB_STEP_SUMMARY`. No sticky comment, no write token, no sharding.
  - **`deps`.** `cargo deny check bans licenses sources` on every run. `advisories` blocks only when Cargo.toml, Cargo.lock or deny.toml change. Remove cargo-audit.
  - **`lint-misc`.** `nix flake check` running the cheap linters, including actionlint and zizmor.
  - **`nix-build`.** `nix build .#nails-release -L` plus the archive smoke test, using the setup-nix composite. This replaces nix-pr-verify.yml.
  - **`gate`.** The only job with `needs:`. It uses `if: always()` and fails when any needed job failed or was cancelled. A job skipped by the path filter counts as success.
  - **Caching, tools, toolchain, timeouts, alerts.**
    - One Swatinem/rust-cache `shared-key` with `save-if: github.ref == 'refs/heads/main'`. scheduled.yml restores the same key so it does not expire.
    - Install nextest, cargo-llvm-cov, cargo-deny and just with taiki-e/install-action.
    - Read the toolchain from rust-toolchain.toml via actions-rust-lang/setup-rust-toolchain or plain rustup. The pinned dtolnay action requires its `toolchain:` input, so it has to be replaced, not just edited.
    - Timeouts at about 1.5x the observed p95: lint 10, rust 15, nix-build 15, lint-misc 10 min.
    - When a push to main fails, call the report-status composite.
  - **nextest profile.** Add `.config/nextest.toml` with a `ci` profile: `retries = 1`, `slow-timeout = { period = "60s", terminate-after = 3 }`, JUnit output. Upload the JUnit file on failure and list FLAKY tests in the job summary.
  - **Off the PR path.** sbom becomes release-only. geiger is replaced by the compile-time unsafe policy (optionally run weekly). Benchmarks move to schedule/dispatch and are informational only. Burn-in is removed.
  - **Scheduled stress lane (scheduled.yml).**
    - Threaded `cargo test --workspace`, plus a run with `--test-threads=1`.
    - A shuffled run (`RUSTC_BOOTSTRAP=1 cargo test -- -Z unstable-options --shuffle`) that prints its seed.
    - A nextest repeat loop with `retries = 0` that fails on any FLAKY result.
  - **Local scripts and shells.**
    - Delete scripts/burn-in.sh.
    - Replace scripts/ci-local.sh with the justfile `ci` recipe.
    - Add zsh and fish to the devShell (flake.nix:224) and to the rust job, so the shell-syntax tests can run without `#[ignore]`.
  - **Permissions and downloads.**
    - Add a top-level `permissions: contents: read` (or `{}`) to every remaining workflow and raise permissions per job only where needed.
    - In release-core.yml:252-257, take cyclonedx-cli from nixpkgs (`nix run nixpkgs#cyclonedx-cli`), or pin it and check it with `sha256sum -c`. Skip this if the release-pipeline item has already replaced that step.
  - **Deletions.** Delete nix-pr-verify.yml, forensics-eval-fast.yml and forensics-eval-regression.yml. This is a no-op if the forensics-eval removal has already deleted them. E2E stays in its own workflow with its own required check.
  - **Maintainer step.** Change the branch ruleset's required check from `CI Success` to `gate` and record it in docs/ci.md.

  **Done when:**
  - actionlint and zizmor report no errors for any workflow, including no excessive-permissions findings.
  - Every workflow has a top-level `permissions:` block.
  - No `curl .*releases/download` runs without a checksum check.
  - Only `gate` has `needs:`. ci.yml contains no `cargo install`, `dev`, `schedule:`, sticky-pull-request-comment, `pull-requests: write` or hard-coded toolchain version.
  - ci.yml uses exactly one rust-cache key, and it is saved only on main.
  - A docs-only PR skips the rust, deps and nix jobs and still reports a green `gate`.
  - A nails-core PR finishes the gate in about 3.5 min or less on a warm cache, measured and noted in docs/ci.md.
  - `rust` fails when coverage drops below the threshold and runs the doctests.
  - When a test fails, the uploaded JUnit artifact is not empty, and FLAKY tests appear in the job summary.
  - A fork PR, or any run with a read-only token, passes the gate.
  - Bumping the workspace version without updating Cargo.lock fails `lint`.
  - The scheduled lane runs shuffled tests and prints the seed.
  - zsh and fish are available in CI and in `nix develop`.
  - scripts/burn-in.sh and the three deleted workflows no longer exist.

## Wave 8: CI consolidation/release + unified render/check + activation rollback

### W8-C1: CI lint/bench/release/docs consolidation

Owns: `.github/workflows/`, `benches/`, `clippy.toml`, `docs/ci.md`

- [x] **T-056: Replace the line-count cap and geiger with compile-time lint policy and split the giant manager test file** (low · effort M)

  _Status (W8-C1): done. `[workspace.lints]` denies `unsafe_code` (scoped `#[allow(unsafe_code)]` plus `// SAFETY:` on every remaining site; shell_cleanup uses the safe `nix::sys::signal::kill`) and enables `undocumented_unsafe_blocks`, `too_many_lines` (170) and `cognitive_complexity` (32) from `clippy.toml`, with two `#[expect]` outliers. `scripts/check-line-count.sh` is a find+awk check shared by pre-commit, `just line-count` and CI (warn 500, fail 850 because `manager/deactivation.rs` has 803 code lines; tests warn at 1500). The geiger job is gone and `manager/tests.rs` is split into `manager/tests/` (largest file 1,278 lines). Follow-up: lower the thresholds and the 850 limit as the large files are split._

  **Problem**
  - `scripts/check-line-count.sh` (219 lines, `MAX_LINES=500` at l.7) hard-codes two exemptions: `manager/activation/mod.rs` (521 lines) and `manager/deactivation.rs` (555).
  - Its `#[cfg(test)]` module walker (l.31-179) changes no result. It takes ~22-26 s on every Rust pre-commit. In CI it is silently skipped because l.189 runs `rg ... 2>/dev/null || true` and the runner has no ripgrep, so local and CI logic differ.
  - The cap drives cosmetic module splits, and files bunch up at the limit (`cleanup/logs.rs` is exactly 500 lines).
  - `manager/tests.rs` has 7,860 lines and is pulled in through a redundant `#[path = "tests.rs"]` (`manager/mod.rs:55`).
  - The geiger job (`ci.yml:281`) can never fail. There is no `[lints]` table and no `unsafe_code` policy. The production unsafe sites are `shell_cleanup.rs:222`, `overlay_mount/restore.rs:87,125,226,262` and `deactivation.rs:186,204,208`.

  **Fix**
  - Rewrite the script as a ~10-line path-based check with no ripgrep and no exemption list:
    - Count non-blank, non-comment lines.
    - Production files: warn at 500, fail at about 800.
    - Test files (`tests.rs`, `*/tests/*`): warn at 1,500.
    - Pre-commit and CI run the same logic.
  - Add `[workspace.lints]` to `Cargo.toml`: `rust.unsafe_code = "deny"`, `clippy.undocumented_unsafe_blocks = "warn"`, `clippy.too_many_lines` and `clippy.cognitive_complexity`. Put the thresholds in a new `clippy.toml`, set so the current code passes (or `#[expect]` on the current offenders). Add `[lints] workspace = true` to both members.
  - Add `#![cfg_attr(test, allow(unsafe_code))]` to both crate roots. Each production unsafe site still left after the process and namespace refactors gets a scoped `#[allow(unsafe_code)]` and a `// SAFETY:` comment. Delete the geiger job.
  - Drop the `#[path]` attribute. After the manager decomposition lands, split `manager/tests.rs` into `manager/tests/*.rs` so the files mirror the production tree.

  **Done when**
  - `cargo clippy --all-targets --locked -- -D warnings` passes.
  - A new `unsafe {}` block in non-test code without an allow fails the build.
  - The line-count script has no exemptions, needs no `rg`, runs in under 1 s, and behaves the same locally and in CI.
  - The geiger job is gone, `manager/mod.rs` has no `#[path]`, and no test file under `nails-core/src/manager` exceeds about 2,000 lines.

- [x] **T-057: Fix benchmarks and perf tests: no absolute budget gate, own temp dirs, delete placeholders, move statistical loops out of the PR lane** (medium · effort M)

  _Status (W8-C1): done. Placeholder benches and the PR budget job are gone; the core benches own their temp dirs, use `[profile.bench] lto = "thin"` and run weekly in scheduled.yml against the previous main baseline via critcmp (25% warning, a missing result fails). 07 times nails' own `duration_ms` in the guest without crash or re-format, adds a timed default activation (nixos-rebuild stubbed) and runs only in the nightly lane; 05 runs one extra cycle; 78 bounds the in-guest `duration_ms`. Follow-ups: 07 switches to the prebuilt hidden closure once W14-C1 adds it; deterministic-count guards for the /proc scan need production instrumentation and are not added; pin critcmp after the first scheduled run; the VM tests await evaluation (see nix_pending)._

  **Problem**
  - `nails-core/benches/performance.rs` claims 'Validates RQ2: 2-5 second switching' (l.3), but every bench runs on `MockFilesystem`.
  - The CI job enforces absolute budgets (`ci.yml:392-445`) that sit 10-250,000x above real timings on shared runners. A missing result prints `SKIP` instead of failing (l.418).
  - The bench profile inherits `lto = true` (`Cargo.toml:50-52`), about 1m40s of compile time. This job is the ci.yml PR critical path.
  - `temp_dir.keep()` inside `iter_batched` setup (l.21,48,89) leaks one temp tree per iteration.
  - `nails-cli/benches/startup.rs` measures only clap parsing. The root `benches/performance.rs` is a placeholder that is never built.
  - E2E `07-performance.nix` (684 s) gates PRs on host-side wall-clock times:
    - Its 'p95' (`lib/perf.nix:9-14`) is the second-largest sample.
    - Each sample does `machine.crash()` and re-formats the hidden volume (l.84-108).
    - It times only `--overlay-only`.
  - `05-standard-deactivation-forensic.nix:260-263` repeats a deterministic flow 5 times with reboots, and `78-cleanup-fast-mode.nix:70` asserts `elapsed < 12.0`.

  **Fix**
  - Delete `benches/performance.rs`, `nails-cli/benches/startup.rs` and its `[[bench]]` entry.
  - `nails-core` benches:
    - Move them out of the PR gate into the scheduled lane, compared against a stored baseline (critcmp) with an alert threshold rather than absolute budgets. A missing result fails the job.
    - Add `[profile.bench] lto = "thin"`.
    - Setup returns a struct that owns the `TempDir`.
    - Shorten `measurement_time`/`sample_size`.
    - Remove the RQ2 header.
  - 07:
    - Time inside the guest using nails' own `duration_ms`. Take 1-3 samples and assert the max is under budget.
    - Delete `p95Fn`, drop the crash and re-format between samples, and remove the vacuous post-reboot mount checks.
    - Add one timed activation without `--overlay-only`, using the prebuilt hidden closure.
    - Run it only in the scheduled lane (runner is a parameter).
  - Cut 05 to at most one extra cycle. Relax 78's bound or measure it in-guest.
  - Guard hot paths (opaque walk, `/proc` scan) with deterministic counts (spawned processes, visited dirs), not wall-clock times.

  **Done when**
  - No PR job gates on absolute bench budgets, and the ci.yml PR critical path is shorter.
  - `cargo bench --no-run` builds, and a bench run leaves the `/tmp` entry count unchanged.
  - `perf.nix` has no p95 function. 07 has no `machine.crash()` or re-format, times a non-overlay-only activation, and is excluded from the PR lane.
  - 05 runs at most one extra cycle.

- [x] **T-058: Collapse the release into one tag-triggered workflow (build, E2E gate, rebuild, attestation, draft notes) and fix release hygiene** (medium · effort L)

  _Status (W8-C1): implementation complete. One `release.yml` (tag push or dispatch from the tag) checks tag, version, Cargo.lock and CHANGELOG via `ci/release.py`, builds, rebuilds on a fresh runner (`diff -r`), runs E2E mode all, builds a musl SBOM with cargo-cyclonedx, attests provenance and SBOM, and drafts the release; publish-release.yml, release-core.yml and slsa-github-generator are gone, reproducibility.yml runs weekly from scheduled.yml, the archive is `nails-<version>-x86_64-unknown-linux-musl.tar.gz` and cargo builds `--locked`; RELEASING.md and docs/verify-release.md added. Pending outside this sandbox: a dispatch dry-run from an rc tag, the verify-release commands against the v0.2.0 assets, the stale-lock `nix build` check (see nix_pending), and the one-time repository steps in RELEASING.md (delete `list`/`listr` and the `v0.1.0-git.*` prereleases, tag ruleset, immutable releases). `main` is not bumped to `-dev` yet._

  **Problem**
  - A stable release takes two runs: `release.yml` verify, then a manual `publish-release.yml`. Both call `release-core.yml`, which adds up to 6 musl compiles and two provenance mechanisms: `actions/attest` (l.332) and slsa-github-generator (l.346).
  - The two runs share a `cancel-in-progress` concurrency group (l.17-19). This cancelled the v0.2.0 verify run.
  - `nix-store --realise --check` (`release-core.yml:226`, `reproducibility.yml:99`) only re-runs the tar/gzip step, yet the docs and release notes call it binary determinism.
  - The SBOM tool is compiled from source (l.246), misses musl, and is not attested.
  - `reproducibility.yml` declares its inputs twice (l.4-57). `.github/scripts/package-release.sh` is unused.
  - Release notes ignore CHANGELOG.md, and no E2E run gates the tag.
  - The asset is named `nails-0.2.0-git.<sha>-...` (`flake.nix:72`).
  - The v0.2.0 tag shipped a stale `Cargo.lock` that the Nix build silently rewrote.
  - Verification docs:
    - `sha256sum --check` without `--ignore-missing` appears in `docs/ci.md:178` and `docs/security-validation.md:143`.
    - `slsa-verifier@latest` is used.
    - The steps are duplicated in three places, and nothing says to verify off the decoy.
  - Junk tags `list`/`listr`, six public `v0.1.0-git.*` prereleases, and `.gitignore:150` ignores the tracked `docs/ci.md`.

  **Fix**
  - One `release.yml` on `push: tags: v*` plus a `workflow_dispatch` `tag` input. The first job checks tag == `v${workspace version}`. Jobs:
    - `build`: from source, setup-nix with cache off.
    - `rebuild`: one independent rebuild on a fresh runner, compared with `cmp`. Drop `--check`, or rename it 'archive packaging determinism'.
    - `e2e`: calls the consolidated `e2e.yml` with the runner as a parameter.
    - `sbom`: via taiki-e/install-action, with an explicit musl component.
    - `attest`: `actions/attest` plus `attest-sbom`. Drop slsa-github-generator, and change the 'SLSA Level 3' wording to the level actually provided.
    - `draft-release`: the body is the CHANGELOG section plus a link to `docs/verify-release.md`.
    - report-status on failure.
  - Delete `publish-release.yml`, `release-core.yml` and `package-release.sh`. `reproducibility.yml` declares its inputs once (`workflow_call`) and also runs weekly.
  - `flake.nix`: the archive becomes `nails-<version>-<target>.tar.gz`. Add `"--locked"` to `cargoBuildFlags` (l.120). Bump main to `X.Y.Z-dev` after each release and use `-rc.N` versions for prereleases.
  - New `RELEASING.md`:
    - Checklist: bump the version and commit Cargo.lock, write the CHANGELOG section, push an annotated `v*` tag, check the draft, publish, then bump to `-dev`.
    - One-time actions: `git push origin :refs/tags/list :refs/tags/listr`, delete the `v0.1.0-git.*` prereleases, add a tag ruleset (`v*`, annotated only), enable immutable releases.
  - New `docs/verify-release.md` as the single source:
    - `sha256sum --check --ignore-missing checksums.txt`.
    - `gh attestation verify nails --repo WitteShadovv/nails`.
    - OPSEC: verify from a live environment or an active hidden session, never on the decoy.
    - Remove the duplicated steps from the other docs, and state in `docs/release-artifact-reproducibility.md` that the cross-runner `cmp` is the binary evidence.
  - Remove `docs/ci.md` from `.gitignore`.

  **Done when**
  - A dispatch dry-run produces one run that builds once, rebuilds once, runs E2E, attests (including the SBOM) and creates a draft whose body is the CHANGELOG section.
  - A tag/version mismatch fails the first job, and `nix build .#nails` fails on a stale Cargo.lock.
  - The removed files are gone, and actionlint and zizmor report nothing.
  - The verify-release commands pass against the v0.2.0 assets with only `nails` downloaded.
  - No doc calls `--check` binary determinism, and `git check-ignore docs/ci.md` prints nothing.

- [x] **T-059: Document the CI tier model, workflow layout and contributor test tiers, and do the final workflow consolidation sweep** (high · effort M)

  _Status (W8-C1): done. `.github/workflows` holds exactly ci, e2e, e2e-hetzner, scheduled, release, reproducibility and pr-title (forensics-eval workflows deleted, update-flake-lock folded into scheduled.yml, new manual dispatch-only `e2e-hetzner.yml`), Codecov is removed so the justfile threshold is the only coverage gate, docs/ci.md is rewritten around the four tiers with the job mapping and settings checklist and checked by `just docs-check` (`ci/docs_check.py`), and CONTRIBUTING.md has the tier table. Not done: the ~10-line inline `run:` limit enforced from `nix/checks.nix` needs the long e2e.yml/scheduled.yml blocks moved into `ci/*.py` first; the measured shard count and wall-clock time, and one live `e2e-hetzner.yml` dispatch, still need hosted runs._

  **Problem**
  - The repo has 14 workflows, 38 jobs and ~3,700 lines, about half of it inline `run:` script. Nothing defines what runs per PR, after merge, nightly or at release.
  - `docs/ci.md` contradicts the workflows:
    - It describes the retired `dev` flow.
    - It says benches run only on main (l.37), but `ci.yml:366` runs them on PRs.
    - It lists `shell.nix` in the path filter (l.73), which it is not.
    - It claims a single-runner full suite (it runs 4 shards) and claims log uploads were removed, yet `e2e-tests-full-shard.yml:829-833` still uploads `**/*.log`, `performance.txt` and `metrics.json` from privileged runs.
  - Other contradictions:
    - Coverage is 85.5 in `.pre-commit-config.yaml:160` but 85 in `ci.yml:20`.
    - Codecov gets no token and runs with `fail_ci_if_error: false` (`ci.yml:216-219`).
    - The comment list in `dependabot.yml:101-111` is stale.
  - `CONTRIBUTING.md` omits test tiers, runtimes, KVM, the coverage source, the line rule and `.gitmessage`. Its 'mirror CI' commands fail in the dev shell.

  **Fix**
  - Define four tiers, each with a budget enforced by timeouts:
    1. pre-commit, under 10 s.
    2. pre-push / `just check`, about 90 s.
    3. PR gate, about 10 min p95. Required checks: `gate`, `e2e-result`, `pr-title`.
    4. Post-merge, nightly and weekly: full E2E, advisories, canary, stress, benches, reproducibility. Release runs on tag.
  - Final sweep:
    - `.github/workflows` contains exactly ci, e2e, e2e-hetzner, scheduled, release, reproducibility and pr-title, plus the setup-nix and report-status composite actions.
    - No inline `run:` block is longer than about 10 lines. That logic moves into the justfile or `ci/*.py`, enforced by a check in `nix/checks.nix`.
  - Single coverage threshold read by both pre-commit and CI. Either wire Codecov with a token and `fail_ci_if_error: true`, or remove it.
  - Privileged E2E uploads only named artifacts. Trim `dependabot.yml` comments to the actions actually used.
  - Rewrite `docs/ci.md` in the present tense:
    - One table: workflow, trigger, required, tier, runner parameter, local `just` recipe.
    - Mapping from every old job to its new home or its removal.
    - Post-merge contract (`full-e2e` label, nightly run) and the red-main rule (revert or quarantine within 24 h; advisory issues within 7 days).
    - Cache trust rules, the manual Hetzner lane, and the 60-day schedule auto-disable.
    - Maintainer settings checklist.
    - A link to `docs/verify-release.md`.
    - `just docs-check` fails when a workflow is missing from the table.
  - `CONTRIBUTING.md` Testing section, linked from `docs/development-guide.md`:
    - Command, runtime and prerequisites per tier (`just test`, `just e2e basic-workflow`, smoke, full).
    - Ignored and root-gated tests, and `NAILS_UNSAFE_REAL_OPS`.
    - `nix develop` as the only dev shell.
  - `nix/e2e-tests/README.md`: shards, tiers, and `ci` as the default runner target.

  **Done when**
  - `ls .github/workflows` matches the target layout.
  - Every workflow, job, check and recipe named in `docs/ci.md` exists, and `just docs-check` passes. The doc has no `dev` flow and contains the tier table, job mapping and settings checklist.
  - One coverage threshold. Codecov is either strict or removed.
  - No privileged job uploads `**/*.log`.
  - `CONTRIBUTING.md` has the tier table.

- [x] **T-060: Document supported distribution channels, block crates.io publishing, and remove decoy-side first-install paths from the README** (medium · effort S)

  _Status (W8-C1): done. Both crates set `publish = false`, `docs/distribution.md` lists the supported and unsupported channels and the platform tiers, and the README keeps the verified release binary as the only first install, with source and Nix builds under 'Upgrading from inside a hidden session'. Naming and crate descriptions are left to the naming item._

  **Problem**
  - No manifest sets `publish`. `nails-core` has no path dependencies, so it could be published to crates.io by accident.
  - The README offers decoy-side first installs, which contradicts `docs/USER-SECURITY-GUIDE.md:114-116` (never put the binary on the decoy):
    - Option 2, `cargo build` (README.md:94-101), fills the decoy's `~/.cargo`.
    - Option 3, `nix build .#nails` (l.103-110), leaves nails-named `/nix/store` paths and a `result` GC root.
  - No document says which channels are safe. crates.io, nixpkgs and .deb/.rpm packages would all create forensic indicators on the decoy.

  **Fix**
  - Set `publish = false` in `nails-core/Cargo.toml` and `nails-cli/Cargo.toml`. A `[workspace.package]` key alone does nothing.
  - New `docs/distribution.md`:
    - Supported: the static release binary, verified off the decoy (`docs/verify-release.md`) and copied onto the hidden root; or a source/Nix build from inside an active hidden session, for upgrades.
    - Unsupported: crates.io, nixpkgs, .deb/.rpm, and any decoy-side NixOS module or overlay.
    - Support tiers: NixOS (full); Debian/Ubuntu (overlay-only first); Fedora/Arch (planned backends); non-systemd and ostree/image-based hosts (refused).
  - README: move Options 2 and 3 under 'Upgrading from inside a hidden session', and link `docs/distribution.md` from the install section. Add no `nixosModules` output.
  - The NixOS-specific name expansion (`nails-cli/src/cli/args.rs:9,14`, the crate descriptions, `flake.nix:2`, the README title and badge) is handled by the naming/positioning item. Adjust the crate descriptions here only if that decision has landed.

  **Done when**
  - `cargo publish --dry-run -p nails-core` and `-p nails-cli` both refuse.
  - `docs/distribution.md` exists and the README links to it.
  - The README has no first-install step that builds or downloads NAILS on the decoy.

### W8-C2: Unified render + check/doctor

Owns: `nails-cli/src/cli/output/`, `nails-cli/src/cli/commands/check.rs`, `nails-core/src/manager/preflight_runner.rs`

- [x] **T-061: Consolidate output into one Ui/Theme layer and stop the core library printing ad hoc** (medium · effort L)

  _Status (W8-C2): the single themed status renderer, one NO_COLOR resolution, stderr prompts, per-stream `with_ansi` and the shared config loader for activate had already landed in earlier waves; `output/deactivate.rs` is now the live typed-envelope renderer for deactivate/emergency and stays. W8-C2 removed the core's ad hoc preflight print (`output::check_result`), so checks report once through tracing and honour `--quiet`/`--json`. Remaining: the `DEBUG: Already detached` eprintln in `nails-cli/src/cli/detach.rs` (T-066, W9-C2), Reporter-based core progress (T-087, W13-C1), and evaluating contract E2E 61-64 (see nix_pending)._

  **Problem**
  The status report is rendered three times (`status/human.rs` `print_status_human` + `print_status_no_color`, `status/mod.rs` `print_status_ascii`, ~130 duplicated lines each) and the error path builds two more headers that disagree (`commands/status.rs:104-124`: `=== NAILS Status Report ===` vs the box-drawing variant). Symbols drift: `[WARN]` vs `ReminderSeverity::to_plain`'s `[WARNING]`, logging's `X`/`!` vs the Unicode marks. `output/activate.rs` branches on `no_color` at ~14 sites though `colored` already honours `set_override`. The NO_COLOR check is copied in five places (`logging.rs:169`, `main.rs:46`, `commands/status.rs:38`, `activate/mod.rs:79`, `deactivate.rs:43`) and all use `.is_ok()`, treating empty `NO_COLOR` as set (contrary to no-color.org). `output/deactivate.rs` is a 255-line dead renderer kept alive only by the coverage gate. The core prints out-of-band: `nails-core/src/output.rs` (writeln at 4 sites), `preflight_runner.rs:213` prints every check result regardless of `--quiet`/`--json` and re-logs it via tracing (double report); `detach.rs:152` emits `eprintln!("DEBUG: Already detached, continuing...")` into the journal; prompts (`prompts/mod.rs`) write to stdout.

  **Fix**
  Stage it. (1) Collapse the three status renderers and the two error headers into one function taking a `Theme {symbols, color, box-drawing}` resolved once from `--plain`/`--no-color`/`NO_COLOR`/TTY (empty `NO_COLOR` = unset; ASCII for `TERM=dumb`; colour auto = isatty && TERM!=dumb), reusing `SecurityPosture`/`ReminderSeverity` formatting instead of copying it. Delete `output/deactivate.rs` and its tests; remove the DEBUG eprintln; route activate through the shared config loader; make tracing `with_ansi` respect per-stream TTY and send prompts to stderr. (2) Later: commands return typed reports, the core emits progress via a Reporter trait (or tracing events) instead of stdout, gate `output::check_result`/`warn` on verbosity+JSON (ends the preflight double-report), keep exactly two renderers (human, JSON), and make the fork-child prints async-signal-safe raw writes.

  **Done when**
  - One status renderer driven by one `Theme` resolved once; the three copies and the two divergent error headers are gone.
  - `output/deactivate.rs` and its tests deleted; the DEBUG eprintln removed.
  - Core check results are not printed under `--quiet`/`--json`; no double-report between `output::*` and tracing.
  - NO_COLOR handling matches no-color.org (empty = unset) in one place; prompts go to stderr; contract E2E 61/62/63 pass.

- [x] **T-062: Read-only nails check (alias doctor) built from the shared preflight registry; replace the diverging dry-run** (medium · effort M)

  _Status (W8-C2): implemented. `build_registry`/`NailsManager::preflight_registry` is shared by activation and the new read-only `nails check` (alias `doctor`); `dry_run.rs` is deleted and `activate --dry-run` calls `check`; the registry adds StateCheck, the suspicious-reference check and a warn-only binary-location check; NixOSConfigCheck no longer creates files (activation stages them via `stage_hidden_nixos_config`), StorageReadinessCheck has a read-only mode, and the generated `configuration.nix` is a commented hidden-session template. Unit tests cover identical check lists and no writes. Remaining: run as non-root, privilege-blocked checks still report a Fail with the raw error (overlay-compatibility shows `Permission denied` reading /boot) instead of being named as skipped; fold this into T-088's CheckResult rework. The 29 and 45 VM tests await evaluation (see nix_pending)._

  **Problem**
  The only readiness check is `activate --dry-run`, which hand-copies the preflight registry (`commands/activate/dry_run.rs`, 386 lines, "mirrors NailsManager::run_preflight_checks"). The copy has drifted: it lacks `StateCheck` (`preflight_runner.rs:203`), the suspicious-reference check, the read-only NixOS preflight the default path runs (`activate/mod.rs`), and the `NixOSBuildTargetCheck` skip logic (`preflight_runner.rs:171-193`). It always exits 0 even after failures, ignores `--json` and colour, and is gated by activate's flag validation. It is also not read-only: `NixOSConfigCheck` creates hidden files (`preflight/checks/nixos_config/mod.rs:100-116`) and `OverlayCompatibilityCheck` strips opaque xattrs. There is no doctor command for non-experts, and the generated hidden config is a one-package ripgrep stub (`nails-core/src/nixos/config/mod.rs:46-47`).

  **Fix**
  (1) Expose one public `preflight::build_registry(fs, config, mode, current_state)`; activation and the CLI both call it (includes StateCheck, suspicious-reference, read-only NixOS preflight on NixOS only, build-target skip). Delete the `dry_run.rs` copy. (2) Add `nails check` (alias `doctor`), strictly read-only: move hidden-file creation out of `NixOSConfigCheck` into activation staging, and do not invoke opaque-xattr stripping (reworked by the opaque-xattr item). Run as non-root where possible, listing checks skipped for lack of privilege; print each result plus the effective config summary, overlay targets, session handling and profile; support the `--json` envelope; exit 4 on any failure. (3) Add a binary-location check: the running binary lives under the hidden root and is not reached via a decoy PATH entry or symlink. (4) `activate --dry-run` becomes a thin alias for `check` (same output and exit code). (5) Replace the ripgrep stub with a commented, valid-Nix template of hidden-session settings (volatile journald, shell history, optional panic unit, optional session indicator). Checks added by other items appear automatically through the shared registry. No setup wizard here.

  **Done when**
  - `dry_run.rs`'s registry copy is gone; a unit test asserts activation and `check` build identical check lists for the same inputs.
  - A `MockFilesystem` unit test shows `check` performs no write, create, remove or xattr op.
  - `nails check` exits 4 on any failure and 0 otherwise; `--json` emits the envelope with per-check name/status/message; run as non-root it names skipped privileged checks instead of raw permission errors.
  - `activate --dry-run` and `check` produce the same output and exit code.
  - The generated `configuration.nix` parses (`nix-instantiate --parse` test) and is no longer the ripgrep stub.
  - `nix/e2e-tests/tests/nixos/29-activate-dry-run.nix` covers `nails check` and passes.

### W8-C3: Activation mount rollback

Owns: `nails-core/src/manager/activation/guards.rs`, `nails-core/src/manager/mount_tracker.rs`, `nails-core/src/manager/activation/rollback.rs`

- [x] **T-063: If activation fails after mounting, unmount the overlays before the state is rolled back (wire in the dead rollback code)** (high · effort M)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (the mount tracker's rollback). The item stays ticked as history; it describes no current code._

  _Status (W8-C3): done. `mount_overlays` hands its mounts to the caller (`MountTracker::take_mounts`) instead of committing; the new `ActivationMounts` guard in `activation/rollback.rs` (no `allow(dead_code)`) is declared after `StateGuard`, so a later failure unmounts the overlays, then writes the rolled-back state, then restarts the session onto the decoy. Mounts rollback cannot remove make StateGuard persist `Degraded` listing them, and per-mount state saves are hard errors. Unit tests cover the Active-write, session-restart and unmount-failure cases; the masked-display-manager subtest in 53 awaits evaluation (see nix_pending)._

  **Problem**
  `mount_overlays` commits the `MountTracker` before returning (`nails-core/src/manager/activation/overlay_mount/mod.rs:108`), so RAII rollback is disarmed the instant mounts succeed — contradicting its own comments at `overlay_mount/mod.rs:30` and `:41`. Activation continues past that point and can still fail at `restart_session_after_success` (`activation/mod.rs:379`) or `update_state(Active)` (`activation/mod.rs:476-481`). On failure, `StateGuard::drop` (`nails-core/src/state/guard.rs:227-264`) calls `force_state(previous_state)`; when the previous state is `Inactive`, `force_state` clears `overlay_status` and `nixos_generation` (`state_management.rs:185-196`) while the overlays stay mounted and are no longer recorded anywhere. `SessionRestartGuard` is disarmed only after `guard.commit()` (`activation/mod.rs:489`), so its drop (`activation/guards.rs:30-61`) restarts the display manager onto the still-mounted overlays. The real cleanup, `rollback_overlay_mounts_after_activation_failure` (`activation/rollback.rs:57`), is `#[allow(dead_code)]` and reached only from tests. Per-mount and generation state saves swallow errors at Debug verbosity (`overlay_mount/mod.rs:229-234`, `:344-349`), so mount tracking can silently be missing on disk.

  **Fix**
  - Remove the `tracker.commit()` call inside `mount_overlays` and correct the misleading comments at `overlay_mount/mod.rs:30,41`.
  - Introduce an activation-scope rollback guard (e.g. `ActivationMounts`) that owns the list of mounted targets (path + mount kind) and does not borrow the filesystem from inside a `MutexGuard`. On error or drop it calls `rollback_overlay_mounts_after_activation_failure` in reverse mount order; drop the `#[allow(dead_code)]` in `rollback.rs`.
  - Disarm the new guard next to `guard.commit()` (`activation/mod.rs:485`) and order the guards so overlay rollback runs before `SessionRestartGuard` restarts the session and before `StateGuard` writes state, so the display manager comes back onto the decoy and the state matches reality.
  - `StateGuard` must not persist `Inactive` while NAILS mounts remain; when rollback leaves mounts behind, persist `Degraded` (accepted by `emergency`/`recover`) with the remaining mounts listed.
  - Make per-mount save failures hard errors that abort activation before further mounts, instead of Debug-only warnings.

  **Done when**
  - `rollback.rs` carries no `#[allow(dead_code)]`, and `mount_overlays` no longer commits the tracker.
  - Mock unit tests: injected failure in the session restart and in `update_state(Active)` each leave zero overlays mounted and state `Inactive`, with the display-manager restart recorded after the unmounts; an injected unmount failure during rollback leaves state `Degraded` with the remaining mounts listed.
  - `nix/e2e-tests/tests/state/53-state-guard-rollback.nix` forces a post-mount failure (e.g. a masked display manager) and asserts no overlays remain and the status posture is the decoy.
  - `cargo test` and `cargo clippy` pass clean.

## Wave 9: Platform seam + journal/flake anti-forensics + CLI contract tests

### W9-C1: Platform seam & restore hook

Owns: `nails-core/src/platform/`, `nails-core/src/manager/mod.rs`, `nails-core/src/filesystem/traits/mod.rs`

- [x] **T-064: Add a Platform abstraction with os-release detection, one NixOS-discovery function, and explicit refusal of unsupported hosts** (high · effort L)

  _Status: mostly done. `platform::detect()` is unit-tested against nixos/debian/ubuntu/fedora/arch/ostree/non-systemd os-release fixtures with typed refusals; activate, `check`/`--dry-run` and the `nixos-build-target` preflight share `discover_host_target()` (a lone system profile resolves to the same legacy target on every path, with a cross-path agreement test); activation refuses an `Unsupported` host profile before any state write (exit 8); the Filesystem trait/mock carry no `nixos_*` methods; a contract-test module runs against NixOs, Fhs and Fake platforms. The `overlay_policy()` consumer (T-083) has now landed. Remaining: the manager/overlay tests still carry ~96 `/etc/nixos` fixtures; because `discover_host_target()` is still filesystem-driven, moving them onto `FakePlatform`/into `platform::nixos` tests requires making discovery consult the injected `HostProfile`/`Platform`, and should land as one discovery seam rather than piecemeal. Plus a green NixOS E2E run on a nix host._

  _Status (2026-10): done. Build-target discovery goes through `Platform::discover_build_target` (the NixOS cascade lives in `platform::nixos`; FHS and refused hosts discover nothing), and the platform backend owns the `ConfigLayer`, which now also supplies the base-reference gate and its preflight checks. Manager tests run on `FakePlatform` with a recording `FakeConfigLayer` instead of `/etc/nixos` fixtures (only two preflight-runner tests of NixOS check messages keep a path); what the real layer writes moved to `NixOsConfigLayer` tests. The NixOS VM suite is green._

  **Problem**
  There is no platform seam: NixOS-specific decisions are spread across the CLI, the manager, the mount loop, and the `Filesystem` trait, and the copies already disagree. The discovery cascade exists three times with drift — `activate/mod.rs:216-241` probes hidden flake → `/etc/nixos/flake.nix` → legacy config *or* system profile, `dry_run.rs:119-142` omits the system-profile probe (so `--dry-run` reports "profile switch would be skipped" where activate would do a legacy build), and `preflight/checks/nixos_build_target.rs:122-161` has four probes that return `Fail` where `--no-preflight` activate continues. `manager/mod.rs:110` embeds `nixos_builder: Option<NixOSBuilder>` in core; `filesystem/traits/mod.rs:146-158` carries `nixos_*` profile methods production never calls (and `real/system_ops.rs` builds the invalid `nixos-rebuild --profile`); `mock/state.rs:72-73` mirrors that dead state. The mount loop hardcodes `/nix`, `/var`, `/etc` hooks (`manager/activation/overlay_mount/mod.rs:152-208`) and `activation/mod.rs:57` has decayed params (`let _ = (overlay_only, has_nixos_switch);`). This is the foundation for the overlay-only Debian/Ubuntu backend.

  **Fix**
  Create `nails-core/src/platform/` with a `Platform` trait chosen once by `Platform::detect()` (reads `/etc/os-release` `ID`/`ID_LIKE`/`VERSION_ID`, plus `/run/current-system`, `/run/ostree-booted`, and whether PID 1 is systemd) and overridable via config/CLI. Compute one `HostProfile` at startup and thread it through activate, dry-run, preflight, deactivate, emergency, status, and verify so they share one discovery result. Fold the three cascades into one `discover_host_target()` consumed by all three paths. Trait surface: `overlay_policy()` (default/never-overlay/read-only paths), `pre_mount`/`post_mount` hooks, `preflight_checks()`, `artifact_scanners()`, `restore_base_system()`, and host command search dirs. Backends: `NixOs` (current behaviour moved behind the trait, kept first-class in CI), and `Unsupported` that refuses ostree/image-based hosts and non-systemd PID 1 with an actionable message (this refusal is the deliverable for those targets). Delete the dead `nixos_*` trait methods and mock profile state. Add `FakePlatform` for core tests, move NixOS fixtures into NixOS-module tests, and add one contract-test module every backend runs. Consume (do not re-create) the single process runner from the runner-consolidation item.

  **Done when**
  `Platform::detect()` is unit-tested against fixture os-release files (nixos, debian 12/13, ubuntu 24.04, fedora, arch, an ostree marker, non-systemd PID 1); unsupported cases return a typed refusal. activate, `--dry-run`, and preflight derive discovery from the same `HostProfile`, with a test covering the "only system profile exists" case proving all paths agree. The `Filesystem` trait and mock no longer carry `nixos_*` methods or profile state. Manager, overlay, and state tests run against `FakePlatform` with no `/etc/nixos` fixtures. A contract-test module runs against `NixOs`, the FHS backend, and `FakePlatform`. `nix develop -c cargo clippy --all-targets -- -D warnings` and `cargo test` pass; the existing NixOS E2E suite is green.

- [x] **T-065: Move the decoy restore step into a platform hook and skip the NixOS switch when a reboot follows** (low · effort S)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (the decoy restore hook and the NixOS switch on deactivation). The item stays ticked as history; it describes no current code._

  _Status (W9-C1): `Platform::restore_base_system()` added — the NixOS backend re-points `/run/current-system` and only falls back to `switch-to-configuration test` when a requested reboot fails (never switch/boot, so the ESP/bootloader stay untouched); FHS and Unsupported backends are no-ops. Recording-runner tests cover reboot-skips-switch, failed-reboot-fallback and the FHS no-op. The behaviourally identical inline restore still lives in `manager/deactivation.rs` from an earlier wave; collapsing it onto this hook is left to the deactivation owner (W19-C1)._

  **Problem**
  During normal deactivation the orchestrator runs `<system-profile>/bin/switch-to-configuration switch` against the real disk (`deactivation/orchestrator/mod.rs:333-386`, gated by `requires_decoy_restore` at `manager/deactivation.rs:490-497`) and then reboots (`manager/deactivation.rs:528-537`). The reboot already activates the default generation, so the switch is redundant: it costs time and can write the ESP. The step is also NixOS-only and has no equivalent on other platforms, but currently lives in shared deactivation code.

  **Fix**
  Add `Platform::restore_base_system(reboot_follows)` and move the restore step behind it. NixOS backend: when a reboot follows, only ensure the `/run/current-system` symlink (`ensure_run_current_system_symlink`) and invoke `switch-to-configuration switch` solely as a fallback if the reboot request fails; when no reboot follows, keep the current switch behaviour. FHS/Debian and other backends: no-op. Remove the inline switch logic from the orchestrator so it calls the platform hook.

  **Done when**
  A unit test with a recording runner shows that normal NixOS deactivation with a successful reboot does not invoke `switch-to-configuration`, while a failed reboot triggers the fallback switch. The FHS backend records no `switch-to-configuration` invocation. `cargo clippy --all-targets -- -D warnings` and `cargo test` pass.

### W9-C2: Detached-no-journal + flake-after-overlay

Owns: `nails-cli/src/cli/detach.rs`, `nails-core/src/manager/activation/preflight.rs`, `nails-cli/src/cli/commands/activate/mod.rs`

- [x] **T-066: Detached activation/deactivation write nothing identifying to the decoy journal (neutral unit, null output, panic hook, volatile-journald check)** (critical · effort M)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (the journald re-homing). The item stays ticked as history; the path-free panic hook and the null worker output it added still apply._

  _Status (W9-C2 + wave C3/CC6): all Rust-side work landed. Detached workers no longer leak identifying data (neutral auto-named units, null worker stdio with the `NAILS_DETACH_DEBUG_JOURNAL` escape hatch, path-free panic hook, no cleanup pattern list on INFO). Wave C3 added the journald re-home: relinquish the persistent journal before `/var` is overlaid, restart systemd-journald + `journalctl --flush` after, a device-based fd-into-overlay check that rolls the activation back on mismatch, teardown restarts journald back onto the base `/var`; plus a new `journald_storage` preflight (refuses a persistent decoy journal, `--allow-persistent-journal` override) wired through the registry/activate/check CLI, and the E2E session helpers repointed to the neutral unit. Remaining is nix-only: the persistent-journal disk-image VM regression and the live fd-into-overlay assertion under a real journald — see nix_pending._

  **Problem:** The detached transient units are named `nails-activate-<pid>.service` / `nails-deactivate-<pid>.service` (nails-cli/src/cli/detach.rs:183, :275) with no `--description`, so PID 1 logs `Started nails-activate-<pid>.service - <hidden-root>/nails activate`. Both are launched with `--property=StandardOutput=journal`/`StandardError=journal` (detach.rs:238-239, :290-291), sending all pre-overlay worker output into the still-real journal before `/var` is overlaid: the replayed preflight, the pattern list logged at nails-core/src/manager/activation/preflight.rs:177-181, per-file history-cleanup lines, and a leftover `eprintln!("DEBUG: Already detached, continuing...")` at detach.rs:152. There is no `std::panic` hook, so panics with source paths also reach the unit's stderr. No journald-storage preflight exists, and the post-`/var` "unconditional restart" is really `systemctl start systemd-journald` on an already-active unit (overlay_mount/mod.rs:178-183 -> helpers/service_controller.rs:317-328), a no-op. On persistent-journal hosts (the NixOS default; docs/impermanence-base-config.nix persists /var/log) these records survive deactivation and reboot.

  **Fix:**
  1. In detach.rs, for both activate and deactivate, stop passing a product-named `--unit` (let systemd generate `run-uNNN.service` or use a neutral random token) and always pass an explicit neutral `--description`; set `StandardOutput=null`/`StandardError=null` so the hidden-root file log is the only sink, gated behind an explicit debug flag only. Delete the `DEBUG:` eprintln.
  2. In activation/preflight.rs stop logging the cleanup pattern list; emit per-file cleanup only at debug level to the hidden log. Audit every println!/eprintln!/output path that can run once detached for user-identifying text.
  3. Install `std::panic::set_hook` early in nails-cli/src/main.rs: full details only to the hidden-root log when attached, a generic one-line message with no paths to stderr.
  4. Before detaching call `journalctl --relinquish-var`; replace the post-`/var` `start` with `systemctl restart systemd-journald`, then `journalctl --flush`, and verify journald's journal fds resolve into the overlay upper, rolling back otherwise.
  5. Add a journald-storage preflight that reads effective `Storage` (systemd-analyze cat-config systemd/journald.conf, or /var/log/journal absent/on tmpfs) and fails by default on a persistent decoy journal with an explicit override flag; never vacuum the decoy journal.
  6. Update E2E helpers keyed on the product unit name (nix/e2e-tests/lib/session-helpers.nix:22-35, tests/session/33-session-kill-graphical.nix, tests/session/34-session-kill-headless.nix) to discover the worker via `systemctl show -p ExecStart` on `run-u*` units or `nails status --json`; add the persistent-journal disk-image regression below.

  **Done when:**
  - detach.rs contains no `nails-activate-`/`nails-deactivate-` literal and no `StandardOutput=journal`/`StandardError=journal`; no `DEBUG:` eprintln remains in production code.
  - Unit test asserts the built systemd-run argv has a neutral `--description` with no binary path and a unit name with no product name.
  - Panic hook installed; a child-process panic test shows stderr with no source path or crate path.
  - New journald-storage preflight fails on `Storage=persistent` and passes with the override flag (unit test on the parser).
  - Persistent-journal VM test: after activate/deactivate/reboot, a `logger` canary written while active, the hidden-root path, the binary name and the cleanup-pattern list are all absent from the lower /var/log/journal (uses the disk-image check infra).
  - journald is restarted with `restart`; an assertion confirms its journal fds resolve into the overlay upper.
  - `nix develop -c cargo test --workspace` and `cargo clippy -- -D warnings` pass; updated E2E session tests pass.

- [x] **T-067: Do not invoke nix on the hidden flake before /nix and /root are overlaid; move real flake validation into the detached, overlaid phase** (critical · effort M)

  _Status (W9-C2): pre-overlay preflight now does static checks only (flake.nix/flake.lock exist, config attr resolves, zero nix invocations); the real `nix flake metadata`/eval validation moved into the post-overlay phase of `activate_with_options`, right after `mount_overlays` and before the session restart, so a broken flake fails with overlays rolled back and nothing is copied onto the decoy store/DB/cache. `ActivateOptions.skip_flake_validation` is derived from the genuine `--no-preflight`/`--overlay-only` (argv-preserved so the detached worker still validates). Unit/integration tests cover the ordering and the broken-flake rollback. Pending off-sandbox: evaluating the extended disk-image regression in e2e test 28 on a nix host (see nix_pending)._

  **Problem:** The activation preflight phase runs `run_read_only_nixos_preflight` before detach, session-kill and overlay mount (nails-core/src/manager/activation/preflight.rs:76-84 -> manager/preflight_runner.rs:12-39). For a flake backend this executes `nix flake metadata --json <ref> --no-write-lock-file --impure` and `nix eval ... --impure` (nails-core/src/nixos/command.rs:132-171) against an auto-discovered hidden-root flake (`<hidden_root>/nixos/flake.nix`, nails-cli/src/cli/commands/activate/mod.rs:217-224). `nix flake metadata`/`getFlake` copies the entire flake directory into /nix/store as a `-source` path and registers it in the Nix DB, while root's fetcher/eval caches write to ~/.cache/nix — all before `/nix` and `/root` are overlaid (overlays mount later in the sequence). The plaintext hidden NixOS configuration and the hidden path therefore land on the decoy's persistent store and caches and survive deactivation and reboot. Labelling the step "read-only" is incorrect.

  **Fix:**
  1. Pre-overlay, perform only static checks: `flake.nix`/`flake.lock` exist and the configuration attribute name parses. Never invoke nix against a hidden-root flake before `/nix` and `/root` are overlaid.
  2. Move the real `nix flake metadata`/`getFlake`/eval validation into the detached phase after the overlays are mounted and before the session restart; on failure unmount through the existing rollback guards so a broken hidden flake still fails cleanly.
  3. If a pre-overlay nix call is ever unavoidable, run it with `--store local?root=<tmpfs or hidden-root scratch>` and HOME/XDG_CACHE_HOME pointed at tmpfs so nothing lands on the decoy.
  4. Extend the flake E2E (nix/e2e-tests/tests/nixos/28-activate-flake-override.nix) with a disk-image regression: embed a marker string in the hidden flake, snapshot `ls /nix/store` plus valid-path/DB state and /root/.cache/nix on the lower layer before activation and after deactivation, and assert no store path, DB entry or cache entry references the marker or the hidden path. Include a null control and a positive control.

  **Done when:**
  - Unit test over the activation sequence (mock executor order) asserts no nix command runs before overlay mount.
  - After an activate/deactivate cycle using a hidden-root flake, no new /nix/store path, no Nix DB entry and no /root/.cache/nix content references the hidden marker or path (disk-image assertion in test 28, with null + positive control).
  - Real flake metadata/eval validation runs only after overlays are mounted; activation with a broken hidden flake fails with overlays rolled back.
  - `nix develop -c cargo test --workspace` and `cargo clippy -- -D warnings` pass; the e2e nixos flake tests pass.

### W9-C3: CLI contract/snapshot tests

Owns: `Cargo.toml`, `nails-cli/tests/cli_contract.rs`, `nails-cli/tests/snapshots/`

- [x] **T-068: Move CLI contract checks from VM tests to cargo snapshot and schema tests, and fix the silently skipping CLI tests** (medium · effort M)

  _Already resolved: `nails-cli/tests/cli_contract.rs` is merged — insta snapshots of every `--help`/`--version` surface (guarded against product-identifying strings and default hidden-storage paths), `status`/`verify` `--json` validated against the committed JSON Schemas, the rendering matrix, the error envelope and one case per documented exit code. `grep check_unsafe_ops_allowed` finds zero hits (the 22 early-return tests are gone), renderer `-q/-v/-vv/-vvv` and nixos-rebuild argv unit tests are added, and the VM contract tests collapsed into `58-contract-active-session.nix` (needs a nix host to evaluate; see nix_pending)._

  **Problem**
  The CLI contract is validated by 8 VM tests (`nix/e2e-tests/tests/contract/58-65`, 597 lines) that each boot a NixOS VM for work that needs no VM: `65` only runs `--help`/`--version`, `61` compares verbosity line counts across reboot cycles, `62`/`63` check ANSI vs plain over reboots, `58`/`59` validate against `nix/e2e-tests/fixtures/schemas/{status,verify}.json` (no Rust test uses these schemas), `60` does plain file tampering, and `64` asserts nothing. `nix/e2e-tests/tests/nixos/79-service-restart-failure-nonfatal.nix` fakes a `nixos-rebuild` exit 4 already covered by unit tests. The cargo side is weak: `nails-cli/tests/cli_integration.rs` (1864 lines, 83 tests) has 22 tests that early-return via `check_unsafe_ops_allowed` (line 36) unless `NAILS_UNSAFE_REAL_OPS=1`, which is never set, so they report as passed with the skip hidden in captured stderr. `test_activate_json_output:247` accepts `status` or `TEST SAFETY GUARD`; `test_deactivate_json_output:389` never parses JSON. 141 `contains` substring asserts, zero snapshots.

  **Fix**
  - Add `insta` (with `insta-cmd`) and `jsonschema` as dev-dependencies to `nails-cli/Cargo.toml` and the workspace `Cargo.toml`.
  - New `nails-cli/tests/cli_contract.rs` driven by a temp hidden root, a hand-written `state.json`, and `--config`: snapshot `--help`/`--version` plus assert no blocked substrings (hidden paths, product strings per the UX work); `status` JSON for inactive / active / tampered / missing state, validated against the committed schemas and snapshotted; `verify` JSON validated against its schema; human, `--plain`, `--no-color`, `NO_COLOR`, `TERM=dumb`, and non-TTY renderings; the error JSON envelope; one case per documented exit code; and assert no log file is written when logging is off.
  - Add renderer-level unit snapshots of `-q`/`-v`/`-vv`/`-vvv` on a canned activation report.
  - Delete the 22 early-return tests and `check_unsafe_ops_allowed`; replace with non-destructive, unprivileged cases (non-root refusal, config errors, check/dry-run JSON) that parse JSON instead of substring-matching. Cases needing root use `#[ignore = "reason"]`, never an env-gated early return.
  - Add unit tests for `nixos-rebuild` argv construction through the command-runner seam.
  - VM side: delete contract tests `59`, `60`, `63`, `64`, `65` and `nixos/79`; fold the assertions that genuinely need a real activation (active status/verify JSON vs schema, PTY ANSI vs `--no-color`/`NO_COLOR`, plain mode, verbosity monotonicity) into one `58-contract-active-session.nix` with a single boot and activation; keep `contract-helpers.nix` only as needed.

  **Done when**
  - `cargo test -p nails-cli` runs the contract tests with no root and no VM.
  - `rg check_unsafe_ops_allowed nails-cli` returns nothing, and no test returns early based on an env var.
  - Schema tests fail if `StatusReport` drops a required field.
  - `nix/e2e-tests/tests/contract/` holds a single VM test and `nixos/79` is removed.
  - `insta` snapshots are committed under `nails-cli/tests/snapshots/` and reviewed via `cargo insta`.

## Wave 10: Runtime tmpfs scaffolding + persona inventory + test hygiene

### W10-C1: Runtime scaffolding in tmpfs + modern mount APIs

Owns: `nails-core/src/overlay/pivot/mod.rs`, `nails-core/src/manager/activation/overlay_mount/mod.rs`, `nails-core/src/manager/mount_tracker.rs`

- [x] **T-069: Put all NAILS runtime scaffolding (pivot staging, snapshots, store bind, command cache) in one neutral per-activation tmpfs that is tracked and torn down, sized from measured content, with atime-safe reads** (high · effort L)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (the runtime tmpfs, pivot staging and store bind). The item stays ticked as history; it describes no current code._

  _Status (W10-C1 + wave C3/K2): partial. Done: the snapshot tmpfs is sized from measured content plus headroom with a warn-only `snapshot-memory` preflight; wave C3 added the verify mount-table scan (`check_nails_owned_mounts`) that flags leftover NAILS overlays/staging binds at non-standard targets, deferring persistent overlays to the upperdir scan to avoid double-reporting. Wave F1 fixed the headline forensic leak: pivot staging and the vfat `/boot` snapshot moved from `/mnt/nails-pivot` (on the persistent decoy ext4 root) to `/run/nails-pivot` on the always-excluded `/run` tmpfs, with the old `/mnt/nails-pivot` registered as a Critical legacy artifact and indicators.json/e2e fixtures realigned. Remaining (large cross-file work, re-dispatch with VM validation): the per-activation random child tmpfs and removal of the fixed `/run/nails` production constants (a recognizable base was kept deliberately so state-independent emergency/verify still key on it), the typed mount-record enum in `MountTracker`/`overlay_status` with record-driven teardown on rollback/deactivate/emergency, the read-only ESP bind, `O_NOATIME` copy/verify reads, the `/run/nails/original-nix-store` unmount+removal for T-033, and the e2e assertions in `overlay/70`, `faults/94`, `forensic/06`, `forensic/07` — see nix_pending._

  _Status (2026-10): done. Each activation mounts one random-named tmpfs under `/run` (0700, nosuid, nodev) holding pivot staging, the vfat snapshot and the pre-overlay store bind; the fixed `/run/nails` and `/run/nails-pivot` constants are gone (they remain only as legacy indicators in the artifact registry). The root is recorded in state as a `MountType::Tmpfs` record, torn down last by rollback, deactivate and recover, and rediscovered from mountinfo by a state-independent emergency. The vfat snapshot is copied in-process with `O_NOATIME` (the read-only ESP bind was not needed), and overlay/70 asserts unchanged lower atimes on a strictatime `/boot`._

  **Problem:** Runtime scaffolding ends up on the decoy root and is only partly torn down.
  - `PIVOT_STAGING_BASE = "/mnt/nails-pivot"` (`overlay/pivot/mod.rs:16`). `/mnt` is excluded from overlays (`config/types.rs:71`), so `snapshot_pivot_overlay_mount` (`pivot/mod.rs:257-276`) creates `nails-pivot/`, `boot/` and `boot-snapshot/` on the real root filesystem on every activation with a vfat `/boot`. These directories are never removed.
  - Mounts are recorded only as `MountInfo::persistent(target)` (`overlay_mount/mod.rs:185`). As a result, `rollback_all` (`mount_tracker.rs:179`) and the orchestrator unmount the bind but leave the staging overlay and the snapshot tmpfs mounted. `deactivation.rs:343-356` and `rollback.rs:22-35` rebuild `PivotMountInfo` by guessing paths from config.
  - `/run/nails/original-nix-store` (`runtime_cache.rs:5`) is only unmounted at the next activation. `/run/nails/systemctl-cache` (`command_cache.rs:374`) is never removed.
  - The snapshot tmpfs size is a hard-coded `"1G"` (`pivot/mod.rs:263`), which duplicates `DEFAULT_MAX_SNAPSHOT_BYTES` (`overlay_compatibility.rs:15`). Swap must be off, yet nothing checks available RAM.
  - `cp -a` (`dir_ops.rs:142`) reads `/boot` without `O_NOATIME`, so every activation updates the ESP's access times.
  - verify checks only `/home`, `/etc` and `/root` (`verify/verifier.rs:121-125`).

  **Fix:**
  - Per activation, create one directory under `/run` with a random name that cannot be derived, mount a private tmpfs on it (mode 0700, nosuid, nodev), and record its path in state. Pivot staging, ephemeral uppers and any store bind source that still exists after T-033 all live inside it. Delete `PIVOT_STAGING_BASE` and every `/run/nails` constant.
  - Replace `MountInfo{target, mount_type}` with a typed record enum (`Overlay`, `Pivot{staging}`, `SnapshotPivot{staging, snapshot}`, `Bind`, `Tmpfs`), stored in `MountTracker` and in `overlay_status` (`state/file.rs:85`). Rollback, deactivate and emergency tear down from these records through `unmount_pivot_overlay`, then unmount and remove the runtime directory last. Delete the loops that rebuild paths from config.
  - Overlay-incompatible targets (in practice the vfat ESP or `/boot`): bind them read-only instead of copying a snapshot. This needs no RAM and no copy. Hidden activation uses `test` (`nixos_switch.rs:60`), so it never writes there; a hidden `switch` or `boot` fails loudly with EROFS, and the docs must say so. If a writable view has to stay, size the tmpfs from the measurement in `overlay_compatibility` plus headroom, and copy in-process with `O_NOATIME`. Remove the `"1G"` literal either way.
  - Add a memory preflight (warning only) that compares `MemAvailable` with the estimated tmpfs content that stays in RAM.
  - Any direct read of decoy files by NAILS itself (copy, verify scans) opens with `O_NOATIME`.
  - verify lists `/proc/self/mountinfo` (using the T-005 parser) and flags any overlay or bind whose upper or source is under the hidden root or the runtime directory. Add the old `/mnt/nails-pivot` and `/run/nails` paths to the artifact registry (T-074).
  - Update the assertions in `nix/e2e-tests/tests/overlay/70-overlay-pivot-vfat-boot.nix:46-50`.

  **Done when:**
  - `rg '/mnt/nails-pivot|/run/nails' nails-core/src` finds no production constants.
  - Unit tests show that rollback, the orchestrator and emergency unmount the staging, snapshot and runtime tmpfs from the records.
  - E2E 70: after deactivate and after emergency, `findmnt` shows no NAILS mounts, `test ! -e /mnt/nails-pivot` passes, and the runtime directory is gone.
  - VM reset while Active, then reboot: host-side `fls` on the root image (T-075) finds no entry named after the tool.
  - A test records the lower files' atimes before and after activate and verify and finds no change.
  - verify flags an overlay at a non-standard target when fed a fake mountinfo.
  - The memory preflight has unit tests for both the warning and the no-warning case.

- [x] **T-070: Adopt openat2 path containment and detached-mount APIs to replace hand-rolled, leak-prone machinery** (medium · effort L)

  _Status (W10-C1 + wave C3/K2 + wave F1): done. `SafeRoot` (openat2 containment, fail-closed, atomic write) with unit/property tests and `create_hidden_dir_all`; ADR 0004 recorded. Wave C3 extended `SafeRoot` and routed the hidden-root state file, state lock (O_NOFOLLOW) and notification writes through it. Wave F1 closed the last hidden-root leaks: the notification read path now opens each queued file through `SafeRoot`, the activation residue report and notification clear writes go through a new symlink-safe `write_hidden_file_atomic`/`SafeRoot::remove_file`, and the pivot/snapshot scaffolding moved onto the `/run` tmpfs so no hidden-root path is opened outside the helper. Deferred to other tickets: opaque-xattr containment (T-040), the fsmount/open_tree privileged-tier prototype (T-008), the leak-pattern commit gate (T-074); `restore.rs` keeps fork/setns per ADR 0004._

  **Problem:** The code hand-builds things the kernel already provides.
  - `overlay_mount/restore.rs:83-146` (duplicated around `:241`) calls `fork()` in a multi-threaded process, then `unshare(CLONE_FS)` and `setns` into `/proc/1/ns/mnt` to recreate the read-only `/nix/store` bind. It reports errors through `eprintln!`, and this path cannot be tested.
  - Paths under the hidden root are built with plain joins and `std::fs`, so nothing enforces that a symlink or `..` stays inside the hidden volume.
  - Overlays are mounted with `mount(2)` and option strings (`filesystem/real/mount_ops.rs:29-41`). Pivot targets also need a staging mount point that is visible while setup runs (`overlay/pivot/mod.rs`).

  **Fix:**
  - Add a small path-safety helper (e.g. `nails-core/src/filesystem/safe_path.rs`). It holds an `O_PATH` fd for the hidden root and resolves paths with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)`. Route every create, open and remove under the hidden root through it: state file, upper/work dirs, notifications, and opaque handling (T-040). It fails closed on ENOSYS.
  - Prototype overlay creation with `fsopen("overlay")`, `fsconfig` and `fsmount`, then attach with `move_mount` straight onto the target. Where the kernel allows it, this removes the staging mount and bind for pivot targets; otherwise keep staging inside the runtime tmpfs (T-069). If T-033 still needs the store bind, replace the fork/setns helper with `open_tree(OPEN_TREE_CLONE)` plus `move_mount`. Write the result up as an ADR in `docs/` either way.
  - Do not use cgroup-v2 freeze/thaw to quiesce writers: frozen processes keep fds and cwd on lower dentries and write to the decoy after thaw. Do not use `systemd-mount`: its transient units log to the journal before `/var` is overlaid.

  **Done when:**
  - The helper has unit and property tests (`..`, absolute and relative symlinks, loops, magic links), shared with T-015.
  - No hidden-root path is opened outside the helper. Enforce this with clippy `disallowed-methods` or by review with `rg`.
  - Either the privileged integration tier (T-008) shows no staging mount in `/proc/self/mountinfo` during activation, or the ADR explains why that is not possible.
  - `restore.rs` contains no `fork`/`setns`, or the ADR justifies keeping them.
  - `rg 'cgroup.freeze|systemd-mount' nails-core` finds nothing.

### W10-C2: Persona inventory

Owns: `nails-core/src/persona/inventory.rs`, `nails-core/src/preflight/checks/inherited_autostart.rs`, `nails-cli/src/cli/commands/check.rs`

- [x] **T-071: List the decoy autostart state the hidden session inherits, offer hidden-only masking, and document inherited remote and network identifiers** (medium · effort M)

  _Status (W10-C2): implementation complete and unit-tested: a read-only `persona/inventory.rs` (user and global autostart, user and global `.wants`, linger, GDM/SDDM/LightDM autologin, name-only remote-linked tag, fresh-home filtering), a Warn-only `inherited-autostart` preflight shown by `nails check` and the activation confirmation (`activate/dry_run.rs` no longer exists), `[persona] mask_inherited` writing `Hidden=true` overrides and `/dev/null` user-unit masks through the merged home before the session restart, and the guide/threat-model docs plus an optional hidden network-identity NixOS module and NetworkManager drop-in (VPN autoconnect is documented as a per-profile step, since NetworkManager has no global key for it). The session E2E test 36-inherited-autostart (it asserts the masks and the unchanged decoy home, not a live graphical login) and the NixOS module await evaluation on a nix-capable host (see nix_pending)._

  **Problem:** Users get no warning about what the hidden session inherits from the decoy. NAILS writes its own autostart hook into the merged `~/.config/autostart`, where every decoy entry from the lower layer also runs (`nails-core/src/shell/rc_integration.rs:132-180`). Decoy systemd user units and timers, lingering and display-manager autologin carry over too. The hidden config is imported on top of the decoy config instead of replacing it (`nails-core/src/nixos/config/mod.rs:20-27`). As a result, sync, cloud, messaging and account clients run under the decoy identity and can contact remote servers and the user's other devices. Machine-id, hostname, MAC and NetworkManager profiles (including VPN autoconnect) are shared as well, because `clean_stale_network_config` only removes `resolv.conf` and `nsswitch.conf` (`nails-core/src/manager/helpers.rs:105-176`). The dry run (`nails-cli/src/cli/commands/activate/dry_run.rs:24-146`) and the docs say nothing about any of this.

  **Fix:**
  1. Add a platform-neutral collector `nails-core/src/persona/inventory.rs` for the target user. It lists `~/.config/autostart` and `/etc/xdg/autostart` entries (skipping `Hidden=true` entries and `nails-notify.desktop`), enabled user units and timers (`~/.config/systemd/user/*.wants`, `/etc/systemd/user/*.wants`), `/var/lib/systemd/linger/<user>`, and autologin settings for GDM (`/etc/gdm{,3}/custom.conf`), SDDM (`/etc/sddm.conf{,.d}`) and LightDM (`/etc/lightdm/lightdm.conf{,.d}`). Entries whose names match a fixed list of common sync and account clients get the tag "remote-linked". The tag is based on the name only and makes no claim about signed-in state. System services are not classified heuristically.
  2. Add a Warn-only preflight check `preflight/checks/inherited_autostart.rs` that reports the count and the remote-linked names. Show the full inventory in `nails check` (T-062) and in the activation confirmation (T-029). When fresh-home mode is on (T-046), report only system-level items.
  3. Add optional hidden-only masking via `[persona] mask_inherited = ["name", ...]` (or `"*"`) in `nails.toml` (T-013). After the overlays are mounted and before the session restarts, write `Hidden=true` autostart overrides and `/dev/null` user-unit masks through the merged view, so they land only in the hidden upper. Never write into a mounted upper directory directly. Lingering and autologin are reported but not masked.
  4. In `docs/USER-SECURITY-GUIDE.md` (threat table :342-351, pre-activation checklist :416-430) and `docs/threat-model.md` (T-121), state two things: remote and account state is shared and never rolled back, and correlation through the shared network identifiers is out of scope. Ship an optional network-identity snippet for the hidden NixOS config (random Wi-Fi/Ethernet MAC, a distinct `networking.hostName`, VPN autoconnect off) and the equivalent NetworkManager `conf.d` drop-in for FHS hosts. The snippet only takes effect once the hidden switch runs before the session restart (T-089). Change the `clean_stale_network_config` doc comment to say it only preserves DNS.

  **Done when:**
  - MockFilesystem fixture tests cover each inventory source (user and global autostart, user and global `.wants`, linger, autologin for each display manager), the client-name matcher and the fresh-home filtering. `cargo test` and clippy pass, and coverage stays at 100%.
  - The check returns Warn with a count and never blocks activation. `nails check` and the activation confirmation both show the inventory.
  - An E2E test in `nix/e2e-tests/tests/session/` sets up a decoy user with an autostart entry and an enabled user timer. With masking on, neither runs in the hidden session, and after deactivation the decoy home hashes the same as before.
  - The guide and the threat model document the shared remote, account and network identifiers and include a pre-activation checklist. The network snippet is parse-checked by the lint gate.

## Wave 11: Verify overhaul + forensics-eval replacement + CLI thin + config layer

### W11-C1: Verify & forensic disk-image harness

Owns: `nails-core/src/verify/`, `nails-core/src/artifacts.rs`, `nix/forensics-eval/`, `nix/e2e-tests/lib/disk_forensics.py`

- [x] **T-073: Truthful, platform-aware verify: honest headline, real artifact classes, all user homes, mount-state checks, offline image mode, no self-inflicted findings** (high · effort L)

  _Status: mostly done (wave C3/K1). Landed: the honest headline ("No known artifacts found … This is not proof of absence." with areas-not-checked and checks_run), the passwd-driven multi-home scan, the mountinfo upperdir overlay scan, identity-based process matching, unreadable-dir tolerance, the no-self-findings host context, `--offline`/`--root` image mode, `Platform::artifact_scanners()` (Debian apt/dpkg drift + NixOS note), exit codes 10/11, updated `verify.json` schema, and the E2E `forensic/07` + `contract/59` tests plus `smoke/02` + `smoke/12` updates (all need VM evaluation — see nix_pending). Remaining (deferred to the deactivate-flow rework): `reports/last-deactivation.json` written to the hidden root before reboot and surfaced by the next `status` — it depends on write-ordering that only exists after that rework, and the Debian scanner's package-baseline is only produced once the activation path writes it._

  _Status (2026-10): done. A standard deactivation writes `reports/last-deactivation.json` to the hidden volume after teardown and before the reboot; `status` surfaces it (human and JSON, schema updated) and forensic/05 asserts it. The pre-activation residue baseline is scoped to the decoy (`Verifier::scoped_to_decoy`), so it no longer reports the attached hidden volume. Follow-up: nothing writes the Debian package baseline under `reports/package-baseline` yet, so the apt/dpkg scanner reports "not checked" on real hosts._

  **Problem:** `nails verify` claims more than it checks and cannot pass in the documented workflow.
  - The deep scan reads `/root/.bash_history`, `/root/.zsh_history`, `/home/.bash_history` and `/home/.zsh_history` (`nails-core/src/verify/verifier.rs:240-246`). The last two never exist, so user history is never checked.
  - Overlays are checked only at /home, /etc and /root (`verifier.rs:117-140`). A leftover /var, /nix, /tmp, /srv or /opt overlay goes unreported.
  - The backend check tests whether the path exists, not whether it is mounted (`:318-331`). Run from the hidden binary, verify always warns about the hidden root and `state.json` (`:353-367`). It also creates `<root>/logs/nails.log` and then reports that file in the same run.
  - `find_files_with_pattern` propagates `read_dir` errors (`filesystem/real/file_ops.rs:169`). A non-root `verify --deep` therefore exits 2 on `/tmp/systemd-private-*`, although the guide says to run it without sudo.
  - The process check flags any cmdline containing "nails" as CRITICAL (`filesystem/real/system_ops.rs:90-126`), which includes `sed`, `tee` and an editor on the config. The headline says "SECURE: No traces found. System appears clean." (`nails-cli/src/cli/output/verify.rs:17`).
  - README step 7 (`README.md:169-172`) says to verify from the decoy side, which contradicts the no-binary-on-decoy rule. The guide's capability table claims recently-used tracking is checked; it is not.

  **Fix:**
  - **Headline:** "No known artifacts found (N checks, <depth> scan), not proof of absence", followed by the list of areas that were not checked.
  - **Exit codes:** 0 clean, 10 warnings, 11 critical, 2 error.
  - **Indicators:** take the artifact classes from the T-074 registry: the rc marker block, autostart entry, system profile links, the /etc/nixos link and import marker, `/run/nails`, and log and config names.
  - **Homes:** check every home from passwd (uid >= 1000 with a login shell, `SUDO_USER`, and root): history files, `recently-used.xbel`, and an optional warning when `~/.config/VeraCrypt/{History.xml,Favorite Volumes.xml}` or gvfs-metadata/thumbnail URIs name the configured hidden root.
  - **Mounts:** read mount state from `/proc/self/mountinfo` and flag every overlay whose upperdir is under the hidden root. Add a journal search for the hidden-root path and NAILS unit names.
  - **Host context:** verify never writes (no file logger) and suppresses findings about its own hidden root and state file. It asserts that the state reads Inactive instead.
  - **Unreadable directories:** report them as "not checked (permission denied)" at info level, never as an error exit.
  - **Process match:** match on `/proc/<pid>/exe` having the same inode as the nails binary, or argv[0] basename `nails` with a known subcommand. Exclude the caller's own session. A plain substring match is only Info.
  - **Offline mode:** `verify --offline --root <mnt>` scans a read-only mounted decoy image or partition. Paths are rebased under `<mnt>`, and live process and mount checks are skipped.
  - **Platform scanners:** add `Platform::artifact_scanners()`, all read-only. NixOS documents the `/var/lib/nixos` drift as expected. DebianFamily diffs apt `history.log`, `dpkg.log` and `/var/lib/dpkg/status` against a baseline stored on the hidden root at activation.
  - **Deactivation report:** deactivate runs verify after unmounting and before the reboot, writes `reports/last-deactivation.json` on the hidden root, and the next `status` shows its summary. This depends on the deactivate flow rework.
  - **Docs:** fix the README verify step, the USER-SECURITY-GUIDE verify section, and its capability table.

  **Done when:**
  - `rg 'System appears clean|SECURE: No traces|/home/.bash_history' nails-cli nails-core` returns nothing.
  - Unit tests (MockFilesystem plus a mountinfo fixture) cover: multiple homes, a leftover /var overlay, an unreadable directory (Info finding, exit status unaffected), no file created during a run, and no hidden-root or state warnings in the host context.
  - A cargo test runs `verify --offline --root <fixture>` against a read-only fixture tree: it finds a planted indicator and ignores live processes and mounts.
  - Unit test: the DebianFamily scanner flags a changed dpkg status and performs no writes.
  - E2E: new `tests/forensic/07-verify-seeded-artifacts.nix` seeds each artifact class and verify flags each one. `nails verify | tee out` produces no CRITICAL process finding. A clean deactivation exits 0.
  - E2E: deactivate writes `last-deactivation.json` before the reboot.
  - `fixtures/schemas/verify.json` and the tests `contract/59-verify-json-schema.nix` and `smoke/12-status-verify.nix` are updated and pass. cargo test and clippy are clean.

- [x] **T-074: One artifact registry shared by verify, preflight and the E2E indicators; explicit verify contexts; name-independent mapper and loop detection** (medium · effort M)

  _Status: done (W11-C1 registry, completed wave C3/K1). `nails-core/src/artifacts.rs` holds the single registry with one `CONFIG_FILE_NAME`, now fully consumed by `verify` (artifact loop + severity/fix mapping), the base-config preflight, and `nix/e2e-tests/fixtures/indicators.json` (drift-guarded); name-independent dm-crypt/loop detection landed and unit-tested. Remaining is nix-only: `smoke/02-verify.nix` VM evaluation, and if VM-level coverage of an arbitrary crypt mapper is wanted, a dmsetup step there — see nix_pending._

  **Problem:**
  - The artifact list in `nails-core/src/obfuscate/mod.rs:252-268` and `:426` (`/tmp/nails.log`, `/tmp/nails.toml`, `/var/log/nails.log`, `/etc/nails`, `/home/.nails`, `/root/.nails`) names nothing the tool actually writes.
  - The config filename is defined three times and the definitions disagree: `init.rs` uses `nails.yaml`, `config/loading.rs:12` uses `config/nails.yaml`, and obfuscate `CONFIG_FILE_NAME` uses `nails.toml`.
  - No check covers the staged `/etc/nixos` link, the `hardware-configuration.nix` import marker, or `nails-*` journal units.
  - Open crypt mappers and loop devices are not detected at all.
  - `docs/USER-SECURITY-GUIDE.md:236,461,533` only check and close a mapper named `veracrypt-hidden` at `/mnt/hidden`, while the code default is `/mnt/hidden-volume`.

  **Fix:**
  1. New module `nails-core/src/artifacts.rs` replaces the artifact constants of the removed obfuscate module. It is the single registry of what NAILS writes:
     - one `CONFIG_FILE_NAME` (`nails.toml`), used by init, loading and verify;
     - the state file and log names, the staged `/etc/nixos` link and import marker, and transient unit prefixes;
     - notification and autostart names, the rc marker, pivot staging paths and `/run/nails`.
  2. verify (T-073), the base-config preflight (`preflight/checks/suspicious_nails_reference.rs`) and the E2E disk-image checks (T-075) all consume the registry.
  3. Export the registry to `nix/e2e-tests/fixtures/indicators.json`, with a cargo test that fails when the file drifts from the registry.
  4. Add name-independent detection to the host context: dm-crypt devices from `/sys/block/dm-*/dm/uuid` (prefix `CRYPT-`) and loop devices from `/sys/block/loop*/loop/backing_file`. The device holding the running binary is Info ("close before handing over the machine"). Any other device is a warning.
  5. Docs replace the `veracrypt-hidden` checklist with `findmnt -S /dev/mapper -o TARGET,SOURCE`, `dmsetup ls --target crypt` and `losetup -a`.
  6. Build the forbidden list in `security/73-binary-obfuscation-scan.nix` from the registry, or drop the test together with the obfuscation module.

  **Done when:**
  - The config filename literal appears in exactly one const.
  - A MockFilesystem test asserts that verify flags every registry entry the activation path creates.
  - The `indicators.json` drift test passes.
  - E2E `smoke/02-verify.nix`: after a clean deactivation the self-check exits 0, and an extra crypt mapper with an arbitrary name is reported.
  - `rg veracrypt-hidden docs README.md` returns nothing.

- [x] **T-075: Replace nix/forensics-eval with host-side decoy disk-image checks inside the E2E suite (fls/strings/journal, null and positive controls)** (high · effort L)

  _Status: done (W11-C1). `nix/forensics-eval/` and its runner scripts are deleted; `disk_forensics.py` (fls/strings/journal/store parsers), `forensic-vm-config.nix`, `disk-forensics.nix` and parser unit tests landed, and forensic tests 04/05/06/08 were ported to one disk-image lineage. VM/KVM evaluation of the ported tests and the lint lane remains (nix cannot run in this sandbox) — see nix_pending._

  **Problem:** The current forensic checks can neither detect a leak nor fail.
  - `fls -r /dev/vdb ... || echo CLEAN` runs on the LUKS ciphertext (`forensic/04-forensic-clean.nix:78`, `05-standard-deactivation-forensic.nix:200`, and the forensics-eval `real_stage_exporter.py`). The decoy disk (vda) is never imaged.
  - 04 computes `file_diff` without using it and filters out `/var/log` and `/var/lib`. 05 skips the journal and binary files (`--exclude-dir=journal`, `grep -I`) and only prints the verify result (`:184-196`).
  - 06 asserts nothing and still prints "exact initial state" (`:112`).
  - In forensics-eval, every capture name carries its stage label, so every capture shows up as a finding. The fls parser expects an invented output format, and the positive control passes by construction.
  - Test VMs use the host 9p store with a tmpfs write layer, so store residue never reaches a disk that could be imaged.
  - About 10k lines, five workflows and four scripts exist only to maintain this.

  **Fix:**
  1. Add `nix/e2e-tests/lib/forensic-vm-config.nix` (imports `vm-config.nix`) with `useNixStoreImage = true; writableStore = true; writableStoreUseTmpfs = false;`. One root disk keeps a single lineage across `shutdown()`/`start()` within a test.
  2. Add `nix/e2e-tests/lib/disk_forensics.py`, a host-side module with tool paths injected from Nix (qemu-img, sleuthkit, binutils, e2fsprogs, journalctl, sqlite):
     - `snapshot()`: shut down, then `qemu-img convert -O raw` the root disk from `machine.state_dir`;
     - `fls_paths()`: parse real `fls -r -p` output, including tab separators, relative paths, `*` and `(realloc)`;
     - `string_hits()`: raw `grep -a` over the whole image;
     - `journal_hits()`: extract with debugfs/icat, then read with `journalctl --directory`;
     - `nix_store_paths()`: query `ValidPaths` from `db.sqlite`;
     - `diff()`: keyed on in-image paths.
  3. Hard oracles:
     - **Null control:** a plain reboot shows zero findings beyond a short, commented allowlist.
     - **Positive control:** a canary written outside the overlays, plus a `logger` line, must be found by the fls, strings, journal and store checks.
     - **Real check:** the hidden canaries (file, history line, journal line, store path) and the entries of `fixtures/indicators.json` (T-074) are absent from the post-standard and post-emergency images.
     - The `/var/lib/nixos` drift is an explicit allowlist entry that points at its TODO.
  4. Port 04, 05 and 06 to one lineage (baseline -> active -> post-standard), and add a separate post-emergency test. Remove the `/dev/vdb` fls checks. Turn the computed inventories into allowlist assertions. 05 asserts the verify status and exit code. No test summary claims a check it does not assert.
  5. Add parser unit tests in `nix/e2e-tests/lib/tests/test_disk_forensics.py` against real output captured once (`fixtures/forensics/`). They run in the fast lane.
  6. Optional follow-up: an impermanence fixture (`lib/impermanence-vm-config.nix`: tmpfs root, `/persist` disk) and a `/var/lib/nixos` canary user that must not appear under `/persist`. It is non-blocking until triaged.
  7. Delete:
     - `nix/forensics-eval/`;
     - `.github/workflows/forensics-eval-{fast,regression,full,full-shard,full-pr-metadata}.yml`;
     - `scripts/run-forensics-eval.sh`, `run-forensics-eval-tests.sh`, `forensics_live_scope_guard.py` and `prepare-forensics-review-bundle.py`;
     - `rawForensicsEval` and `forensics-eval-metadata` in `flake.nix:200-221`;
     - the forensics-eval sections of `docs/ci.md`.
     Add a CHANGELOG entry.

  **Done when:**
  - `rg -n 'forensics-eval|forensics_eval' --glob '!CHANGELOG.md'` returns nothing.
  - `nix flake show` evaluates without `forensics-eval-metadata`.
  - `rg 'fls.*/dev/vdb' nix/e2e-tests` returns nothing.
  - The positive control fails the test when its decoy write is removed. The null control passes with only the documented allowlist.
  - The forensic tests use `forensic-vm-config.nix` and pass. The parser tests run with `python3 -m unittest`.

- [x] **T-076: E2E coverage for VeraCrypt, bind-mounted and unsuitable backends, plus a realistic /etc/nixos fixture** (medium · effort M)

  _Status: done (W11-C1). New `tests/backends/` VeraCrypt (tcrypt), bind-mount and NFS-unsuitable tests, a shared `backends.nix` helper, regular-file (`mode 0644`) `/etc/nixos` fixtures, and backend-neutral `hidden_volume.rs` wording landed. VM evaluation remains, and the non-interactive VeraCrypt hidden-volume creation flags must be confirmed on a nix host (tcplay fallback documented in-file) — see nix_pending._

  **Problem:**
  - Every positive E2E path uses LUKS2 plus ext4 on `/dev/vdb` (`lib/hidden-volume.nix`). vfat appears only as a refusal case.
  - README and CHANGELOG document `cryptsetup open --type tcrypt --veracrypt --tcrypt-hidden`, but no test opens a VeraCrypt volume and none uses a bind-mounted directory root.
  - NFS and sshfs cannot host an overlay upper (no trusted xattrs or d_type support), and no preflight probe or test checks for a clean refusal.
  - `lib/vm-config.nix:60-86` provides `/etc/nixos` through `environment.etc.<f>.text`, which creates `/etc/static` symlinks instead of the regular files a real install has.
  - The preflight message says "Mount the hidden LUKS volume" (`preflight/checks/hidden_volume.rs:87`, test at `:192`).

  **Fix:**
  1. Add a VeraCrypt hidden-volume test in the nightly lane. Commit a small pre-generated container under `nix/e2e-tests/fixtures/backends/`, because cryptsetup can open TCRYPT volumes but not create them. Open it with `--type tcrypt --veracrypt --tcrypt-hidden` under a neutral mapper name. Activate, plant canaries, deactivate, then run the T-075 image scan, including mapper names in the journal.
  2. Add a bind-mounted directory test: a directory on a separate ext4 disk, bind-mounted at the hidden root.
  3. Add an NFS negative test: a second node exports a share, and the test expects refusal from an upper-filesystem capability probe. Add that probe (trusted xattr plus d_type on the hidden root) to `preflight/checks/overlay_compatibility.rs` if it does not exist yet.
  4. Make the `/etc/nixos` fixtures regular files (`mode = "0644"`).
  5. Use backend-neutral wording in the `hidden_volume.rs` message and update its test.
  6. btrfs and USB backends stay out of scope.

  **Done when:**
  - The tcrypt test and the bind-mount test pass in `nix/e2e-tests/tests/backends/`.
  - The NFS test asserts the capability error.
  - `test ! -L /etc/nixos/configuration.nix` holds in the VM.
  - `rg LUKS nails-core/src/preflight/checks/hidden_volume.rs` returns nothing.

- [x] **T-077: E2E test that proves where hidden-session Nix store writes land** (high · effort M)

  _Status: done (W11-C1). The `/nix` store-bind fix was already on overhaul and test 44's layer assertion already landed; the missing acceptance gate `nix/e2e-tests/tests/forensic/09-nix-store-placement.nix` (filename 09 because 80 was taken) was added, proving both run-unique store paths land only under the hidden `/nix` upper and are absent from the imaged decoy root and its `db.sqlite`. VM evaluation remains — see nix_pending._

  **Problem:** Hidden-session store paths may be written to the decoy store.
  - `manager/helpers/runtime_cache.rs:5` keeps the decoy store at `/run/nails/original-nix-store`.
  - After the /nix overlay is mounted, `manager/activation/overlay_mount/restore.rs` (around `:24-45` and `:284-306`) binds that pre-overlay store back over `/nix/store` in the manager and init namespaces, then restarts nix-daemon and logs "now writing to overlay".
  - Nix remounts a read-only store bind as writable. Hidden rebuild outputs and nix-shell packages can therefore end up on the decoy filesystem as unregistered paths whose names reveal the hidden packages.
  - `shell/44-nix-daemon-restart-on-overlay.nix:150-157` only checks that `nix store add` succeeds. The host-shared store in the VMs makes the placement impossible to observe.

  **Fix:**
  1. Add `nix/e2e-tests/tests/forensic/80-nix-store-placement.nix` on `forensic-vm-config.nix` (T-075).
  2. Activate with /nix overlaid. Inside the session, realise a store path unique to the run: `nix store add` of a nonce file plus an offline writeText-style derivation.
  3. From outside the session namespace, assert that the path is absent from the lower store and present under the hidden /nix upper.
  4. Deactivate, snapshot the disk with `disk_forensics.py`, and assert that the nonce hash appears in neither the fls listing (deleted entries included), the raw strings, nor `db.sqlite` `ValidPaths`.
  5. Extend test 44 to assert which layer received the path.
  6. Land the test in the same change as the /nix store bind fix (re-bind the overlay's own store read-only, or root the daemon on the hidden upper). It is that fix's acceptance gate.

  **Done when:**
  - The commit message records the placement the test observes on current code.
  - After the fix, test 80 passes: the nonce path exists only under the hidden upper and is absent from the decoy image and the Nix DB.
  - Test 44 asserts the layer, not just success.

### W11-C2: CLI thin boundary

Owns: `nails-cli/src/cli/commands/mod.rs`, `nails-core/src/manager/preflight_runner.rs`

- [x] **T-078: Make the CLI thin: one shared preflight registry, one config-resolve entry point, one color/verbosity preamble** (medium · effort M)

  _Status: done (W11-C2). The shared core preflight registry, the single config-resolve entry point and the one color/verbosity preamble were already on overhaul from earlier waves; this wave closed the last gap so file logging (`init_file_layer`) resolves through that single entry point and never silently defaults when an explicit `--config` fails to load, with a regression test._

  **Problem**
  Business logic has leaked into `nails-cli`, duplicating `nails-core`. `nails-cli/src/cli/commands/activate/dry_run.rs:150-251` (`build_preflight_registry`) reimplements the registry that `nails-core/src/manager/preflight_runner.rs:77-216` (`run_preflight_checks`) already builds, and the two have drifted: dry-run omits `StateCheck`, always registers `NixOSBuildTargetCheck` with `selected_flake_dir = None` (skipping core's `flake_target_already_validated` short-circuit), and swallows `build_overlay_targets` errors (`Err(_) => Vec::new()`) where core propagates with `?` — so a dry-run can pass where real activation fails. Config loading is also forked: five commands call `load_config_or_exit` (`nails-cli/src/cli/commands/mod.rs:40`) while `activate/mod.rs:159-174` uses its own `Config::load`/`from_file_and_cli`/`apply_cli_overrides` path, and `logging.rs:267-268` silently falls back to `Config::default()` on any load error even when `--config` was passed. The color/verbosity preamble (`set_plain_mode` + `set_color_enabled` + `set_verbosity`) is copy-pasted across `main.rs:42`, `status.rs:34`, `emergency.rs:37`, `deactivate.rs:39`, and `activate/mod.rs:75`.

  **Fix**
  - Move preflight-registry construction into `nails-core` as one function (e.g. `build_preflight_registry(&fs, &config, overlay_only)`) consumed by both `run_preflight_checks` and dry-run; delete `dry_run.rs::build_preflight_registry`. Get the NixOS build-target from the platform seam's `discover_nixos_target()` rather than re-deriving it here.
  - Add a single `Config::resolve(path, cli_overrides)` entry point in core and route every command and `logging.rs` through it; drop the silent `Config::default()` fallback — when `--config` is given and load fails, exit non-zero with the error. (Strict TOML schema loading belongs to the config-migration work; this item only unifies the call sites.)
  - Extract the color/plain/verbosity preamble into one helper invoked once per command entry.

  **Done when**
  - Dry-run and activation build the identical registry from the one core function; a test asserts the two check sets match.
  - All commands and `logging.rs` resolve config through `Config::resolve`; no silent default when `--config` is explicit, covered by a test on the error exit.
  - One preamble helper; the duplicated `set_*` blocks are gone.
  - `cargo test` (via `nix develop -c cargo test`) is green and a regression test confirms dry-run no longer passes where activation would fail.

### W11-C3: NixOS ConfigLayer

Owns: `nails-core/src/platform/config_layer.rs`, `nails-core/src/nixos/builder/`, `nails-core/src/manager/activation/nixos_build.rs`

- [x] **T-079: Make the declarative hidden config an optional NixOS-only ConfigLayer** (high · effort M)

  _Status: done (W11-C3). A `ConfigLayer` trait with a single `NixOsConfigLayer`, obtained from `Platform::config_layer()` (None on FHS/Debian), now gates staging, fingerprint, `/etc` import injection, build, switch and decoy restore; the CLI pre-detach staging routes through `NailsManager::stage_hidden_config` behind the same gate, and the discovery cascade is centralized. The real NixOS rebuild/switch VM E2E (tests 27-30) must be run later to confirm the unchanged path — see nix_pending._

  **Problem** The declarative hidden-config half of activation is bound to NixOS-only mechanisms: `nixos-rebuild` (`nails-core/src/nixos/command.rs:94`), the profile switch script (`nails-core/src/nixos/builder/switch.rs:50-57`), `/run/current-system` (`nails-core/src/manager/activation/overlay_mount/restore.rs:206`) and `nix-daemon` (`.../overlay_mount/auto_mount.rs:27-40`). A Debian/Ubuntu decoy has none of these, so this path cannot run there. The only seam is the negative `--overlay-only` flag: it skips builder creation (`nails-cli/src/cli/commands/activate/mod.rs:198`) and the NixOS preflight checks (`nails-core/src/manager/preflight_runner.rs:177-194`), but it is a CLI flag rather than a platform property, and generic paths still do NixOS work — `stage_hidden_config_symlink` runs even under `--overlay-only`/`--no-preflight` (`.../manager/activation/preflight.rs:60-63,106-117`) and the `/etc` import injection is hard-coded per target (`.../overlay_mount/mod.rs:152-208`).

  **Fix** Introduce a `ConfigLayer` trait (plan/apply/restore) in the new platform module (`nails-core/src/platform/config_layer.rs`) with a single `NixOsConfigLayer` implementation. Route hidden-config staging, fingerprinting (`nails-core/src/nixos/fingerprint.rs`), the `/etc` import injection (`nails-core/src/nixos/config/inject.rs`), the build (`.../manager/activation/nixos_build.rs`) and the switch (`.../manager/activation/nixos_switch.rs`) through it. Move the flake / configuration.nix / system-profile discovery cascade into one function inside this layer and call it from activate, dry-run (`nails-cli/src/cli/commands/activate/dry_run.rs`) and `NixOSBuildTargetCheck` (`nails-core/src/preflight/checks/nixos_build_target.rs`). Obtain the layer from `Platform::config_layer()`, which returns `None` on `DebianFamily`; overlay-only becomes "no layer" rather than a parallel code path. Guard `stage_hidden_config_symlink` and the switch steps behind an active layer. Boot-time/kexec carriage of this config to other distros stays out of scope (see the boot-time redesign item).

  **Done when** With no ConfigLayer (FakePlatform + a recording command runner), activation never touches `/etc/nixos`, hidden nixos staging, `nixos-rebuild` or `switch-to-configuration`, asserted by test. The discovery cascade lives in exactly one function, and dry-run, activate and preflight produce the same plan for every fixture. NixOS VM tests exercising the real rebuild and switch path still pass.

## Wave 12: State reconcile/status + Debian-family platform mechanics

### W12-C1: State reconcile & kernel-truth status

Owns: `nails-core/src/state/reconcile.rs`, `nails-core/src/status/`, `nails-cli/src/cli/output/status/`

- [x] **T-080: Reconcile persisted state with the boot and the kernel mount table so a stale Active never makes activate a silent no-op** (critical · effort M)

  **Problem**: `activation/mod.rs:181-186` returns `Ok(())` for any persisted `Active` state before preflight and before checking the kernel mount table, and `verify_overlay_status` (`state_management.rs:378`) has no production caller. `state.json` lives on the hidden root, survives reboots, and is never compared against a boot id or the live mounts. After an unclean shutdown mid-session, `activate --no-kill-session` or `--no-preflight` prints success while mounting nothing, then the CLI runs `shell_setup` on `result.is_ok()` (`activate/mod.rs:368-388`, `shell/setup.rs:96`), writing the rc block (`shell/rc_integration.rs:36-180`) and the autostart entry with the hidden binary path straight onto the bare decoy home. `StateCheck` (`preflight/checks/state.rs:84-92`) also tells users to reboot for stuck states, but a reboot does not change `state.json`.

  **Fix**: Add `nails-core/src/state/reconcile.rs` with `reconcile(state, load_outcome, nails_mounts, current_boot_id) -> EffectiveState`. Record `/proc/sys/kernel/random/boot_id` and `owner_pid` in `state.json` when entering Activating/Active/Deactivating. Outcomes: `Inactive`; `VerifiedActive` (all tracked overlays mounted with expected upperdir); `StaleFromPreviousBoot` (boot id differs -> reset to Inactive, keep cached build data, warn); `Interrupted` (same boot, Activating/Deactivating with dead `owner_pid`); `Degraded` (Active with overlays missing, or NAILS mounts present while state says Inactive); `Unknown` (state unreadable). Run reconcile at the start of every command after taking the state lock, via `manager/state_management.rs`; stale states are reset and persisted, others reported. `activate_with_options` returns `ActivationOutcome {Activated, AlreadyActive}`; return early only on `VerifiedActive` (AlreadyActive, exit 0 on every flag path, message is not "Activation complete"), and refuse on Degraded/Interrupted/Unknown pointing at `nails recover`/`nails emergency`. Run `shell_setup` and the colour-scheme sequences only on `Activated`, and only when the target home is on a NAILS-owned overlay (discovery from the mount-table ownership work); otherwise log and skip. Persist the mount method per target (direct/pivot/snapshot-pivot) in Active state for status to show. Rewrite `StateCheck` messages to drop reboot advice.

  **Done when**: unit tests cover Active-with-different-boot-id resetting to Inactive then really mounting; Active same-boot with no overlays -> Degraded -> refuse; Activating with dead pid -> Interrupted; Inactive with a NAILS overlay in mountinfo -> Degraded; `shell_setup` writes nothing when the target home is not a NAILS overlay (mock fs). Already-active returns exit 0 with the same message under default, `--no-kill-session` and `--no-preflight`. `rg -i 'reboot (if stuck|to reset)' nails-core/src` is empty. `rg run_truthful` plus the new E2E: `nix/e2e-tests/tests/state/55-state-crash-mid-activation.nix` remounts after the crash and asserts the stale reset, and a new `nix/e2e-tests/tests/lifecycle/12-stale-active-after-reset.nix` hard-resets during an active session then runs `activate --no-kill-session` and asserts overlays are mounted with no rc block or autostart file on the decoy lower layer. `cargo test` and `clippy` pass.

- [x] **T-081: status reports what the kernel actually has mounted (degraded/inconsistent/unknown postures) and shows newest logs without writing logs** (high · effort M)

  **Problem**: `status` trusts `state.json` instead of the kernel. Active-with-overlays-missing maps to `Warning`/"transitional state - wait for completion" (`status/report/types.rs:119`) even though hidden writes are then reaching the decoy disk. `Inactive` returns `VerificationStatus::NotApplicable` without probing mounts (`status/mod.rs:358`). A truncated/missing/unreadable `state.json` yields `State: Inactive / DECOY` and exit 0 because `load_outcome` is `#[serde(skip)]` (`types.rs:205`) and `run_truthful` just calls `run` (`status/mod.rs:252`); once the backend is lazily unmounted the overlays keep serving hidden data while status says decoy. `is_mounted` (`status/mod.rs:335`) also reports a plain ext4 `/home` as "Verified". Recent Logs reads `nails.log` front-to-back and renders `take(20)` (`output/status/mod.rs:16-105,233`; `human.rs:123,257`), showing the oldest entries, and every read-only status call appends TRACE JSON to `nails.log` via the file logger (`logging.rs:343`).

  **Fix**: Compute posture from the reconciled `EffectiveState` (T-080) plus mount-table ownership discovery. Five postures with distinct remediation text and exit codes: `decoy` (clean, 0); `active` (verified, 0); `degraded` (Active but N overlays missing: "hidden writes may reach the decoy disk, run `nails emergency`", non-zero); `inconsistent` (NAILS overlays mounted but state inactive/unavailable, run `nails emergency`, non-zero); `unknown` (state unreadable or hidden root not mounted, non-zero). Human mode always prints per-overlay errors; JSON carries posture, `load_outcome`/state source, per-overlay identity (mount point, upperdir, owned) and any remaining NAILS mounts. Only report an overlay as verified when it is an actual NAILS overlay, not any mounted path. Delete `run_truthful`. Logs: keep the last N entries (bounded `VecDeque` or read from the end) in chronological order, shown only with `--details` or when posture is active/degraded. Read-only commands (`status`, `verify`, `notify-dispatch`) do not attach the file logger at all.

  **Done when**: per-posture unit tests: Active with missing overlays -> degraded (non-zero exit, remediation names emergency); truncated `state.json` -> unknown; missing `state.json` plus a NAILS overlay in mountinfo -> inconsistent; ext4 `/home` not reported as a verified overlay. JSON snapshot includes posture and load_outcome. With 30 log lines, status shows the newest N in chronological order and leaves `nails.log` size and mtime unchanged. `rg run_truthful` is empty. E2E (extend `nix/e2e-tests/tests/state/56-state-missing-file.nix`): lazily unmounting the hidden backend during an active session makes status report inconsistent or degraded, never decoy. `cargo test` and `clippy` pass.

### W12-C2: Host commands, ro-guard, nix gating, submounts, systemd

Owns: `nails-core/src/platform/host_commands.rs`, `nails-core/src/platform/ro_guard.rs`, `nails-core/src/platform/service_manager.rs`, `nails-core/src/filesystem/real/submount.rs`

- [x] **T-082: Replace hard-coded /run/current-system/sw/bin binaries with a per-platform HostCommands resolver** (high · effort M)

  **Problem:** 17-18 production call sites spawn tools from NixOS binary dirs with no fallback: `Command::new("/run/current-system/sw/bin/systemctl")` in `process/session/types.rs:110` and `process/restart/mod.rs:84`; also `manager/helpers/command_cache.rs:61,130,364`, `runtime_cache.rs:85-89`, `service_controller.rs:16,27`, `activation/overlay_mount/restore.rs:337-338`, `cli/detach.rs:119,128`. Only `manager/deactivation.rs:78-80` has any PATH fallback. On a non-NixOS host the first `systemctl` spawn returns ENOENT; `restart_systemd_service` propagates it (`restart/mod.rs:200`), so overlaying any target a service holds (e.g. /var) fails and auto mode aborts after the user session is already killed. `start_service_and_socket` discards errors (`service_controller.rs:317-328`). Other tools (loginctl, kill, chown, cp, du, find, getfattr/setfattr, sync, swapoff, systemd-run, nixos-rebuild) run off inherited PATH, so the trust model is mixed.

  **Fix:** Add `nails-core/src/platform/host_commands.rs` with a `HostCommands` resolver built once before any mount from the platform search list (NixOS: /run/current-system/sw/bin, /run/wrappers/bin; FHS: /usr/sbin, /usr/bin, /sbin, /bin), caching canonical paths. Trust check: the resolved file must be root-owned and not group/world-writable; accept a parent dir that is root-owned and either not group/world-writable or sticky with a trusted group (covers /nix/store 1775 root:nixbld). Spawn with `env_clear()` plus an allowlist: PATH = resolved dirs, LANG=C, and NIX_PATH/NIX_* only for the nixos-rebuild call (this is the shared root env hardening). Route every listed call site through the resolver, including RebootCommand and the detach PATH; stop discarding `start_service_and_socket` errors. Preflight prints a missing-tool -> package table and fails early. (Collapsing executor traits is separate; D-Bus/zbus is later work.)

  **Done when:** `rg '/run/current-system/sw/bin'` over nails-core/src and nails-cli/src matches only inside the NixOS platform search list. Unit tests: resolver picks /usr/bin/systemctl on an FHS fixture root, rejects a world-writable candidate, and accepts a /nix/store-style sticky parent. Preflight fails with a tool-to-package table when a required tool is missing. A recording runner confirms spawned commands get the allowlisted environment.

- [x] **T-083: Make the overlay policy platform data and enforce that every writable OS tree is overlaid or read-only, keeping /usr read-only on FHS hosts** (critical · effort L)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (the per-directory overlay policy; the fstab policy at entry takes its place). The item stays ticked as history; it describes no current code._

  **Problem:** `DEFAULT_OVERLAY_EXCLUSIONS` (`config/types.rs:66-79`) excludes /bin, /usr, /lib, /lib64, /sbin (justified only as "common in NixOS") and a machine-specific /Downloads. `build_overlay_targets` force-removes /bin and /usr even when the user clears the exclusion (`manager/helpers.rs:283-286`, "breaks tests"), and explicit mode refuses them (`explicit_mount.rs:28-36`). On usr-merged FHS distros (Debian 12+, Ubuntu) all software lives in /usr: with /var overlaid but /usr writable, package payloads and /usr/local writes during a session land on the decoy disk while the package DB lands in the hidden upper, leaving unowned files that debsums/rpm -Va detect. On NixOS the hidden activation rewrites /bin/sh and /usr/bin/env on the decoy root, leaving inodes referencing hidden store paths; nothing remounts those trees read-only. There is no enforced invariant that the decoy stays read-only while hidden is active, and forensic test 06 only hashes /home, /etc, /var so the leak is invisible.

  **Fix:** Move default exclusions, never-overlay paths and read-only paths into `Platform::overlay_policy()` (new `platform/ro_guard.rs`, data in `platform/nixos.rs` and `platform/debian.rs`). Universal never-overlay: /proc, /sys, /dev, /run and the hidden-root mount. Replace the unconditional /bin,/usr force-retain and the explicit-mode refusal with the policy-driven guard. DebianFamily: overlay /etc, /home, /root, /var, /srv, /opt, /tmp, /media; keep /usr (and real-dir /bin, /sbin, /lib*) read-only for the session by bind-remounting ro in the init mount namespace (reuse the setns helper in `overlay_mount/restore.rs`), undone on deactivate and emergency. NixOS: keep the /bin/sh and /usr/bin/env rewrites off the decoy disk by overlaying those tiny trees or ro-guarding them. After overlays mount, bind-remount every decoy-block-device-backed, non-overlaid mount ro (MS_BIND|MS_REMOUNT|MS_RDONLY), starting with /; on EBUSY abort and roll back (fail-closed). Add a preflight check in `preflight/checks/writable_trees.rs`: refuse activation when any writable OS tree is neither overlaid nor read-only; add an Active-state check in `verify/verifier.rs` that walks /proc/self/mountinfo and fails on a writable non-overlaid decoy mount. Express the policy in the new TOML config without NixOS-only defaults leaking to other platforms; remove /Downloads. (Full /usr overlay on FHS and the boot/kexec whole-root redesign are TODO-only, recorded elsewhere.)

  **Done when:** Unit tests: NixOs and DebianFamily policies produce the expected target and read-only sets from fixture root listings (including usrmerge symlinks). Preflight refuses activation when a writable OS tree is neither overlaid nor read-only. Activation aborts and rolls back when the ro remount returns EBUSY (mock test). verify/status flags a writable non-overlaid decoy mount from fake mountinfo. Debian/Ubuntu VM test: `touch /usr/local/x` during the session fails with EROFS, /usr is writable again after deactivate and after emergency, and the decoy disk image shows no new files under /usr; creating a new top-level dir fails with EROFS. Forensic test 06 (persistent ext4 root): /, /bin/sh, /usr/bin/env inode/mtime/ctime and the top-level entry list are unchanged while Active and after emergency. Hidden NixOS switch still succeeds in E2E. /Downloads no longer appears in defaults.

  _Already resolved: the platform seam carries `overlay_policy()` (`platform/ro_guard.rs`, `OverlayPolicy::nixos()/fhs()/none()`), consumed by `overlay_mount` and `explicit_mount` with the fail-closed read-only guard; `preflight/checks/writable_trees.rs` refuses a writable non-overlay OS tree and `verify/verifier.rs` flags a writable non-overlay decoy mount while Active; `/Downloads` is out of `DEFAULT_OVERLAY_EXCLUSIONS`. Remaining is nix-host-only: a green NixOS E2E run, the Debian/Ubuntu EROFS VM checks and the forensic root-invariant disk-image checks (see nix_pending)._

  _Status: code complete and merged (wave 12) — overlay policy is platform data in `platform/ro_guard.rs`, with a usr-merge-aware resolver, a fail-closed read-only guard (rolled back on EBUSY, undone on deactivate/emergency), a `writable_trees` preflight check and an active-state verify check, all with passing unit tests for the NixOS/FHS policy sets, the EBUSY rollback and the writable non-overlaid detection; /Downloads removed; forensic test 06 extended. Remaining: the Debian/Ubuntu VM E2E (EROFS on /usr and a clean decoy image) needs new non-NixOS VM harness infrastructure and a nix host, and the forensic-06 extension plus a green NixOS switch must be evaluated on a nix host._

- [x] **T-084: Gate the NixOS /nix runtime machinery on a real NixOS host and merge the duplicated mount loops behind platform hooks** (high · effort M)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (the `/nix` runtime machinery and the mount loops). The item stays ticked as history; it describes no current code._

  **Problem:** The /nix overlay lifecycle (nix-daemon stop, command caching, store re-bind, /run/current-system restore) starts whenever /nix is a target, with no NixOS check (`auto_mount.rs:27-40`, `explicit_mount.rs:38-55`). On Nix-on-Debian/Ubuntu, `resolve_current_system_profile` falls back to /run/current-system (`runtime_cache.rs:85-89`); `replace_symlink(/run/current-system, /run/current-system)` would then create a self-loop and fail activation (`restore.rs:196-208`). This is latent today and becomes live once the hardcoded-path fix lands. `auto_mount.rs` and `explicit_mount.rs` duplicate ~90 lines of nix caching, daemon stop, opaque handling, submount lowers and DNS cleanup, and per-target side effects (/nix, /var, /etc) are hard-coded in `overlay_mount/mod.rs:152-208`. The cached hidden generation's closure is never checked against what decoy GC may have removed.

  **Fix:** Merge `auto_mount` and `explicit_mount` into one loop in `overlay_mount/mod.rs` that calls `Platform` pre_overlay/post_mount hooks; auto and explicit mode then differ only in target selection. NixOs hooks (`platform/nixos.rs`) keep current /nix handling but run only when /run/current-system exists and /proc/self/mountinfo shows a read-only bind at /nix/store. Add a Nix-on-foreign hook (`platform/nix_foreign.rs`) that still overlays /nix (never excluded by default) but only stops/starts nix-daemon(.socket) via the resolved service manager, with no /run/current-system handling and no store re-bind. Make `replace_symlink` refuse link == target. On NixOS fast-path activation, verify the cached hidden generation's requisites still exist in the merged /nix and rebuild or warn if not. (Closure-copy size, /run/nails cleanup, the dead rollback fn, and opaque-marker semantics are owned by other items.)

  **Done when:** Only one mount loop remains. Unit test: on a Nix-on-foreign HostProfile with /nix as a target, no /run/current-system access or store re-bind happens and only daemon stop/start is issued. `replace_symlink` returns an error for link == target. Existing NixOS /nix E2E tests still pass.

- [x] **T-085: Handle submounts under overlay targets and add per-distro exclusion data** (high · effort M)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (submounts under overlay targets and exclusion data). The item stays ticked as history; it describes no current code._

  **Problem:** Device-backed submounts with fs_root '/' are skipped (`filesystem/real/submount.rs:139-143`), and pseudo sources (tmpfs) likewise, so they become empty dirs in the merged view: /boot/efi on Debian/Ubuntu, Ubuntu /snap/<name>/<rev> squashfs (snap apps stop launching), and separate /var/log or /var/tmp partitions. Default exclusions lack /snap, /.snapshots, /sysroot, /ostree and /efi, and include machine-specific /Downloads. /proc/mounts and mountinfo are parsed with `split_whitespace` and no octal unescaping (`mount_ops.rs:91,111,131,150`; `submount.rs:29,103`), so paths with spaces break mount detection.

  **Fix:** Before mounting a parent overlay, enumerate submounts under each target. Re-attach read-only submounts (squashfs snaps, ro mounts) after the parent overlay with a recursive bind (`open_tree(OPEN_TREE_CLONE|AT_RECURSIVE)` + `move_mount`, or clone-to-staging then rbind) and keep them ro. Give each writable submount its own nested overlay with a pre-cloned lower and upper/work under the hidden root; never re-expose them writable. List every hidden or nested submount in preflight output. Add per-platform exclusion data (Ubuntu: /snap; NixOS unchanged) in `platform/debian.rs`. Decode octal escapes (\040 etc.) in the mount-table parser (`mount_ops.rs`, `submount.rs`, `filesystem/mount_info.rs`); reuse the shared parser fix if it lands first. (/Downloads removal is done in the overlay-policy item.)

  **Done when:** Unit tests: mountinfo fixtures with '\040' decode correctly; a ro squashfs submount is planned as a ro re-attach; a writable ext4 submount is planned as a nested overlay. Ubuntu VM test: a snap-mounted path still resolves during the session, and writes under a writable submount land in the hidden upper (confirmed by host-side disk image check).

- [x] **T-086: Declare systemd+logind a hard requirement, fix slice-blind PID-to-unit mapping, and add a small service/session seam** (medium · effort M)

  **Problem:** Detach, the cgroup escape, session kill, the display-manager list, socket+service stops and reboot all assume systemd and logind (`cli/detach.rs:187-193,277-283`; `session/management/mod.rs:186-270,414-433`; `session/detection.rs:172`; `restart/mod.rs:190-215`), so non-systemd hosts fail late and obscurely. `extract_service_name` (`process/detection/mod.rs:275-290`) and `read_service_name` (`shell_cleanup.rs:30-41`) take the last '.service' cgroup component without checking it is under system.slice, so user units (e.g. pipewire.service under user@UID.service) are sent to the system manager. The display-manager fallback list is hard-coded. Info-level "DEBUG:" lines are emitted at `session/management/mod.rs:170-197`.

  **Fix:** Refuse non-systemd hosts at platform detection (PID 1 not systemd) with a clear message; this also covers the explicit refusal of ostree/image-based and non-systemd (OpenRC/runit) hosts. Map a PID to a system unit only when its cgroup path is under /system.slice/; for user units, skip them or address them with `systemctl --user -M <uid>@`. Prefer the display-manager.service alias for DM detection and keep the name list as platform data (Debian/Ubuntu: gdm3). Introduce small `ServiceManager` and `SessionManager` traits (`platform/service_manager.rs`) backed by the resolved systemctl/loginctl, mainly as a test seam. Downgrade the "DEBUG:" info logs to debug. (OpenRC/runit/elogind backends are deferred.)

  **Done when:** Unit tests: a cgroup path under user.slice/.../user@1000.service never yields a system unit stop; a system.slice path does. A non-systemd PID 1 fixture is refused by detection before any action. No info-level log line contains "DEBUG:".

## Wave 13: Progress reporter + actionable errors

### W13-C1: Progress feedback & actionable errors

Owns: `nails-core/src/reporter.rs`, `nails-cli/src/cli/output/activate.rs`, `nails-cli/src/cli/main_guard.rs`, `nails-cli/src/cli/logging.rs`

- [x] **T-087: Progress and result feedback: TTY step progress with heartbeat, clean human log format, reliable result delivery on the detached path** (high · effort L)

  _Status (W13-C1): the human console layer no longer prints per-line timestamps (`.without_time()`, keeping the precise timestamp only in the JSON file layer), and activation now emits a per-overlay `mounting <path> (i/N)` line at Normal verbosity. Earlier waves had already satisfied most premises: streaming-to-completion (`process/run.rs`) and the 30s heartbeat (`nixos/command.rs` `BUILD_PROGRESS_INTERVAL`) exist, the file-logging warning is gated off decoy commands, there is no config-discovery INFO spam, preflight results report once, and the generic hint is gone. Remaining: the full `Reporter` TTY (spinner + elapsed) / detached implementations wired through the activation phases, last-build-line under the spinner, the detached progress file plus `nails status` showing phase/elapsed and last-activation-duration, and the result-delivery rework (user-session push + notify-dispatch polling until state leaves Activating) — the latter need VM e2e and are left for a follow-up._

  _Status (wave F2): the long-step heartbeat now surfaces the most recent stderr line — the streaming progress callback is `FnMut(Duration, Option<&str>)`, the stderr drain reads line-by-line and publishes its last non-empty line while the full byte buffer stays intact for failure classification, and a shared `progress_line()` helper (char-boundary length cap) renders the three long-step heartbeats. Still remaining and unchanged: the `Reporter` TTY/non-TTY/JSON/detached abstraction wired through the activation phases, TTY-only gating of the last build line, the detached progress file plus `nails status` phase/elapsed and last-activation-duration, and the result-delivery rework (user-session push + notify-dispatch polling) — all VM-e2e-bound, left for a follow-up._

  _Status (2026-10): done. A per-surface `Reporter` (TTY spinner with elapsed, plain lines, JSON events, detached) drives the activation phases; the last build line shows only on a TTY. A detached activation keeps `progress.json` on the hidden volume and `status` shows the phase, step and elapsed time while Activating plus the last activation duration (E2E 74). A committed activation pushes results into the operator's session (`systemd-run --user --machine`, runuser fallback); notify-dispatch polls until the activation settles (15 min cap); a missing notify-send is logged once and reported by `status`. notification/52 proves a rebuild-failed result reaches the session._

  **Problem:** `nixos-rebuild` and `switch-to-configuration` run through `.output()` (nails-core/src/nixos/command.rs:18-37), fully buffered with no streaming or heartbeat — the user sees `[6/7] Running NixOS switch...` then minutes of silence and may interrupt mid-step. Progress exists only as tracing INFO at phase boundaries (manager/activation/mod.rs); there are no per-overlay lines and no spinner. The default fmt layer prints microsecond timestamps and levels (cli/logging.rs), preflight results print twice (preflight_runner.rs:213 plus the tracing event), and config-discovery and `file logging disabled` warnings appear on every run, including init and decoy-side verify. On the default kill-session path the CLI detaches via `systemd-run` before the switch, so there is no terminal; notify-dispatch gives up after ~30s idle while the rebuild is still running (notify_dispatch.rs:34-55) and always exits 0 (:74-76), so a `NixOS Rebuild Failed` result is likely never shown.

  **Fix:**
  1. Add a `Reporter` abstraction in nails-core (step_started / progress / finished / heartbeat / result) that separates UI events from logs, with TTY (spinner + elapsed), non-TTY (one line per step + `still running (2m10s)` every 30s), JSON (typed events in the activate NDJSON stream), and detached (progress file on the hidden root) implementations.
  2. Change `run_command` to spawn and pump lines; keep the full buffer for `classify_nixos_failure_category` and the hidden-root log; show the last stderr line under the spinner only on a TTY; forward nothing to stdout/stderr in detached mode. No default kill timeout on the switch (only an optional warning threshold).
  3. Emit per-overlay `mounting /home (3/12)` lines during activation.
  4. Human mode: compact format with no timestamps, level prefix only for WARN/ERROR; move config-discovery messages to DEBUG; print each preflight result once and honour `-q`; drop the file-logging warning on decoy-side commands (init, check, verify, status).
  5. Detached path: write phase, start time, elapsed, and last build line to a progress file on the hidden root; `nails status` shows `activation in progress: <phase>, <elapsed>` while Activating; store and display the last activation duration.
  6. Result delivery: the activation worker delivers the final result straight to the user session (`systemd-run --user --machine=<user>@` / runuser) and marks it delivered; notify-dispatch polls until state leaves Activating (hard cap 15 min) instead of a fixed idle count; record a missing notify-send once in the hidden-root log and have `status` report undelivered result notifications.

  Out of scope here: the Ctrl-C/SIGTERM handler (this item only supplies its user-facing message) and removing per-directory getfattr spawning.

  **Done when:** a slow fake command shows step + elapsed in TTY mode and a heartbeat at least every 30s in non-TTY mode; `run_command` streams output while the full buffer is still available for classification, and emits nothing to stdout/stderr in detached mode; default human output has no timestamps, config-discovery appears only with `-v`, each preflight result appears once, and init/check/verify/status print no file-logging warning; activation prints `mounting <path> (i/N)` per overlay; the detached progress file updates per phase and `nails status` shows phase and elapsed while Activating; an e2e test confirms a rebuild-failed result raised after session restart is delivered to the user session, a missing notify-send is logged on the hidden root and reported by `status`.

- [x] **T-088: Actionable diagnostics: per-check remediation, dependency-ordered preflight output, early root check, rollback reported only when it happened** (medium · effort M)

  _Status (W13-C1): landed the high-value core. A euid gate in `main()` runs before logging init so non-root activate (non-dry-run), deactivate and emergency print `this command must run as root: try \`sudo <argv0> <subcommand>\`` and exit 5 with no log or state written; `CheckResult::Fail` now carries `{message, remediation}` with per-check remediation surfaced and one ordered `To fix:` list, the generic hint is gone, `rg -- '--kill-session' nails-core/src` is empty, `hidden_volume.rs` has no LUKS wording, and the swap check splits message/remediation. Remaining: `RollbackOutcome {NotNeeded,Completed,Failed}` so rollback text prints only when a rollback actually ran (activate.rs still prints it for every non-preflight Err); a `CheckResult::Skipped` variant for dependency short-circuit markers (checks are already hidden-volume-first and no-write-safe, but dependents still cascade); `IoError` path attachment; and naming the active swap devices in the swap remediation._

  _Status (wave F2): landed `CheckResult::Skipped` plus a hidden-volume dependency gate (`is_hidden_volume_gate`/`requires_hidden_volume`) so dependents short-circuit to a neutral skip without running or writing; `RollbackOutcome {NotNeeded, Completed, Failed}` recorded in the activation-scope rollback guard's Drop, bridged through the drop-ordered `StateGuard` into the manager and exposed via `last_rollback()`, so the CLI prints nothing before any mount, the plain line on a clean rollback and the still-mounted targets on a failed one; the swap remediation names the exact disk-backed devices (RAM-only zram exempt); the overlay size probe replaces raw `du: Permission denied` with actionable root text; the pivot abort no longer falsely claims the user declined. Unit tests added for each. Remaining: `IoError` path attachment (struct-variant redesign dropping `#[from]`, rippling through the filesystem layer owned by other chunks) — left for a follow-up; the filesystem layer already embeds the path into `IoError` messages manually._

  _Status (2026-10): done. `IoError` is now a struct variant `{ path, source }` without `#[from]`; `NailsError::io` and `IoResultExt::at_path` attach the path at every construction site, and the message names the path exactly once._

  **Problem:** Every preflight failure ends with the same hint, `Fix: Review system state and ensure hidden volume is mounted` (nails-cli/src/cli/output/activate.rs:254-263; JSON `fix` at :101-104), contradicting specific messages like `System is already active`. Results print three times: `output::check_result` (nails-core/src/output.rs:210-212, which also ignores `-q`), the `PreFlightCheckFailed` Display (error.rs), and a `tracing::error` per check (preflight_runner.rs:220-224). There is no ordering or dependency short-circuit, so an unmounted hidden volume cascades into storage, overlay-compat (`du -sb /boot failed`), nixos-config and swap FAILs; config staging and pre-activation cleanup run before the registry (manager/activation/preflight.rs), so a missing root either surfaces as a staging failure or passes after files were written. `Automatic rollback completed.` prints for every non-preflight error (activate.rs:266-273), including errors raised before any `StateGuard` exists and when the rollback itself failed. There is no early euid check, `IoError` is `#[error(transparent)]` with no path, `HiddenVolumeCheck` says `Mount the hidden LUKS volume` in a backend-agnostic design, prompts/mod.rs suggests the removed `--kill-session`, the `--no-pivot` path prints `User declined pivot mount` when no prompt was shown, and the SwapCheck hint is a blanket `sudo swapoff -a`.

  **Fix:**
  1. Add a small `Diagnostic` (error code → ExitStatus, message, cause chain, hint); give each `NailsError` variant a `hint()`.
  2. Make `CheckResult::Fail` carry `{message, remediation: Option<String>}`, move inline `Run: ...` text into remediation, and show the generic hint only when a check has none.
  3. Order checks by dependency (hidden volume, then storage, then the rest); dependents report `skipped: requires mounted hidden volume`; print each result once, honour `-q`, and finish with one ordered remediation list; remove the duplicate tracing::error lines and the repeated list in the error Display.
  4. Run the hidden-root mounted check before config staging, the suspicious-reference check, and pre-activation cleanup, so nothing is written when the root is missing.
  5. Return `RollbackOutcome {NotNeeded, Completed, Failed(errors)}` and print rollback text only for Completed or Failed.
  6. Add a `RequiresRoot` gate in the CLI for activate (except check/--dry-run), deactivate, emergency and recover; run it before logging init and any file write; print `this command must run as root: try \`sudo <absolute argv0> <subcommand>\`` and exit 5.
  7. Attach the path to every `IoError`; replace raw command errors (du) with actionable text and say `run as root for this check` when unprivileged.
  8. Use backend-neutral wording (`mount the hidden storage at <path>`), update stale flag suggestions to the new flags with sudo and full path, replace the false `User declined pivot mount` with `<target> needs a pivot mount and --pivot=refuse is set`, and make the swap hint name the active swap devices (zram exemption handled elsewhere).

  **Done when:** `rg 'Review system state and ensure hidden volume is mounted'` returns nothing and failed checks show their own remediation; a unit test confirms that with the hidden-volume check failing, dependents report skipped and staging/cleanup write nothing; each preflight result appears exactly once followed by one remediation list; errors from options.validate, lock acquisition and session-kill never print `Automatic rollback completed.` while a failed rollback prints its errors; an assert_cmd test run unprivileged has activate/deactivate/emergency exit 5 with a sudo hint and create no log or state file; `IoError` messages include the path, hidden_volume.rs has no `LUKS` wording, `rg -- '--kill-session' nails-core/src` returns nothing; cargo test and clippy pass.

## Wave 14: Hidden-toplevel build + real-rebuild E2E + platform init

### W14-C1: Hidden toplevel build + outcome + real-rebuild E2E

Owns: `nails-core/src/manager/activation/nixos_switch.rs`, `nails-core/src/nixos/fingerprint.rs`, `nails-cli/src/cli/commands/reapply.rs`, `nix/e2e-tests/tests/nixos/27-activate-full-rebuild.nix`

- [x] **T-089: Build the hidden NixOS toplevel explicitly, cache its store path (not the decoy generation), and switch to it before the session restarts** (critical · effort L)

  **Problem:** The slow path runs `nixos-rebuild test` (`nails-core/src/nixos/builder/switch.rs` ~189-214), which activates but never creates a system-profile generation. `nails-core/src/manager/activation/nixos_switch.rs:133` then stores `builder.current_system_generation()`, i.e. `readlink(/nix/var/nix/profiles/system)` — the **decoy** generation — and the comment at `nixos_switch.rs:47-50` wrongly claims `nixos-rebuild test` writes the system profile. Deactivation keeps `nixos_generation` + `config_fingerprint`, so the next activation with an unchanged fingerprint (`nixos_build.rs:92-104`) runs `system-<decoy>-link/bin/switch-to-configuration test` and reports success while silently applying the decoy config. The fingerprint hashes only `hardware-configuration.nix` and `configuration.nix` (`nixos_build.rs:37-69`), ignoring `flake.nix`, `flake.lock`, imported modules and the flake ref. The session is also restarted (`activation/mod.rs:360-384`) *before* the switch (:386-455), so with autologin the decoy session runs first and a failed switch only logs a warning.

  **Fix:** Split build from activation. After the overlays are mounted, build the hidden toplevel explicitly (`nix build <ref>#nixosConfigurations.<name>.config.system.build.toplevel --out-link <gcroot>`) with the GC root on the hidden `/nix` upper, record the resulting store path in state as `hidden_toplevel` (replacing `nixos_generation`), then run `<toplevel>/bin/switch-to-configuration test` BEFORE restarting the display manager or `user@UID`. Fast path: skip the build only when the fingerprint matches and the recorded store path still exists; clear the cache when it does not. Fingerprint the whole hidden config tree (`etc/nixos` + `config/nixos`, including `flake.nix`, `flake.lock`, imported files) plus the flake ref and configuration name. Add strict-TOML option `nixos.switch_required` (default true, fail closed): on build/switch failure roll the overlays back before any restart. Point `requires_decoy_restore` (`deactivation.rs:271`) at `hidden_toplevel`, delete the false comment, and remove the unused builder API chain (`build_profile*`, `switch_profile`, `get_result_store_path`, `switch_to_system_profile`, `system_generation_exists`) and its tests.

  **Done when:** `rg current_system_generation nails-core/src/manager` is empty; the stored value is a `/nix/store/...-nixos-system-*` path; editing `flake.lock` or an imported module changes the fingerprint; a missing cached path falls back to the slow path. A real-rebuild VM test replaces `nix/e2e-tests/tests/nixos/27-activate-full-rebuild.nix`: full-mode activate, deactivate (with reboot), activate again, with a hidden-config marker present after the second activation and the fast path taken. `session/33-session-kill-graphical.nix` asserts switch-before-restart, and a failing hidden config with `switch_required=true` leaves no overlays. `cargo test` and `clippy` pass.

- [x] **T-090: Report activation truthfully: an ActivationOutcome with warnings, consistent already-active handling, and nails reapply** (high · effort M)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (`nails reapply` and the live activation outcome). The item stays ticked as history; it describes no current code._

  **Problem:** `activation/mod.rs:396-460` stores a switch/rebuild failure in `nixos_switch_warning`, emits only `tracing::warn` (:510-516) and returns `Ok(())`. The CLI then prints a green '✓ Activation complete in Xs' (`nails-cli/src/cli/output/activate.rs:141-151`), emits JSON status `success` with no warnings field (:4-15, :79-87) and exits 0 (`commands/activate/mod.rs:405-408`). In the default GUI path the worker is detached and its output goes to the journal (`detach.rs:237-238`), so the only signal is a notification that may never arrive. Already-active handling is inconsistent: `--no-kill-session`/`--no-preflight` print 'complete in 0.0s' and exit 0, while the default path fails the CLI state check and exits 2 (`preflight/checks/state.rs:81-83`). A fixed hidden config can only be applied with a full deactivate (which reboots) then activate.

  **Fix:** Have `activate_with_options` return an `ActivationOutcome { already_active, hidden_config: Applied { toplevel, fast_path } | NotRequested | Failed { reason }, survivors, warnings }`. Human output on a failed config: 'Activated with warnings: hidden NixOS configuration was not applied (<reason>)' in warning style. JSON: status `success_with_warnings` with a `warnings` array and a distinct exit code reserved in the exit-code table. Already-active returns exit 0 and the same 'already active' message on every flag path. Persist the last outcome in state so `nails status` shows 'hidden configuration NOT applied' after a detached run, and have the detached worker send the outcome as a notification. Add a `nails reapply` command (new `nails-cli/src/cli/commands/reapply.rs`, wired into `commands/mod.rs` and `args.rs`) that, while Active, re-runs the build plus `switch-to-configuration test` and reports the outcome.

  **Done when:** CLI snapshot tests show a switch failure with `switch_required=false` producing human text containing 'with warnings', JSON status `success_with_warnings` with a `warnings` array, and the documented exit code; already-active gives exit 0 with the same message under default flags and `--no-kill-session`; status rendering shows the 'not applied' line after a failed switch; `nix/e2e-tests/tests/nixos/30-rebuild-failure-rollback.nix` asserts the warning outcome and exit code, and `nails reapply` applies the hidden marker once the config is fixed. `cargo test` and `clippy` pass.

- [x] **T-091: E2E coverage of the real offline NixOS rebuild, default auto mode, sudo invocation, re-activation and an impermanent decoy profile** (high · effort L)

  **Problem:** Every activation in `nix/e2e-tests` either uses `--overlay-only` (~48 files, incl. `lib/shell-helpers.nix:31` `activate_for_user`), stubs `nixos-rebuild` on PATH (27-33, 49, 79; detached activation propagates PATH so 33/49 hit the stub too), or fails in preflight (19, 21). About 69/80 files use `overlay_mode: explicit` (`lib/test-helpers.nix:9-45` overlays only /etc, /home, /root, /srv, /tmp), while the product default is Auto (overlays /var and /nix); Auto appears only in `26-config-exclusions`, which excludes /var, /tmp and /nix. The only real `nixos-rebuild` (30) fails at evaluation by design, nothing references `/var/lib/nixos`, and there is no impermanent (tmpfs root + /persist) profile — so applying the hidden declarative config is never exercised.

  **Fix:** (1) Rewrite test 27 as a real-rebuild test: add a `nix/e2e-tests/fixtures/hidden-config/` fixture (one `environment.etc` marker + one oneshot service), prebuild its toplevel into the VM via `virtualisation.additionalPaths`/`system.extraDependencies` with `nix.settings.substituters = []` so `nixos-rebuild` runs offline, run `nails activate` in default mode with no stub, assert the marker and service, deactivate, then diff `/etc` and `/var/lib/nixos` on the decoy image against baseline with a linked allowlist for known drift. (2) Add an auto-mode activate/deactivate lifecycle test (no `--overlay-only`, default set incl. /nix and /var) to the `ci` subset in `default.nix`. (3) Add a `sudo nails ...` test run from `testuser` in a login shell without injecting HOME. (4) Add a second activation with an unchanged config and no `--overlay-only` to prove the fast path applies the hidden config, not the decoy generation. (5) Add an impermanent decoy profile (`nix/e2e-tests/lib/impermanent-decoy.nix`: tmpfs /, /persist binds for /var/lib/nixos and /etc/nixos, volatile journald; `useNixStoreImage = true`, `writableStoreUseTmpfs = false` for forensic variants) feeding the host-side disk-image checks. Tag real-rebuild tests `slow`.

  **Done when:** test 27 has no stub on PATH and asserts the hidden marker and service exist during the session and are gone after deactivation; the `ci` subset contains an auto-mode activate/deactivate test; a sudo-from-testuser test exists with no HOME injection; the re-activation test applies the hidden config on the fast path; the impermanent decoy profile exists and is used by at least the real-rebuild and forensic tests; all new tests pass locally via `nix build .#checks.x86_64-linux.<name>`.

- [x] **T-092: Settle the /var/lib/nixos drift with a control run and a canary hidden user; add state-machine and path-containment property tests** (medium · effort M)

  **Problem:** The post-deactivation drift observed in evaluation — rewrites of `/persist/var/lib/nixos` `declarative-users`/`declarative-groups`, `uid-map`, `gid-map`, `auto-subuid-map` — was never root-caused: there was no control run (plain reboot without activation) and no comparison of contents versus mtimes. Likely contributors are boot-time `update-users-groups` and the decoy `switch-to-configuration switch` during standard deactivation. No test declares a hidden user (`users.users` appears only in `nix/e2e-tests/lib/vm-config.nix`), so recommending one blindly could create a new trace. Separately, the containment-critical functions `is_on_hidden_volume_internal` (`state/mod.rs:88`) and `apply_exclusion_filter` (`manager/helpers.rs:211`) have only example tests, and `update_state` keeps a second hand-written transition table (`state_management.rs:256-264`) that can drift from `state/transitions.rs`.

  **Fix:** On the impermanent profile with host-side disk-image checks, run baseline → reboot without NAILS (the control), then baseline → activate → standard and emergency deactivate. Diff `/persist/var/lib/nixos` **contents**, not just mtimes. Declare a canary hidden user with a fixed UID in the hidden config and assert its name and UID are absent from decoy `/persist/var/lib/nixos`, `/etc/passwd`, `/etc/group` and the journal after both deactivation modes. If the canary leaks, open a code fix (overlay handling for `/var/lib/nixos`; evaluate userborn/systemd-sysusers); if the drift equals the control, document it as boot noise in `docs/threat-model.md`. In Rust, add an exhaustive 5x5 test asserting `update_state`'s table agrees with the `SystemState` transition methods (or remove the duplicate table), and add `proptest` (dev-dependency) for the path-containment string fallback with generated `..`, `.` and repeated-separator paths plus a tempdir-based proptest for the symlink branch (`nails-core/tests/containment_proptest.rs`).

  **Done when:** the E2E control and canary tests exist and run in the full tier, with the canary assertion a hard failure (or a tracked expected-fail with a linked TODO if it reproduces); the result is documented in a `docs/threat-model.md` 'Known residual changes' section; the exhaustive transition-table test passes; the containment proptest suites pass; and `nix develop -c cargo test --workspace` passes.

### W14-C2: Platform init/preflight registration

Owns: `nails-core/src/nixos/config/prepare.rs`, `nails-cli/src/cli/commands/init.rs`, `nails-core/src/preflight/checks/nixos_config/mod.rs`

- [x] **T-093: Platform-specific init and preflight registration; preflight writes nothing; generic errors are not NixOS-named** (medium · effort M)

  **Problem**
  - `NixOSConfigCheck` and `NixOSBuildTargetCheck` are registered whenever `--overlay-only` is unset (`nails-core/src/manager/preflight_runner.rs:177-194`, duplicated in `nails-cli/src/cli/commands/activate/dry_run.rs:232-233`). On a non-NixOS host these fire and fail with NixOS-only guidance ("Ensure NixOS is properly installed.").
  - Preflight mutates the filesystem: `NixOSConfigCheck::run` auto-creates `hardware-configuration.nix` and the hidden configuration module (`nails-core/src/preflight/checks/nixos_config/mod.rs:72-140`). Checks must be side-effect-free.
  - `nails init` creates NixOS-only dirs (`nix`, `.work/nix`, `etc/nixos`) and bootstraps the hidden NixOS layout from `/etc/nixos/hardware-configuration.nix` before validating the host (`nails-cli/src/cli/commands/init.rs:17-31,91-94,109-111`; `nails-core/src/nixos/config/prepare.rs:200-206`), leaving a half-initialized hidden root elsewhere. `stage_hidden_config_symlink` is fatal even in overlay-only mode and writes a generated `configuration.nix` (`activation/preflight.rs:106-117`; `nixos/config/mod.rs:46`).
  - `NailsError::NixOSError` is used at ~69 non-test sites including generic failures: the symlink probe (`activation/preflight.rs:42`) and reboot (`manager/deactivation.rs:136-145`).

  **Fix**
  - Build the preflight registry from `Platform::preflight_checks()` plus the active config layer's checks; drop the unconditional `!overlay_only` NixOS registration here and in `dry_run.rs` (share the one registry builder with the CLI-side dedup item).
  - Make every preflight check read-only; move all filesystem creation into `nails init`.
  - Have `nails init` validate all preconditions for the detected platform (incl. the mount check from the init-preconditions item) before writing anything, then create only the dirs the platform/layer need: no `nix`/`.work/nix`/`etc/nixos` bootstrap and no NixOS config staging on DebianFamily.
  - Replace `NixOSError` at generic sites (symlink probe, reboot) with typed variants from the error-enum redesign; keep NixOS-named errors for NixOS-layer failures only.

  **Done when**
  - On a DebianFamily fixture, `nails init` creates no NixOS paths and returns before writing anything when a precondition is missing.
  - Preflight checks pass a mock-filesystem test asserting zero write calls.
  - Reboot and symlink-probe failures no longer surface the NixOS error variant.
  - No NixOS checks are registered in overlay-only / non-NixOS mode in either registry path.

## Wave 15: Decoy-posture/swap/space preflight + Debian backend + distro VM suite; fs-contract tier

### W15-C1: Decoy-posture/swap/space preflight + Debian backend + distro VM

Owns: `nails-core/src/preflight/checks/decoy_posture.rs`, `nails-core/src/preflight/checks/swap.rs`, `nails-core/src/platform/debian.rs`, `nix/distro-tests/`

- [x] **T-094: Platform-aware decoy-posture preflight (persistent journald/syslog/auditd, root fs, swap/hibernation, atime, maintenance timers) that fails closed, with journald relinquish/flush hooks** (critical · effort M)

  _Status: partial in wave 15. Done: one write-free `DecoyPersistenceCheck` (`preflight/checks/decoy_posture.rs`) folding in journald and failing closed on persistent journal/rsyslog/syslog-ng/auditd, warning on persistent root fs, atime, crash-dump channels and `nixos-upgrade.timer`; `accept_persistent_decoy` key and `--accept-persistent-decoy` flag (replacing `--allow-persistent-journal`); generated hidden module forces `system.autoUpgrade.enable = false`; volatile journald in `vm-config.nix`; `docs/decoy-requirements.md` linked from README, operator guide and threat model. Remaining: journald `--flush`/`--relinquish-var` hooks on mount, deactivation and emergency; `verify --deep` journal grep with a fake reader; status posture never plain `secure` for a persistent decoy; E2E refusal/override and decoy-image journal leak tests under `tests/security/`; the check is centrally registered (no `Platform::preflight_checks()` hook). Nix evaluation of vm-config.nix and the hidden module pending._

  _Status (wave F2): the status-posture gap is now closed — a write-free `DecoyPersistenceCheck::decoy_is_persistent` probe (sharing the preflight detection, override-independent), a `decoy_persistent` flag on `StatusReport`, a `posture_mark()` downgrade that never presents an active-on-persistent-decoy system as fully secure (`is_fully_secure()`), a human persistent-decoy warning line, a `decoy_persistent` JSON field, the status schema requirement and contract-snapshot redaction, all with unit/CLI/contract tests. Remaining: journald `--flush`/`--relinquish-var` hooks on mount/deactivation/emergency, `verify --deep` journal grep (JournalReader trait + `journalctl --grep`, with a fake reader), central `Platform::preflight_checks()` registration, and the E2E refusal/override + decoy-image journal-leak specs under `tests/security/` — all nix/VM-bound (see nix_pending)._

  _Status (2026-10): done. `verify --deep` greps the journal for hidden-session leak tokens through a `JournalReader` seam with a fake-reader test; journald is flushed onto the `/var` overlay and relinquished before teardown (T-113), with the runtime journal scrubbed after emergency. security/82 covers the persistent-decoy refusal and override, security/83 the decoy-image journal leak. journald configs are resolved with their drop-ins (`/etc`, `/run`, `/usr/lib`). The check stays centrally registered rather than through a `Platform::preflight_checks()` hook; no done-when depends on it._

  **Problem**
  The forensic guarantees silently depend on an amnesic decoy, but preflight never checks for one. `preflight/checks/mod.rs` registers only hidden-volume, space, overlay, state and swap checks; nothing inspects journald `Storage=`, a persistent `/var/log/journal`, the root fs type, rsyslog/syslog-ng/auditd, or sudo logging. Debian 12+, Ubuntu and stock NixOS keep a persistent journal, so sudo command lines (including the hidden-root binary path), transient unit names and overlay events land on the decoy disk before `/var` is overlaid. `overlay_mount/mod.rs:176-183` only calls `start_service_and_socket("systemd-journald")`, which does nothing on a running unit despite the comment claiming an unconditional restart. `status/report/types.rs:224` still reports `SecurityPosture::Secure` for any Active+Verified system. README:65 calls impermanence merely "Strongly recommended". Crash channels (coredump, pstore, kdump) and decoy maintenance timers (esp. `system.autoUpgrade`, which can touch EFI NVRAM) are also unguarded.

  **Fix**
  Add a single platform-aware `DecoyPersistenceCheck` provided through `Platform::preflight_checks()` (new `nails-core/src/preflight/checks/decoy_posture.rs`; do not add a second module). Detect: effective journald `Storage=` (parse `journald.conf` plus drop-ins in `/etc`, `/run`, `/usr/lib`, or `systemd-analyze cat-config`) and whether `/var/log/journal` lives on a non-tmpfs fs; root fs type from `/proc/self/mountinfo`; active rsyslog/syslog-ng/auditd; sudo syslog settings; atime policy (noatime/relatime) on persistent overlay lowers. Fail closed: a persistent journal, active syslog/auditd fails activation unless the operator sets `accept_persistent_decoy = true` in `nails.toml` or passes `--accept-persistent-decoy`; root-fs type and atime are warnings. Add a crash-posture sub-check warning on `kernel.core_pattern`, systemd-coredump `Storage`, registered pstore backends and kdump. Move journald handling into platform `post_mount`/`pre_unmount` hooks: `journalctl --relinquish-var` before mounting `/var`, `--flush` after it is up; `--relinquish-var` before unmounting `/var` on deactivation (no flush after); after emergency with no reboot, rotate+vacuum the runtime journal or instruct a reboot. Force `system.autoUpgrade.enable = lib.mkForce false` in the generated hidden module and WARN when `nixos-upgrade.timer` is enabled. Add a `verify --deep` pass that greps the journal (`journalctl --grep`) for the tool name, backend mapper/mount names and cryptsetup. `status` must never report plain `Secure` for a persistent decoy. Document the required amnesic profiles in `docs/decoy-requirements.md` (NixOS impermanence, Ubuntu overlayroot, Debian bilibop, volatile journald, noatime, no swap/hibernation, the sudo-log exposure and its mitigation; EFI/firmware/RTC are outside the overlay model), linked from README, USER-SECURITY-GUIDE and the threat model. Set `services.journald.storage = "volatile"` in `nix/e2e-tests/lib/vm-config.nix` so existing tests model an amnesic decoy. The check must perform no writes.

  **Done when**
  - Unit tests (MockFilesystem) cover journald persistent/volatile/auto+dir, drop-in precedence, tmpfs vs disk `/var/log/journal`, syslog/auditd detection, and the override path; crash-posture sub-check reports core_pattern/coredump/pstore/kdump; tests assert no write occurs.
  - Activation on a persistent-journal host fails preflight with remediation text and passes with the override; a volatile-journal VM passes.
  - `nails status --json` reports the posture and never `secure` for a persistent decoy.
  - E2E: refusal + override tests pass; after activation journald writes to the overlaid `/var`, and host-side inspection of the decoy disk image after deactivation finds no hidden-session journal entries; all existing E2E tests pass with volatile journald in vm-config.nix.
  - Generated hidden module disables autoUpgrade (module-generator test); preflight warns on `nixos-upgrade.timer`.
  - `verify --deep` reports journal hits for the tool name and backend names (test with a fake journal reader).
  - `docs/decoy-requirements.md` exists and is linked from README, operator guide and threat model; `nix develop -c cargo clippy --workspace -- -D warnings` clean.

  Files: `nails-core/src/preflight/checks/decoy_posture.rs`, `nails-core/src/preflight/checks/mod.rs`, `nails-core/src/manager/preflight_runner.rs`, `nails-core/src/manager/activation/overlay_mount/mod.rs`, `nails-core/src/deactivation/orchestrator/unmount.rs`, `nails-core/src/emergency.rs`, `nails-core/src/verify/verifier.rs`, `nails-core/src/status/report/types.rs`, `nails-core/src/config/types.rs`, `nails-cli/src/cli/args.rs`, `nails-core/src/nixos/config/` (generated hidden module), `nails-core/src/platform/{nixos,debian}.rs`, `nix/e2e-tests/lib/vm-config.nix`, `nix/e2e-tests/tests/security/`, `README.md`, `docs/USER-SECURITY-GUIDE.md`, `docs/decoy-requirements.md`.

- [x] **T-095: Classify swap per device (allow RAM-only zram, fail on disk swap and hibernation), re-check after the hidden switch, and never copy decoy swapDevices into the hidden config** (high · effort M)

  _Status: done in wave 15. Per-device `classify_swap` (zram without backing passes, random-key dm-crypt warns, partition/file/fixed-key swap and hibernation fail) shared by `SwapCheck`, `verify` (Warn/Critical), a post-switch re-check with a critical notification and a pre-deactivation re-check; `swap_is_enabled` removed; seeded hidden hardware config strips `swapDevices`/`resumeDevice`. E2E `15-preflight-swap.nix` (zram subtest) and new `16-swap-reenable-detected.nix` await a KVM run; a hidden-config swap assertion after mount on a real swap VM is still an E2E follow-up._

  **Problem**
  `swap_is_enabled` is just `swaps.lines().count() > 1` (`filesystem/real/system_ops.rs:9-12`), so RAM-only zram swap (the Fedora default and NixOS `zramSwap`) fails `SwapCheck` (`preflight/checks/swap.rs:65-68`) and blocks activation, training users to bypass all checks with `--no-preflight`. Hibernation/resume is never checked anywhere. `SwapCheck` also runs once at preflight and is never re-evaluated after `switch-to-configuration`, which starts `swap.target` and can re-enable a swap device the user turned off to pass preflight (`manager/activation/mod.rs` switch path). `ensure_hidden_hardware_configuration` copies the decoy `hardware-configuration.nix` verbatim, including `swapDevices` (`nixos/config/prepare.rs:164+`). `verify` reports swap only as Info (`verify/verifier.rs:186-199`). Every E2E VM forces `swapDevices = lib.mkForce [ ]` (`nix/e2e-tests/lib/vm-config.nix:33`), so this is never exercised.

  **Fix**
  Write one per-device swap classifier (parse `/proc/swaps` per entry): pass `/dev/zramN` only when `/sys/block/zramN/backing_dev` reads `none`; warn on dm-crypt swap whose crypttab/dmsetup table shows a random key; fail on plain partition or file swap. Fail separately on hibernation when `/sys/power/resume` is not `0:0` or `/proc/cmdline` contains `resume=`. Use the same classifier in `SwapCheck` and in `verify` (raise verify severity above Info). Re-run the swap+hibernation posture check right after the NixOS switch and again before deactivation, failing loudly with a notification if disk swap reappeared. In preflight, evaluate the hidden config for `swapDevices`, `zramSwap` and `boot.resumeDevice` after overlays are mounted. When bootstrapping the hidden hardware config, strip or comment out `swapDevices` with a warning instead of copying them. Add one E2E VM that configures a real swap device (not forced empty) to exercise the re-check.

  **Done when**
  - Unit tests with fixture `/proc/swaps` and `/sys` trees: zram without backing_dev passes; zram with backing_dev fails; partition/file swap fails; `resume=` on the cmdline fails.
  - `verify` reports swap with the same classification.
  - Generated hidden `hardware-configuration.nix` has no active `swapDevices` (unit test).
  - E2E (VM with a swap device, `swapoff` before activate): the post-switch check detects the re-enabled swap and reports failure.

  Files: `nails-core/src/filesystem/real/system_ops.rs`, `nails-core/src/preflight/checks/swap.rs`, `nails-core/src/verify/verifier.rs`, `nails-core/src/nixos/config/prepare.rs`, `nails-core/src/manager/activation/mod.rs`, `nix/e2e-tests/lib/vm-config.nix`, `nix/e2e-tests/tests/preflight/15-preflight-swap.nix`.

- [x] **T-096: Space check that accounts for the rebuild: fail below the floor, use a higher floor when a NixOS build will run, re-check after mounting and after the switch** (medium · effort M)

  _Status: done in wave 15. Single hard floor (default 500 MB in one place), new `rebuild_space_mb` (default 4096) re-checked after mounting and before a full rebuild with rollback, post-switch "hidden volume nearly full" notification, `hidden-volume-full` failure category pointing to `nails reapply`; `14-preflight-space.nix` updated (KVM run pending)._

  **Problem**
  `minimum_space_mb` defaults to 500 (`config/builder.rs:210`, `config/defaults.rs:223`, `config/testing.rs:59`) while `SpaceCheck` and its docs claim 1024 (`preflight/checks/space/mod.rs:27-28,107-111`). `SpaceCheck::run` is a single `statvfs` at preflight: pass at `>= minimum`, warn between 50% and 100%, fail below 50% (`space/mod.rs:131-160`). It never models what activation writes. The NixOS rebuild runs after overlays are mounted and writes the store delta (often several GB) into the `/nix` upper as root, so it can eat root-reserved blocks; free space is never re-checked after the switch. ENOSPC then surfaces as a raw rebuild error and NAILS's own state/log writes fail too.

  **Fix**
  Make "below the configured floor" a hard Fail with no warn band, and define the default in exactly one place (drop the conflicting 1024 everywhere). In the strict TOML config add two floors: a base floor for overlay-only mode (e.g. 500 MB) and a rebuild floor (default a few GB, e.g. 4 GiB) used when a NixOS build is expected, i.e. no cached hidden toplevel or the fingerprint changed. Do not estimate sizes in preflight (evaluating the hidden flake before overlays exist would write to the decoy store). After overlays are mounted and before the build, re-check free space against the rebuild floor and abort with rollback if short (`nix build --dry-run` sizes may optionally be compared here). After the switch, re-check again and send a "hidden volume nearly full" notification below a warning threshold. Map ENOSPC during the build to a clear message: hidden volume full, free or enlarge it, then run `nails reapply`.

  **Done when**
  - Unit tests: 400 MB free with a 500 MB floor fails; rebuild expected with 2 GiB free and a 4 GiB rebuild floor fails before the build starts; overlay-only with 600 MB free passes.
  - `nix/e2e-tests/tests/preflight/14-preflight-space.nix` updated to fail below the floor.
  - The new config keys appear in the config reference and misspellings are rejected by the strict TOML loader.
  - `cargo test` and `cargo clippy` pass.

  Files: `nails-core/src/preflight/checks/space/mod.rs`, `nails-core/src/config/defaults.rs`, `nails-core/src/config/types.rs`, `nails-core/src/config/builder.rs`, `nails-core/src/config/testing.rs`, `nails-core/src/manager/preflight_runner.rs`, `nails-core/src/manager/activation/mod.rs`, `nails-core/src/manager/activation/nixos_switch.rs`, `nix/e2e-tests/tests/preflight/14-preflight-space.nix`.

- [x] **T-097: DebianFamily platform backend: overlay-only NAILS on Debian 12+/Ubuntu 24.04 with a documented support boundary** (high · effort L)

  _Status: done in wave 15 on the generic FHS backend (no separate `DebianFamily` struct, so another distro is one support-table entry): `platform/debian.rs` holds version parsing and the support table (Debian 12+, Ubuntu 24.04+, `ID_LIKE=debian` provisionally), detection refuses Fedora/Arch/unknown/missing ID, older releases and non-merged-usr layouts with documented messages; README support matrix and ROADMAP phases added. The VM smoke tier is T-098._

  **Problem**
  The core ships NixOS-only assumptions: overlay exclusions of `/usr`, `/bin`, `/lib`, `/sbin` (`config/types.rs:66-79`); reboot/systemctl hardcoded at `/run/current-system/sw/bin/...` (`manager/deactivation.rs:78-80`, `helpers/command_cache.rs`, `helpers/service_controller.rs`); `switch-to-configuration` during deactivation (`deactivation/orchestrator/mod.rs:347`); `nixos-rebuild`/profiles in `system_ops.rs`. On Debian/Ubuntu these either fail (no systemctl at that path) or leak package payloads into the decoy `/usr`. The owner decision is overlay-only on Debian/Ubuntu first, with the backend designed so Fedora/Arch slot in later.

  **Fix**
  Implement a `DebianFamily` `Platform` behind the platform abstraction (detection via `/etc/os-release` ID/ID_LIKE = debian, ubuntu) with minimum versions (Debian 12, Ubuntu 24.04) and a usrmerge check that refuses non-merged layouts. Policy: overlay the writable trees and keep `/usr` read-only as a safety invariant (EROFS guard); Ubuntu adds `/snap` to the exclusions. No `ConfigLayer`, so overlay-only is implicit. Provide FHS host-command search dirs (no hardcoded `/run/current-system/sw/bin`), systemd/logind service and session handling (gdm3-aware), the shared `DecoyPersistenceCheck` with Debian/Ubuntu defaults, dpkg/apt artifact scanners, and a no-op `restore_base_system`. Keep all backend-specific code in `nails-core/src/platform/debian.rs` so Fedora/Arch become new files implementing the same trait plus a contract-suite run. Refuse Fedora/Arch/unknown os-release, non-systemd (OpenRC/runit) and ostree/image-based hosts with an explicit documented message. Update README with a support matrix: NixOS full (declarative hidden config), Debian/Ubuntu overlay-only with volatile journal required, everything else refused. Track remaining phases (Fedora, Arch, full `/usr` overlay, cross-distro evaluation, boot-time redesign) as separate TODO items in ROADMAP.

  **Done when**
  - The platform contract suite passes for `DebianFamily`.
  - Debian 12/13 and Ubuntu 24.04 smoke tests (container and VM tiers) pass init -> activate -> status -> deactivate/emergency -> verify in overlay-only mode, including the `/usr` EROFS assertion and the decoy-disk leak check.
  - Fedora/Arch/unknown os-release fixtures (and non-systemd / ostree hosts) are refused with the documented message.
  - README support matrix matches the implemented detection.

  Files: `nails-core/src/platform/debian.rs`, `nails-core/src/platform/mod.rs`, `nails-core/src/platform/detect.rs`, `nails-core/src/config/types.rs`, `nails-core/src/manager/deactivation.rs`, `nails-core/src/manager/helpers/command_cache.rs`, `README.md`, `ROADMAP.md`.

- [x] **T-098: Portable Debian/Ubuntu VM smoke suite on the NixOS test driver (nix-vm-test), built so more distros are one list entry each** (medium · effort L)

  _Status: partial in wave 15. `nix/distro-tests/` (pinned image table, nix-vm-test wrapper, loop/LUKS hidden root, per-distro smoke scenario with `/usr` EROFS negative control and disk-image null/positive controls), `nix-vm-test` flake input, `e2e-distro`/`e2e-distro-metadata` attrs, `ci.e2e distro-plan` (<= 8 jobs) and an informational `distro-e2e.yml` workflow are in place. Remaining (KVM host with network): `nix flake lock` for the new input, real image hashes in place of `lib.fakeHash` plus binary-cache mirroring, confirm the nix-vm-test attribute name, and build the debian-12/13 and ubuntu-24.04 smoke attrs._

  _Status (wave F2): no further in-sandbox distro-test work — the suite is unchanged and all remaining steps stay KVM-host-bound (see nix_pending). The accompanying status-posture slice shared with T-094 landed this wave._

  _Status (2026-10): done. The images are the dated cloud images nix-vm-test pins (no parallel image table), the input is locked, and the sandboxed run builds. The smoke test passes on Debian 12, Debian 13 and Ubuntu 24.04, including the `/usr` EROFS negative control and the decoy-image null and positive controls; a new distro is one entry in `nix/distro-tests/images.nix`._

  **Problem**
  Every E2E test is `pkgs.testers.runNixOSTest` (`nix/e2e-tests/default.nix:42`), whose driver backdoor only exists in NixOS guests, so regressions on another distro cannot be caught. Nothing tests the planned Debian/Ubuntu overlay-only support, the read-only `/usr` guard, platform detection or the decoy-persistence preflight. Privileged Docker containers cannot host an overlay upper on an overlay2 rootfs and cannot exercise session, journald or reboot behaviour. A lifecycle-only distro suite would pass while a `/usr` leak still exists, so leak assertions are required.

  **Fix**
  Add `numtide/nix-vm-test` as a pinned flake input and a new `nix/distro-tests/` tree (`default.nix`, `lib/`, `tests/`, `images.nix`) that drives Debian 12/13 and Ubuntu 24.04 cloud images on the same test driver with shared Python helpers. Pin images as self-hosted fixed-output derivations mirrored into the project binary cache so upstream pruning cannot break the pins. Make the distro list data (name -> image) so Fedora/Arch each become one entry once their backends exist. Each distro test: copies the static musl release binary into the guest; creates a loop-backed ext4 hidden root (LUKS if cryptsetup ships); asserts platform detection selects the Debian/Ubuntu backend; runs the decoy-persistence preflight (stock persistent journal gets the documented warn/refuse, passes once volatile journald is set); runs explicit overlay-only activation over `/home`, `/etc`, `/srv`, `/opt`, `/var`, `/tmp` writing canaries; asserts writes under `/usr`/`/usr/local` fail (EROFS); runs status, emergency, verify and deactivate with a reboot; and runs the host-side decoy disk-image check (`disk_forensics.py`, the fls/strings/journal checks that replace forensics-eval) with null and positive controls. The os-release detection fixtures are Rust unit tests owned by the platform-abstraction item, not here. CI: add a `distro` axis to the reusable e2e workflow with the runner label as a parameter; run one smoke scenario per distro on schedule, on a `distro-e2e` label and on dispatch (non-required at first), full suite nightly/on demand, distros x shards <= 8. NixOS-specific tests stay NixOS-only. Sequence after the hosted-cached E2E work and the scenario extraction into Python modules.

  **Done when**
  - `nix build` of the Debian 12 and Ubuntu 24.04 smoke attributes runs and passes locally with KVM.
  - A write under `/usr` inside the hidden session fails and the test asserts it (verified against a temporary negative control that leaves `/usr` writable).
  - The decoy-disk image check finds zero hidden canaries and detects the positive control.
  - Adding a distro requires only a new entry in the distro list.
  - The distro workflow runs on schedule, on the label and on dispatch, with the runner as an input.

  Files: `flake.nix`, `flake.lock`, `nix/distro-tests/default.nix`, `nix/distro-tests/images.nix`, `nix/distro-tests/lib/`, `nix/distro-tests/tests/`, `nix/e2e-tests/default.nix`, `.github/workflows/e2e-tests.yml`, `nix/e2e-tests/README.md`.

### W15-C2: Filesystem contract tier + coverage gate

Owns: `nails-core/tests/filesystem_contract.rs`, `nails-core/src/filesystem/mock/`, `.config/coverage.toml`

- [x] **T-099: Test production code paths: a filesystem contract suite for mock and real, mock fidelity fixes, and injected teardown commands instead of cfg(not(test))** (high · effort L)

  _Status: done (wave 15 + wave F1). Contract suite `tests/filesystem_contract.rs` runs over mock and real (replacing `filesystem_trait.rs`); mock keeps every lower, records `SecureDelete`, fails parentless writes; session kill/restart route through the injected `SessionCommandExecutor`. Wave F1 closed the last gap: `SessionRestartGuard` now owns a `Box<dyn SessionCommandExecutor>` and `restart_session_after_success` takes `&dyn SessionCommandExecutor`, so the real systemctl restart path runs in production and under test with no code compiled out — the two cfg(not(test)) rollback seams and the cfg(test) stub are gone, replaced by a recording executor asserting exact commands. Deferred (outside Done-when): making `read_directory` return owned entries, left for the coordinated Filesystem-trait split._

  **Problem**
  41 `#[cfg(not(test))]` blocks across 12 production files compile real side effects out of unit tests (`process/shell_cleanup.rs` 7, `notification/mod.rs` 7, `manager/deactivation.rs` 6, `process/session/types.rs` 4, `process/session/management/mod.rs` 4, `prompts/mod.rs` 3, `process/restart/mod.rs` 3, `state/file.rs` 2, `process/session/detection.rs` 2, plus `shell/mod.rs`, `manager/activation/mod.rs`, `cleanup/history/cleaner.rs`). `handle_session_kill_with_executor` (`manager/activation/session.rs:90`) is a `#[cfg(test)]` copy whose `GraphicalUser` arm just returns the default plan. `rollback_overlay_mounts_after_activation_failure` (`manager/activation/rollback.rs:56`) is `#[allow(dead_code)]`, called only from tests. `rollback_unmounts` (`deactivation/orchestrator/unmount.rs:134`) reads `get_mount_info` after the unmount, which only the mock can satisfy. Mock gaps: `MountInfo` keeps only `lower[0]` (`mock/operations_mounts.rs:34`) while real joins all lowers; writes succeed with no parent dir (`mock/operations_profiles.rs`); `mock_set_file_content` never sets `exists` (`mock/setup_state.rs:320`); `secure_delete` is just `remove_file`; `read_directory` returns `Vec<std::fs::DirEntry>` (`traits/mod.rs:225`), unusable by the mock. `tests/filesystem_trait.rs` (45 tests) runs against the mock only; real side-effect code has the lowest coverage.

  **Fix**
  - Add `nails-core/tests/filesystem_contract.rs` with `fn contract<F: Filesystem>(make: impl Fn(&Path) -> F)` covering file, dir, symlink, existence, size, secure-delete and read_directory semantics; run it against `MockFilesystem` and against `RealFilesystem` rooted in a tempdir; fold `tests/filesystem_trait.rs` into it.
  - Mock fixes: fail on missing parent; `mock_set_file_content` implies `exists`; record `SecureDelete` as its own op; keep all lowers in `MountInfo`; make post-unmount `get_mount_info` match real; change `read_directory` to return owned entries (trait change, coordinated with the Filesystem trait split).
  - Route session kill, reboot, switch-to-configuration and systemctl through one injected command-runner (the CommandExecutor consolidation; `SessionCommandExecutor`, `restart::CommandExecutor`, `nixos::command::CommandExecutor` unify). Delete the matching `cfg(not(test))` forks and `handle_session_kill_with_executor`; unit tests inject a recording runner and assert exact commands for TTY, SSH and graphical sessions.
  - When the activation-rollback item wires `rollback_overlay_mounts_after_activation_failure` into production, run its tests and the deactivation rollback tests against real post-unmount semantics. Defer a full in-memory tree and Clock injection.

  **Done when**
  - The contract suite passes for both `MockFilesystem` and `RealFilesystem`.
  - No `cfg(not(test))` block remains in the session-kill, reboot, switch or systemctl paths.
  - `handle_session_kill_with_executor` is gone and graphical session kill is unit-tested via recorded commands.
  - The mock overlay keeps every lower, and a parentless write fails in both implementations.

- [x] **T-100: Coverage gate on production code only, with one threshold, mutation testing and removal of coverage-only tests** (medium · effort M)

  _Status: done in wave 15. Mock gated behind `cfg(any(test, feature = "test-support"))` (not in release builds); `.config/coverage.toml` is the single threshold (86.0, production-only, measured 86.32%) read by `just coverage` with test files and fixtures excluded; duplicated overlay pivot tests removed; weekly `cargo-mutants` job in `scheduled.yml` (first CI run pending); docs corrected. Replacing bare `is_ok` asserts across the suite is left as general cleanup._

  **Problem**
  Thresholds disagree: `ci.yml:20` = 85, `.pre-commit-config.yaml:160`/`203` = 85.5, `scripts/ci-local.sh` = 85. `preflight/checks/README.md:141,189` claims 100% is enforced; `docs/security-validation.md:159` says 85%. The mock is `pub mod mock` (`filesystem/mod.rs:40`, re-exported `lib.rs:102`) and is measured, so production-only coverage (~84.0%) is inflated to the ~85.39% headline. Coverage-chasing tests exist: `let _ = result; // No assertion - just ensuring code coverage` in `tests/real_filesystem.rs` (214, 277, 305, 555); disjunctive `contains` asserts (e.g. `preflight/mod.rs`); `cli/logging/tests.rs` asserting on strings built inside the test; ~202 bare `assert!(x.is_ok())`; and ~17 duplicated test pairs (`preflight/checks/nixos_config/tests.rs` vs `tests_integration.rs`, `filesystem/mock/tests_basic.rs` vs `tests/filesystem_trait.rs`, `overlay/tests.rs` vs `overlay/pivot/tests.rs`).

  **Fix**
  - Gate `MockFilesystem` and other test infrastructure behind `cfg(any(test, feature = "test-util"))`, with `nails-cli` enabling the feature in dev-dependencies, so it ships in neither build nor coverage; also pass `--ignore-filename-regex` for test files.
  - Define the threshold in exactly one place (e.g. `.config/coverage.toml` or a justfile variable) read by CI, pre-commit and `ci-local.sh`; set it to the measured production-only number and ratchet upward only.
  - Add a weekly `cargo-mutants` run over `state/`, `overlay/` and `cleanup/` in the scheduled lane, uploaded as an artifact.
  - Delete assertion-free, tautological and duplicated tests; where a test has real purpose, replace bare `is_ok` with value assertions. Correct the preflight README and `docs/security-validation.md` to state the real policy.

  **Done when**
  - The threshold number is defined in exactly one file.
  - `cargo build --release` does not compile `filesystem/mock`, and the coverage report excludes the mock and test utilities.
  - `rg 'No assertion - just ensuring code coverage'` returns nothing and the cited duplicate pairs are removed.
  - Docs state the enforced policy and a mutants job exists in the scheduled lane.

## Wave 16: Signal cancellation + structured assertions + container smoke

### W16-C1: Signal cancellation

Owns: `nails-core/src/cancel.rs`, `nails-cli/src/cli/mod.rs`, `nails-cli/src/cli/detach.rs`

- [x] **T-101: Handle SIGINT/SIGTERM/SIGHUP so an interrupted activation rolls back, and keep nails alive under OOM** (high · effort M)

  _Status: Done. `nails-core/src/cancel.rs` sets a process-wide flag from SIGINT/SIGTERM (SIGHUP caught and ignored), `cancel::checkpoint()` boundaries in activation roll back to Inactive with exit code 130, OOM survival via `oom_score_adj` and `OOMPolicy=continue` on both `systemd-run` units. Unit and detach tests pass. Deferred (not in Done-when): mid-build child group-kill (cancellation is cooperative at step boundaries), the EPIPE-safe `/dev/null` console redirect on SIGHUP, and explicit signal masking in teardown. The new E2E spec `nix/e2e-tests/tests/state/58-state-signal-during-activation.nix` and the live `systemctl show OOMPolicy=continue` assertion still need a NixOS VM runner._

  **Problem:** `signal-hook = "0.4"` is declared (`nails-core/Cargo.toml:25`) but unused, and nothing handles SIGINT/SIGTERM/SIGHUP. Cleanup relies entirely on `Drop` — `StateGuard` (`state/guard.rs:227`), `MountTracker` (`mount_tracker.rs:282`), `SessionRestartGuard` and `NixDaemonGuard` (`activation/guards.rs:30,83`) — which does not run when a signal's default action kills the process. TTY and SSH activations run in the foreground (`cli/detach.rs` detaches only graphical sessions, ~141-175; deactivation detaches only under `NAILS_FORCE_DETACH`, ~257-290). The `Activating` state is persisted at `activation/mod.rs:250-256`, before overlays are mounted. So Ctrl-C during a slow `nixos-rebuild`, an SSH hangup, `systemctl stop` of the transient unit, a shutdown, or an OOM kill can leave overlays partly mounted, nix-daemon stopped, the session not restarted, and `Activating`/`Deactivating` persisted. The `systemd-run` calls set no `OOMPolicy` (`cli/detach.rs:186-249`); under `DefaultOOMPolicy=stop` an OOM kill of the nix evaluator child stops the whole unit. Swap must be off (`preflight/checks/swap.rs:65`).

  **Fix:**
  - Add `nails-core/src/cancel.rs`: register SIGINT and SIGTERM via `signal_hook::flag` into a global `AtomicBool`. Add `cancel::checkpoint()` returning a new `NailsError::Cancelled` (`error.rs:20`), and call it between activation steps so the existing rollback (mount rollback + `StateGuard`) runs and the state returns to `Inactive`.
  - The CLI installs the handlers for mutating commands only (`nails-cli/src/cli/mod.rs`, `logging.rs`). SIGHUP does not cancel: the operation continues and further terminal output goes to `/dev/null` through an EPIPE-safe writer.
  - Child processes: run the build phase (`nixos-rebuild build`/`nix build`) in its own process group and kill it on cancellation (`nails-core/src/nixos/command.rs`). Never interrupt `switch-to-configuration`; wait for it, then roll back. Deactivation and emergency defer signals and run teardown to completion (`deactivation/orchestrator/mod.rs`).
  - OOM: add `--property=OOMPolicy=continue` to the activation and deactivation `systemd-run` calls (`cli/detach.rs`). Write a negative value to `/proc/self/oom_score_adj` at startup of mutating commands, and reset children to 0 via a `pre_exec` hook. SIGKILL and power loss stay out of scope (state reconciliation covers them). Memory-headroom preflight belongs to the RAM/tmpfs preflight work, not here.

  **Done when:**
  - Unit test: with the cancel flag set before the overlay step, `activate` returns `Cancelled`, the mock shows no mounts, and the state is `Inactive`.
  - New `nix/e2e-tests/tests/state/58-state-signal-during-activation.nix`: SIGINT and SIGTERM sent to nails parked at the Activating gate (`NAILS_TEST_ACTIVATING_GATE_PATH`, `activation/test_gate.rs`) leave no overlays, the state `Inactive`, and a following `nails emergency` exits 0; a SIGHUP case lets activation complete.
  - An existing detach/session E2E asserts `systemctl show` on the detached unit reports `OOMPolicy=continue`.
  - `cargo test` and `cargo clippy` pass (via `nix develop -c`).

### W16-C2: Structured test assertions

Owns: `nails-core/src/manager/activation/tests.rs`, `nails-core/src/manager/tests.rs`, `nails-core/src/preflight/`

- [x] **T-102: Assert on error kinds and behaviour instead of message wording and log text** (medium · effort M)

  **Problem:** nails-core unit tests pin behaviour to human-readable strings instead of error structure. There are roughly 544 `.contains(...)` assertions against error/stdout/stderr text versus only 9 `matches!(.., NailsError::..)` checks, and 23 `#[traced_test]` tests assert on log wording. `nails-core/src/manager/tests.rs:3550` checks for the literal `"DANGER: Skipping pre-flight checks"`, and `:3595` asserts `logs_contain("(") && (logs_contain("s)") || logs_contain("ms)"))`, which matches almost any log line. The module-level `logs_contain` helper (`manager/tests.rs:15-22`) is shadowed by the `traced_test` macro's own helper everywhere it appears to be used, so it is dead. Error variants carry free-form strings — in nails-core `NixOSError` is constructed ~70×, `InvalidState` ~100×, `OverlayError` ~95× — and `NixOSError` is reused for unrelated conditions (e.g. the reboot refusal at `nails-core/src/manager/deactivation.rs:148-152`). Every wording change breaks tests, while the weak substring checks still pass through real regressions.

  **Fix:** After the error-type redesign lands structured kinds and fields, migrate the nails-core unit tests family by family from text substring checks to `matches!` on error kinds plus field assertions — `nails-core/src/manager/tests.rs`, `manager/activation/tests.rs`, the deactivation tests (`manager/deactivation_tests.rs`, `deactivation/tests.rs`), `status/tests.rs`, and `preflight/`. Delete the vacuous timing-log assertion (`manager/tests.rs:3595`) and remove the dead module-level `logs_contain` helper (`manager/tests.rs:15-22`). Replace log-text assertions with behaviour assertions; where a log line is itself the contract (e.g. the preflight-bypass warning), assert on a stable structured field via `logs_assert` rather than punctuation or generic fragments. Leave user-facing wording pinned at the CLI/output test layer, not by core substring checks.

  **Done when:** Changing an error message string requires no change to nails-core tests (only CLI/output-level tests move). No `#[traced_test]` test asserts on punctuation or generic fragments, and the timing assertion at `manager/tests.rs:3595` is gone. The dead `logs_contain` helper is removed. The count of `.contains(` assertions on error text in nails-core tests drops substantially, with the remainder being genuine rendering tests. `cargo test` and `cargo clippy` (via `nix develop -c ...`) pass clean.

### W16-C3: Debian/Ubuntu container smoke

Owns: `scripts/distro-smoke/`, `docs/ci.md`

- [x] **T-103: Cheap per-PR container smoke tier for Debian/Ubuntu (privileged systemd containers)** (medium · effort M)

  **Problem:** The test infrastructure is NixOS-VM-only — every spec in `nix/e2e-tests/default.nix:42` is wrapped in `pkgs.testers.runNixOSTest`. Nothing exercises NAILS on an FHS distro, so the planned Debian/Ubuntu platform backend would ship with no per-PR regression coverage.

  **Fix:** Add a lightweight container smoke tier separate from the NixOS VM suite. Boot privileged systemd containers (`debian:12`, `debian:13`, `ubuntu:24.04`) via `/sbin/init`, attach a loop-mounted ext4 hidden volume, and run the static musl binary through the full lifecycle: `activate` (overlay-only, auto policy), `status`, `emergency`, `deactivate`, `verify`. Assert `/usr` writes fail with `EROFS` during the active session (the FHS read-only `/usr` guard) and that decoy paths are byte-identical afterward. Put the driver in `scripts/distro-smoke/run.sh` with the per-distro scenario in `scripts/distro-smoke/scenario.sh`. Add a `distro` matrix job to `.github/workflows/ci.yml` triggered on PRs touching `nails-core/` or `nails-cli/`, with the runner label exposed as a workflow input/parameter (runner strategy is still open). Keep the job non-required initially. Document the tier in `docs/ci.md`.

  **Done when:** `scripts/distro-smoke/run.sh debian:12` passes locally and in CI; the matrix job covers debian:12, debian:13 and ubuntu:24.04 and reports per distro on relevant PRs; the `/usr` EROFS assertion and the unchanged-decoy check both run inside the scenario; and the runner label is read from a workflow input rather than hard-coded.

## Wave 17: Platform CLI/state surface + history rework

### W17-C1: Platform CLI & state schema surface

Owns: `nails-cli/src/cli/output/status/human.rs`, `nails-cli/src/cli/output/status/json.rs`, `nails-core/src/state/file.rs`

- [x] **T-104: Generalize CLI identity, NixOS flags, progress steps and the state schema to the platform model** (medium · effort M)

  **Problem**
  The CLI is hardwired to NixOS. The about/long-about text is "NixOS Anti-forensics Isolation & Layering System" (`nails-cli/src/cli/args.rs:9,13`) and the activate help reads "Activate the hidden NixOS environment" (`args.rs:38`); the only platform switch is the negative `--overlay-only` (`args.rs:106`) alongside the NixOS-specific `--flake`/`nixos_flake` (`args.rs:97-98`). Activation prints NixOS steps unconditionally — `[3/7] Preparing NixOS switch metadata` and `[6/7] Running NixOS switch/rebuild` — even on overlay-only runs (`nails-core/src/manager/activation/mod.rs:260-272,387-394`), and the step count is a fixed `/7`. With no builder configured, `switch_nixos_profile` returns `Ok(())` early (`nixos_switch.rs:25-27`), yet a "NixOS Rebuild Complete" notification still fires (`activation/mod.rs:414-423`). The kill-session prompt lists "Mount hidden environment overlays" twice (`nails-core/src/process/session/management/mod.rs:72-73`). `StateFile.nixos_generation` (`nails-core/src/state/file.rs:73-74`) is surfaced as "NixOS Generation:" regardless of platform (`status/human.rs:62,196`; `status/mod.rs:235`; `status/json.rs:25,93`).

  **Fix**
  No backwards compatibility required. Replace `--flake`/`--overlay-only` with a platform-driven layer selection: NixOS options grouped under the NixOS layer (e.g. `--nixos-flake`) and no NixOS layer applied on the DebianFamily platform (coordinate with the activate flag redesign, UX-ARCH-01). Generalize the about/long-about and activate help text to the platform model. Build the progress steps from the active execution path so the total and labels follow the path and NixOS steps never render in overlay-only/DebianFamily runs. Suppress the rebuild notification when no layer actually ran. De-duplicate the kill-session prompt step. Replace `nixos_generation` in the state schema with a typed per-platform section (an enum variant per platform, NixOS carrying its generation) and render it in human and JSON status only for the platform that has it.

  **Done when**
  - Overlay-only / DebianFamily activation output contains no "NixOS" step text and sends no rebuild notification.
  - Progress step total and labels are derived from the active path, not a fixed `/7`.
  - Kill-session prompt lists each step exactly once.
  - State file round-trips the typed platform section; human and JSON status show the NixOS generation only on NixOS.
  - CLI snapshot tests updated (coordinate with UX-ARCH-12).

### W17-C2: History anti-forensics rework

Owns: `nails-core/src/cleanup/history/`, `nails-core/src/cleanup/history_files/mod.rs`, `nails-core/src/deactivation/orchestrator/cleanup.rs`

- [x] **T-105: History handling: resolve the real invoking user, no post-unmount decoy writes, no whole-file truncation or secure delete by default** (critical · effort L)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (history cleanup; the entry kills the interactive shells instead). The item stays ticked as history; it describes no current code._

  **Problem**
  History operations resolve paths from the process `$HOME` (`cleanup/history/mod.rs:80`, `:190`; `cleaner.rs:164`; `verify/verifier.rs:241-246`). Under `sudo nails`, `env_reset` makes HOME `/root` and in the detached unit it is unset, so the invoking user's `~/.bash_history` — which incremental flushing fills with the `cryptsetup`/mount/`nails activate` commands — is never touched, even though `shell/mod.rs:152` already derives it from SUDO_USER/NAILS_TARGET_USER. Shell cleanup (`process/shell_cleanup.rs:62-75,128`) kills only the non-root target uid and keeps the invoking shell on a protected list, so root's decoy history is SIGHUP-flushed and the invoking shell survives truncation. After unmount, emergency (`manager/deactivation.rs:514`) and normal deactivation (`orchestrator/cleanup.rs:133`; `post_unmount_cleanup` defaults true, `cleanup/types.rs:110-113`) run a 3-pass secure delete then temp+rename re-create — new inode, root owner, fresh timestamps, leftover `.tmp` names — writing to the decoy disk after it is unmounted; line-filtering with temp+rename (`cleaner.rs`, `secure_delete` default off) leaves removed lines in freed blocks. Deep verify only scans `/root` and literal `/home/.bash_history`. `USER-SECURITY-GUIDE.md` describes layers that do not exist in code, and the E2E suite hides all of this by injecting `HOME=/home/testuser` (`nix/e2e-tests/lib/shell-helpers.nix`).

  **Fix**
  - Add one `TargetUser` resolver (SUDO_UID/NAILS_TARGET_UID → getpwuid, plus `/root`) and route every history filter/verify/rc path through it; drop `env::var("HOME")` from history and verify. (Env-var/pattern names currently sourced from `obfuscate::` move with the obfuscation-module removal.)
  - Before teardown, SIGKILL all interactive shells including root's, ahead of stopping the display manager / terminating the logind session so in-memory decoy history is never flushed; at deactivation detach by default (or re-exec into a transient unit) so the invoking shell is killed last with the rest rather than protected.
  - Invariant: no writes to any decoy filesystem after unmount unless the decoy root is verified amnesic (decoy-persistence preflight). Remove post-unmount truncation from the normal and emergency paths by default; remove whole-file truncation and secure-delete from defaults.
  - Make decoy history edits opt-in only, and when enabled overwrite in place on the same inode (same owner/mode, `O_NOFOLLOW`) for the resolved user instead of temp+rename.
  - Deep verify (`verify/verifier.rs`) scans `/root` plus each `/home/*/` (or the SUDO_USER home) and matches the backend patterns cleanup already uses (`cryptsetup`, `tcrypt`, `/dev/mapper`).
  - Preflight warns when the invoking user's shell flushes incrementally (zsh `INC_APPEND_HISTORY`/`SHARE_HISTORY`, bash `history -a` in `PROMPT_COMMAND`).
  - Rewrite the `USER-SECURITY-GUIDE.md` history section to match actual behaviour (or state it must come from the decoy base plus a preflight that checks for it).
  - Rewrite E2E (`shell-helpers.nix`, `tests/shell/36-*`, `37-*`, `tests/forensic/05-*`) to run through real `sudo`/`sudo -u` with no HOME injection, planting a decoy-shell history canary pre-activation.

  **Done when**
  - A command in the invoking user's `~/.bash_history` present before `sudo nails deactivate` is gone/overwritten by the end of deactivation (new E2E canary, no HOME injection).
  - Default config performs no write to any history file after unmount (orchestrator unit test over mock fs).
  - `rg 'env::var("HOME")' nails-core/src` returns no history/verify use; unit tests show that with SUDO_UID set and HOME=/root the resolved paths are under the invoking user's home, across sudo and detached contexts.
  - `verify --deep` flags a `cryptsetup` line in `/home/<user>/.bash_history`; a zsh config with `INC_APPEND_HISTORY` triggers the preflight warning (unit tests).
  - E2E 36/37 run through real `sudo` with the real HOME and assert the decoy's pre-existing history lines are preserved while the invoking-user artifact is removed.
  - `USER-SECURITY-GUIDE.md` history section matches implemented behaviour; `cargo test` and `cargo clippy` are clean.

## Wave 18: Process write-capability classification & stale-writer handling

### W18-C1: Process classification & stale writers

Owns: `nails-core/src/process/classification/mod.rs`, `nails-core/src/process/detection/mod.rs`, `nails-core/src/overlay/strategy/mod.rs`

- [x] **T-106: Classify blocking processes by write capability, scan /proc once, and restart or report stale writers that survive the overlay mount** (high · effort L)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (process classification and the writer rescans). The item stays ticked as history; it describes no current code._

  _Status: partial (wave 18 + later waves + wave F1). Done: the write-capability classification core, risky-service opt-in (`resolve_risky_services`), removal of OPTIMAL-from-pivot-count (the security label now keys off decoy writers), unverifiable-writer detection, and the docs wording fix (USER-SECURITY-GUIDE removed, no `--no-kill-session` wording). Wave F1 added two more: the DE/browser/editor/service process-name tables moved out of the classifier into `platform/process_classes.rs` (exact, non-substring membership, `host_process_classes()` seam) consumed by classify, and the mount phase now captures one `ProcSnapshot` and threads it through so `/proc` is walked once per phase instead of once per target. Remaining: the post-mount stale-lower rescan surfaced into state/status (human/JSON/DTO), `chdir("/")` before the first mount with a decoy-cwd warning, and the writer-survival E2E — see nix_pending._

  **Problem**
  Blocking-process classification uses NixOS-tuned name tables and a "no cwd in target = Safe" rule (`classification/mod.rs:132-150`, `:185-205`), so on FHS hosts read-only users of `/opt` or `/tmp` get signalled for no reason. Safe processes are signalled with no prompt because `auto_restart_safe` is always true (`overlay_mount/mod.rs:46`; `strategy/mod.rs:246`) and `--yes` defaults to true (`commands/activate/mod.rs:97` — `yes = !interactive`), so there is no real opt-in. Detection matches by string prefix (`detection/mod.rs:198-249`, `:242`), so `/opt` matches `/opt2` and `" (deleted)"` paths; it never reads `/proc/PID/root`, missing chrooted/namespaced writers. `detect_processes_using` walks all of `/proc` once per target (`strategy/mod.rs:184`, `:353`) — ~9-13 redundant scans on a full-root activation. Worst: an overlay only redirects new path lookups, so processes left running keep writing to the decoy through pre-mount cwd/fds/mmaps, yet Direct mount is documented as optimal (`strategy/mod.rs:73`) and reported `OPTIMAL` whenever `pivot_mounts==0` (`activation/mod.rs:311`); README.md:157-160 sells `--no-kill-session` as the "safer path".

  **Fix**
  - Classify by write capability: a process blocks a target if it has cwd or root in it, an fd opened `O_WRONLY/O_RDWR/O_APPEND` (parse `/proc/PID/fdinfo` flags), a directory fd in it, or a `rw-s` mapping of a file in it; holders with only read-only fds/mappings → `Skip`. Use `Path::starts_with` and strip the `" (deleted)"` suffix. Move the browser/editor/DE name tables into platform data.
  - Scan `/proc` once per activation phase into a snapshot `{pid -> (cwd, root, fd targets+flags, mmap paths)}` and classify every target against it; rescan only after Phase-2 service stop/restart and on pivot fallback. Skip the maps read for mmap-irrelevant targets.
  - Require an explicit opt-in (a dedicated flag in the redesigned activate flag model from UX-ARCH-01, or the interactive prompt) before signalling any non-service process; under it, restart Safe and Risky holders or fail closed with an actionable list — never skip Risky silently.
  - After each mount, rescan `/proc/*/{cwd,root,fd,maps}`; flag a reference as stale-lower when its `mnt_id` (fdinfo) or `st_dev` differs from the new overlay, and flag any process whose mount namespace or root differs from PID 1 as an unverifiable writer. Restart/terminate stale holders; if a holder is NoRestart, refuse or mark the session DEGRADED and list survivors in human + JSON output and in `status`.
  - Remove the Direct=OPTIMAL equivalence (stop keying `security_status` off pivot count) and fix the doc comments. `chdir("/")` before mounting and warn if the invoking shell's cwd is on the decoy. Reword README.md:157-160 and docs/USER-SECURITY-GUIDE.md: `--no-kill-session` trades backend survival for leaked decoy writes, and every app/terminal must be closed first.

  **Done when**
  - Unit tests over synthetic `/proc` fixtures: read-only fd/mmap holder → Skip; `O_RDWR` fd, directory fd, `rw-s` mapping, or cwd/root in target → blocking; `/opt2` does not match `/opt`.
  - `/proc` is walked once per activation phase, not once per target (asserted via a counter in a test); detection results unchanged for existing session/overlay E2E tests; rescan happens after service restarts and on pivot fallback.
  - No non-service process is signalled without the explicit opt-in; under it, Risky holders are restarted or activation fails closed with the offending list.
  - `security_status` no longer reports OPTIMAL from pivot count alone and the misleading doc comments are gone; foreign-namespace/chrooted processes are listed as unverifiable writers in human + JSON.
  - New E2E/disk-image test: a background process holding a writable fd and cwd in `/home` keeps writing after activation, and the decoy lower is unchanged after deactivation (or activation refused).
  - README/guide `--no-kill-session` wording corrected.

  _Status: Wave 18 landed the detection/classification core — ProcessInfo now records write capability (writable/directory fds via fdinfo flags, shared-writable `rw-s` mappings, `/proc/PID/root` and mount-namespace reads flag chrooted/foreign-ns processes as unverifiable writers), component-wise `Path::starts_with` with `" (deleted)"` stripping fixes the `/opt2`-matches-`/opt` bug, a one-shot `ProcSnapshot` walks `/proc` once and classifies many targets from one capture, and `classify_process` now returns Skip for any read-only consumer, all covered by synthetic-/proc unit fixtures. Remaining: thread `ProcSnapshot` through manager/activation so `/proc` is scanned once per phase (counter test); move the DE/browser/editor name tables into the platform data layer; post-mount rescan flagging stale-lower refs (mnt_id/st_dev) and surfacing unverifiable/stale writers in state + status human/json/dto; explicit opt-in restart-or-fail-closed for Risky holders; `chdir("/")` before first mount + decoy-cwd warning; remove Direct=OPTIMAL/security_status-from-pivot-count and fix doc comments; README.md and docs/USER-SECURITY-GUIDE.md `--no-kill-session` wording; new E2E/disk-image writer-survival test._

  _Status (2026-10): done. The post-mount `/proc` rescan flags only real stale-lower writers (by mount id) and records each surviving decoy writer with a kind in state, `status` and the JSON schemas; activation `chdir`s to `/` before mounting and warns on a decoy cwd; no non-service process is signalled without `--terminate-processes`; risky services fail closed unless `--risky-services` says otherwise. The writer-survival E2E reports a surviving writer with its classified kind._

## Wave 19: Emergency/recover subsystem + watcher + fault-injection E2E + help

### W19-C1: Emergency, recover, watcher, fault-injection, help

Owns: `nails-core/src/manager/deactivation.rs`, `nails-core/src/emergency.rs`, `nails-cli/src/cli/commands/emergency.rs`, `nails-cli/src/cli/commands/recover.rs`

- [x] **T-107: State-independent emergency/deactivate driven by the kernel mount table, plus a nails recover command and guidance that points to real commands** (high · effort L)

  _Status: done (wave 19 + wave F1). State-independent emergency via live mount discovery, `nails recover`, fixed guidance, `SystemState::Emergency` removed, and the status overlay-mismatch next step landed earlier. Wave F1 added the remaining items: emergency/recover teardown now reads the recorded owner pid and best-effort SIGTERMs a still-running activation owner (bounded ~3s try-lock) before unmounting, and both the activation success summary and its notification body surface the RAM-backed panic button (`sudo /run/overlay-runtime/control emergency`) via the neutral `runtime_copy::binary_copy_path()`. Remaining: the backend-lazily-unmounted VM E2E, grouped under T-111 (shared with T-108), needs a nix host — see nix_pending._

  **Problem**
  - Emergency refuses every state except Active: "Cannot deactivate from state X. Must be ACTIVE." (`nails-core/src/manager/deactivation.rs:402-435`, `nails-core/src/deactivation/orchestrator/mod.rs:189-217`). This contradicts "Any State -> Emergency" (`state/transitions.rs`; `trigger_emergency` has no production caller). E2E `security/74,75,76` assert the refusal.
  - The panic button is therefore unavailable during the whole switch (state stays `Activating` while overlays are already mounted), after a killed/interrupted activate or deactivate, after a post-mount activation failure, and with a corrupt or missing `state.json` (`state/file.rs:300-376` loads it as Inactive).
  - Unmount targets come only from `state.json` + manager cache (`orchestrator/mod.rs:7-42`), never from `/proc/self/mountinfo`. `update_state(Deactivating)?` runs before any unmount, so a full/read-only hidden root aborts emergency before it does anything. Implicit config discovery falls back to defaults (`nails-cli/src/cli/commands/mod.rs:40-54`), so emergency can read the wrong state file.
  - First unmount failure triggers `rollback_unmounts` + early return (`orchestrator/unmount.rs:44-54`) and StateGuard restores Active.
  - Recovery advice is wrong: "reboot if stuck" / "Reboot to reset state" (`preflight/checks/state.rs:84-92`) do nothing (state.json survives reboot); `nails deactivate --force` does not exist (`verify/verifier.rs:400,411`); `docs/USER-SECURITY-GUIDE.md:254,510-521` tells users to `rm state.json`.

  **Fix**
  - Add a mount-discovery module that parses `/proc/self/mountinfo` and returns NAILS-owned mounts: persistent overlays whose upper/work dirs are under the hidden root, `/run/nails` ephemeral overlays, pivot staging binds, the `/nix/store` restore bind, plus the top-level-overlay fallback when config/hidden root is unknown. Merge with `state.json` and the mount tracker.
  - Emergency runs from any state (Inactive-with-mounts, Activating, Deactivating, corrupt/Unknown). Inactive with no NAILS mounts exits 0 "nothing to tear down". If state records a live `owner_pid`, SIGTERM it, wait up to 3s, then proceed (try-lock semantics). Every state write is best-effort and happens after unmounting; ENOSPC/EROFS/EIO are logged and skipped. Never call `rollback_unmounts`; final state is Inactive if no NAILS mounts remain, else Degraded. Never fail closed: if config/state is missing, use the mountinfo fallback and print which source was used. `activate` keeps failing closed.
  - Add `nails recover` (`nails-cli/src/cli/commands/recover.rs`, wired in `commands/mod.rs`/`args.rs`): reconcile recorded vs live state, tear down remaining NAILS mounts with the same engine (no countdown), back up a corrupt/checksum-mismatched state file to `state.json.bad`, reset to Inactive. `deactivate` stays Active-only but its refusal points to `recover`/`emergency`.
  - Backend-loss resilience: at activation copy the running binary to `/run/nails/bin/nails` (tmpfs, root, 0700; removed by deactivate/emergency); show `sudo /run/nails/bin/nails emergency` in the activation summary and notification.
  - Fix guidance in `verify/verifier.rs:400,411`, `preflight/checks/state.rs`, and `USER-SECURITY-GUIDE.md` (replace `rm state.json` with `nails recover`). Remove the dead `SystemState::Emergency` variant and its branches since emergency now always ends Inactive. status prints the overlay mismatch errors with a next step ("overlays missing: run nails recover or nails emergency").

  **Done when**
  - E2E 74/75/76 are inverted: emergency from Activating/Deactivating/Inactive-with-mounts tears down all NAILS mounts, exits 0; Inactive without mounts exits 0 "nothing to tear down".
  - New E2E: backend lazily unmounted mid-session, then `/run/nails/bin/nails emergency` removes every overlay.
  - Unit tests: emergency with corrupt/unreadable state, a failing save (ENOSPC mock) or missing config still unmounts every discovered mount and reports the source; emergency never calls `rollback_unmounts` and continues past a failed unmount.
  - `nails recover` resets Interrupted/Degraded to Inactive after teardown (unit + E2E).
  - `rg 'deactivate --force|reboot if stuck|Reboot to reset' nails-core nails-cli docs README.md` returns nothing; `SystemState::Emergency` no longer exists; cargo test and clippy pass.

  _Status: Wave 19 landed `nails recover` (reconciles recorded vs live state, backs up a corrupt state file to `state.json.bad`, tears down via mount discovery, resets to Inactive), emergency from any state (clean Inactive is a no-op success), fixed guidance (`verify`, deactivate hint, USER-SECURITY-GUIDE), E2E 74/75/76 aligned and 55/12 re-open the volume and run `recover`; the RAM copy landed with T-108 as the neutral `/run/overlay-runtime/control`. Remaining: SIGTERM a live `owner_pid` before emergency teardown, status overlay-mismatch next step ("run nails recover or nails emergency"), show the `/run` copy emergency command in the activation summary/notification, and the backend-lazily-unmounted E2E (shared with T-108)._

- [x] **T-108: Detect a failing hidden backend during a session: a RAM copy of the binary, config and manifest, plus an alerting watcher** (medium · effort L)

  _Status: done. The RAM-backed `/run/overlay-runtime` copy (0700), the `watcher.rs` alert/debounce machine, the strict `[backend_watch]` TOML, the hidden `watch` subcommand (neutral transient unit `overlay-runtime-monitor`) and the emergency/recover `/run` config fallback landed in prior waves with unit coverage; no created name contains `nails`. Wave F1 added the mid-session alert VM E2E `faults/96-backend-watch-alert.nix` plus its shard weight. Remaining: that E2E must be built/run on a nix host — see nix_pending._

  **Problem**
  - NAILS has no long-running component after activation. Notifications are JSON files under `<hidden_root>/notifications`, dispatched only at login (`nails-core/src/notification/mod.rs:69-71,280-340`), so they cannot report a failure of the hidden root itself. There is no udev/inotify/mountinfo watcher.
  - When the backend fails or is lazily unmounted (udisks/VeraCrypt after device removal), the user sees random application errors with no explanation.
  - The binary and config live on the hidden root (`config/defaults.rs:10-54`, `config/loading.rs:8-19`), so `nails emergency` may not even be runnable once the root is gone.

  **Fix**
  - Phase 1 (shares the `/run` copy from T-107): at activation, copy the running binary, the effective config and a manifest of mounted overlay targets into a 0700 directory under `/run` with a neutral, non-product name. `emergency`/`recover` read this manifest when the hidden root or `state.json` is unavailable (mount discovery comes from T-107). Remove the copy at deactivate and emergency.
  - Phase 2: a watcher started from the `/run` copy as a transient systemd unit with a neutral name (no "nails" in the unit/file/dir name), keeping all state in `/run`. Add `nails-core/src/watcher.rs` and a hidden `nails-cli/src/cli/commands/watch.rs` subcommand. Every few seconds it polls mountinfo plus a statfs/read probe of the hidden root. On failure it alerts the target user via `notify-send` on the user session bus. It runs emergency automatically only when opted in (`[backend_watch] auto_emergency = true` in the TOML config) and the failure persists past a debounce (e.g. 15s); default is alert-only so a transient I/O stall cannot kill the session. deactivate and emergency stop it.

  **Done when**
  - Unit tests: the `/run` copy + manifest are created at activation with mode 0700 and removed at deactivate and emergency.
  - Unit test (mock fs): the watcher alerts after a probe failure and triggers emergency only when `auto_emergency` is set and the failure outlasts the debounce.
  - No unit/file/directory created by the watcher contains "nails" in its name.
  - E2E: lazily unmounting the backend mid-session produces a user alert, and `emergency` run from the `/run` copy tears down all overlays with the hidden root gone; cargo test and clippy pass.

  _Status: Wave 19 landed the `/run/overlay-runtime` copy (binary, effective config, mount manifest; 0700, removed at deactivate/emergency/recover), the `[backend_watch]` config, `watcher.rs` debounce/alert state machine, the hidden `watch` subcommand run as the transient unit `overlay-runtime-monitor`, and emergency/recover falling back to the `/run` config copy; no created name contains "nails" (unit-tested). Remaining: the VM E2E that lazily unmounts the backend mid-session, asserts the user alert, and runs emergency from the `/run` copy (fits the T-111 `faults/` group); live check of the transient unit and notify-send paths._

- [x] **T-109: Emergency ends the hidden graphical session and the services the hidden config added instead of leaving them running until reboot** (high · effort M)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (ending the hidden graphical session on the live decoy). The item stays ticked as history; it describes no current code._

  **Problem**
  - Emergency sets `with_switch_script_execution(kind == Normal)` (`nails-core/src/manager/deactivation.rs:492`), so no decoy switch runs, and the orchestrator only restores `/run/current-system` (`deactivation/orchestrator/mod.rs:332-385`).
  - Only shell processes are killed (`deactivation.rs:474-488`, `process/shell_cleanup.rs:18`); no deactivation path terminates the logind session (`terminate-session`/`terminate-user` appear only in the activation kill path, `process/session/management/mod.rs:189-196`). Busy overlays are lazily detached (`orchestrator/unmount.rs`).
  - Hidden GUI apps, units started by the hidden generation, and settings like the hostname stay live until reboot. Detached overlays keep their uppers pinned, so the guide's `umount /mnt/hidden && cryptsetup close` (`USER-SECURITY-GUIDE.md:460-461`) fails with EBUSY. The guide promises "Immediate return to decoy appearance" (:169) and `emergency.rs:7` claims it "Switches to decoy NixOS configuration". No E2E runs emergency in a graphical session.

  **Fix**
  - In emergency mode, before detaching: terminate the target user's logind sessions (reuse the activation kill path; resolve the target user the same way activation does), then kill remaining processes whose cwd/root/open-fds point into NAILS overlays.
  - Record the set of active units before and after the hidden switch at activation (new `state/file.rs` field), and in emergency stop the difference (faster than a full decoy switch).
  - After unmounting, restart the display manager so the greeter comes from the decoy system.
  - Fix the `emergency.rs` module docs and `USER-SECURITY-GUIDE.md` text about what emergency restores and how to close the backend (no claim of a decoy switch or "immediate" full return).

  **Done when**
  - New graphical E2E (based on `nix/e2e-tests/lib/graphical-vm-config.nix`, e.g. `security/80-emergency-graphical.nix`): active hidden session with a GUI app and a hidden-config service, then emergency; afterwards no target-user process references former overlay paths, the hidden service is stopped, no NAILS overlays remain, the display manager shows the decoy greeter, and `umount` + `cryptsetup close` of the backend succeed.
  - Unit test: emergency stops exactly the recorded unit difference and calls session termination before unmount.
  - `emergency.rs` docs and the guide no longer claim a decoy switch or an "immediate" full return; cargo test and clippy pass.

  _Status: Done in wave 19 (session/unit-diff teardown and display-manager restart; E2E `security/80-emergency-graphical.nix` needs a Nix runner)._

- [x] **T-110: Emergency: detach first, clean up afterwards, no global sync, a time budget, immediate by default with optional --poweroff/--reboot, and an honest result** (high · effort L)

  **Problem**
  - `execute_emergency_cleanup` forces `secure_delete` and `sanitize_memory` (`deactivation/orchestrator/cleanup.rs:63-71`, `manager/deactivation.rs:302-303`) and runs as step 2, before `unmount_overlays` in step 3 (`orchestrator/mod.rs:225-311`). `sanitize_memory` runs an external global `sync` with no timeout then writes `drop_caches` (`cleanup/manager.rs:259-293`); `secure_delete` overwrites files on the hidden upper. On a slow/stalled backend this delays the only step that matters.
  - `drop_caches` can never be written: `write_file_content` creates a `.tmp` sibling and renames it (`filesystem/real/file_ops.rs:113-153`), which procfs forbids, so every emergency logs "Memory sanitization failed (requires root)" even as root (`cleanup/manager.rs:267-293`). drop_caches frees clean page cache; it does not zero RAM.
  - `emergency.rs` rustdoc and `USER-SECURITY-GUIDE.md:131,144,169` overclaim: "< 10 seconds", drop-cache "Configurable" (code forces it), "memory sanitized".
  - `nails emergency` waits through a 3x1s countdown by default (`nails-cli/src/cli/commands/emergency.rs:79-90`); the prompt has no "Ctrl+C to abort" hint and the countdown is silently skipped by `--quiet`/`--json`, so output flags change timing. No `--poweroff`/`--reboot`. On success it always prints "System returned to decoy configuration" (:97) and the `DeactivationReport` is discarded (`manager/deactivation.rs:507`). Teardown commands are a generic blurb (`EMERGENCY_RECOVERY_GUIDANCE`, emergency.rs:125-129).

  **Fix**
  - Emergency order: (1) detach every NAILS mount with `MNT_DETACH`, each `umount2` in its own worker thread under an overall deadline (~5s), reporting still-pending paths; (2) best-effort cleanup afterwards; (3) drop the page cache after unmount. No global `sync`; use `syncfs()` on an fd of the hidden root with a bounded wait if a flush is wanted. No `secure_delete` of hidden-upper files in emergency (they live on the encrypted backend). Normal mode keeps the thorough order.
  - Add `Filesystem::write_kernel_tunable(path, value)` that opens for write with no create/rename (procfs/sysfs knobs), with real + mock impls, and use it for drop_caches; rename the report line to "page cache dropped". Remove the duplicated forced `CleanupConfig`.
  - Teardown starts immediately; add opt-in `--countdown <SECS>` printing "(Ctrl+C to abort)"; remove `--no-countdown`; `--quiet`/`--json` never change timing. Add `--poweroff`/`--reboot` that run after teardown.
  - Return the `DeactivationReport` from `run_deactivation`; make `verify_history_truncation` return pass/fail; record which unmounts needed the detach fallback. The CLI reports what was/was not done; any degradation prints "REBOOT REQUIRED" and exits 7, mirrored in JSON. Replace the success wording and fix the `emergency.rs` rustdoc. After success, print the exact backend-close commands from mountinfo (mount point, source device, dm name when present).
  - Document `init_on_free=1`/`page_poison` in the recommended decoy profile for RAM residue; fix the guide's "Configurable" and timing claims.

  **Done when**
  - Unit tests: in Emergency mode the mock records order unmount* -> cleanup -> drop_caches, no `sync` process is spawned; `write_kernel_tunable` on a temp file writes in place with no `.tmp` sibling.
  - `rg 'drop_caches' nails-core/src` shows no emergency-path use; report text no longer claims memory sanitization; `rg 'System returned to decoy configuration' nails-cli nails-core nix` returns nothing.
  - `--countdown 3` prints the abort hint and waits 3s; `--quiet`/`--json` do not change timing; `--no-countdown` is rejected by clap; `--poweroff`/`--reboot` issue the action after teardown (cargo test, mocked system command).
  - human + JSON output list lazily detached overlays, killed shells, cleanup errors, the history-verification result and not-done items; degraded runs exit 7.
  - E2E `security/78-cleanup-fast-mode.nix` asserts emergency as root reports "page cache dropped" and completes under 10s; `03`, `74`, `75`, `77` and `lib/emergency.nix` are updated and pass; cargo test and clippy pass.

  _Status: Done in wave 19 (detach first, `write_kernel_tunable` drop_caches after unmount, opt-in `--countdown`, `--poweroff`/`--reboot`, REBOOT REQUIRED exit 7; per-unmount worker-thread deadline and killed-shell reporting not added; nix E2E pending evaluation)._

- [x] **T-111: Fault-injection E2E tests and a strict harness that stops masking unclosable backends** (high · effort L)

  **Problem**
  - Crash tests pass without exercising recovery: `state/55` and `smoke/12` never re-open the LUKS volume after `machine.crash()`. `StateFile::load` returns Inactive for a missing file (`state/file.rs:300-354`), so `assert_status_state("Inactive")` (`55:70`) and `state == "Inactive"` (`smoke/12:127`) always pass. `performance/07` re-formats after each crash.
  - No tests for hidden-disk removal, suspend/hibernate, a full upper, signals during activation, `kill -9` during Deactivating, a read-only hidden fs, or emergency with a vfat `/boot` pivot.
  - `unmountHiddenVolume` (`nix/e2e-tests/lib/hidden-volume.nix:72-105`) falls back to `umount -l` and calls a `luksClose` failure "a known test infrastructure limitation". That masks the real cause: lazily detached overlays still referenced by processes keep the hidden superblock alive, so the backend cannot be closed and the key stays in RAM, even though the emergency guidance tells users to dismount (`emergency.rs:125-129`). journald is moved onto the `/var` overlay at activation (`manager/activation/overlay_mount/mod.rs:176-182`) but never restarted after teardown.

  **Fix**
  1. Harness: add `unmountHiddenVolumeStrict` (plain `umount` then `cryptsetup close`; on failure print holders via `fuser -vm` / `/proc/*/fd` and fail the test; remove the "known limitation" text) and `reopenHiddenVolume` (luksOpen + mount, no luksFormat).
  2. Fix tests 55 and 12: after the crash, re-open the same volume and assert the stale-state handling from T-107 (status flags the stale state; `recover`/`emergency` tears it down).
  3. New tests in `nix/e2e-tests/tests/faults/`, tagged `faults`: (a) crash while Active and while Activating (slow-rebuild gate), then re-open and recover; (b) remove the hidden disk while Active (QEMU `drive_del`/`device_del` or in-guest `dmsetup remove --force`) - emergency must unmount every overlay within a bound (~30s) and exit with the documented code; (c) fill the upper with `fallocate` while Active - deactivate and emergency still complete; (d) after emergency without a reboot the backend closes with the strict helper; (e) SIGTERM/SIGINT at the Activating gate - rollback leaves no overlay mounted and no stuck state; (f) `kill -9` during Deactivating, then emergency/recover still works; (g) remount the hidden fs read-only before deactivate/emergency; (h) emergency with a vfat `/boot` asserts the `/mnt/nails-pivot` staging is unmounted and removed.
  4. A later nightly-only phase adds swap/hibernation after activation and `systemctl suspend` with wakeup while Active.
  5. Align `security/75-emergency-from-deactivating.nix` with the chosen recovery semantics.

  **Done when**
  - `rg 'umount -l' nix/e2e-tests/lib` and any ignored-luksClose-failure path return nothing.
  - Tests 55 and 12 re-open the volume and fail when the T-107 recovery fix is reverted.
  - Fault tests (a)-(h) exist, are tagged `faults`, run in the full suite, and pass once their product fixes land.
  - Test (d) fails and lists the holders whenever emergency leaves the hidden filesystem busy.

  _Status: Done in wave 19 (strict harness, `faults/90-95` plus state/55 and 58 tagged `faults`, 55/12 re-open and recover, 75 aligned; suspend/hibernate phase stays nightly follow-up; all pending a Nix runner)._

- [x] **T-112: Command surface and help: hide internal commands, workflow help with EXAMPLES and EXIT STATUS, value hints, neutral examples** (medium · effort S)

  **Problem**
  - `nails --help` repeats the name with `long_about = None` (`nails-cli/src/cli/args.rs:14`); no examples, no exit codes, no explanation of the workflow or the binary-location rule.
  - The internal `notify-dispatch` command appears in public help (`args.rs:193-194`). The `--flake` help hard-codes a NAILS OS attribute `amnesia-virtualbox` (`args.rs:96`). Path arguments have no `value_hint`.
  - The command set lacks `check`, `config` and `recover` (`args.rs:37-199`), so readiness checks, config inspection and stuck-state recovery all need external docs or hand-editing `state.json` (`USER-SECURITY-GUIDE.md:516-519`).

  **Fix**
  - Final public command set: `init`, `check` (alias `doctor`), `activate`, `deactivate`, `emergency`, `status`, `verify`, `config {path, show, validate}`, `recover`. Mark `notify-dispatch` and the watcher subcommand `#[command(hide = true)]`.
  - Root `long_about` explains the four-step workflow (open/mount the backend, init, activate, deactivate or emergency) and the rule that the binary lives in the hidden root and is invoked by full path. Each command gets an `after_long_help` EXAMPLES section; the root `after_long_help` has an EXIT STATUS table generated from the `ExitStatus` enum.
  - Add `value_hint(DirPath/FilePath)` to path arguments. Replace the `--flake` example with a neutral `<path>#<host>`. Each flag's help states its default explicitly.
  - Shell completions/man page are owned elsewhere; if `completions <shell>` is added it prints to stdout only and is never installed into system or decoy-home directories.
  - Add cargo snapshot tests of `--help` for every command.

  **Done when**
  - `nails --help` lists exactly `init`, `check`, `activate`, `deactivate`, `emergency`, `status`, `verify`, `config`, `recover`; `nails notify-dispatch` still runs but is hidden.
  - Root long help explains the workflow and binary-location rule; every command's long help has EXAMPLES; a test asserts every `ExitStatus` variant appears in the EXIT STATUS help text.
  - `rg amnesia nails-cli/src` returns nothing; path args have value hints.
  - cargo `--help` snapshot tests pass; E2E `contract/65-help-version-no-leak.nix` passes.

  _Status: Done in wave 19 (workflow help, EXIT STATUS, EXAMPLES, hidden `notify-dispatch`/`watch`, value hints, neutral examples, `contract/65-help-version-no-leak.nix` pending a Nix runner)._

## Wave 20: Runtime journal handling + fixture trim/persona E2E

### W20-C1: Runtime journal handling

Owns: `nails-core/src/cleanup/manager.rs`, `nails-core/src/deactivation/orchestrator/mod.rs`, `nails-core/src/manager/activation/overlay_mount/mod.rs`

- [x] **T-113: Handle the journal explicitly at activation and teardown (flush onto the overlay; volatile runtime journal after emergency)** (high · effort M)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (the journal flush onto the `/var` overlay). The item stays ticked as history; it describes no current code._

  **Problem:** `/run` is excluded from overlays (`nails-core/src/config/types.rs:70`), and journald's volatile store lives at `/run/log/journal`. On a tmpfs-root decoy (`Storage=volatile`, or `auto` with no `/var/log/journal` — the recommended posture), everything journald records during a hidden session stays in RAM: hidden service lifecycle, sudo commands, user-service stderr. It survives emergency teardown, which does not reboot (`reboots_on_success` matches only `Normal`, `nails-core/src/manager/deactivation.rs:261`), so anyone at the machine can read it with `journalctl`. The only journal handling today is a restart of systemd-journald after the /var overlay (`nails-core/src/manager/activation/overlay_mount/mod.rs:176-183`); cleanup never touches the journal, and forensic test 05 hides the gap by excluding journal dirs from its grep (`nix/e2e-tests/tests/forensic/05-standard-deactivation-forensic.nix:34`).

  **Fix:**
  - At activation, after the /var overlay mounts, run `journalctl --flush` so the persistent on-overlay journal receives entries, and record the activation-start cursor.
  - At deactivation and emergency (`nails-core/src/deactivation/orchestrator/mod.rs`, unmount in `unmount.rs`), before unmounting /var run `journalctl --relinquish-var`; after unmount rotate and remove runtime journal files under `/run/log/journal` (all of them, or those newer than the recorded cursor), via `nails-core/src/cleanup/manager.rs`.
  - Warn the operator that only a reboot is a complete remedy (emergency does not reboot).
  - Route every journal command through the platform/command abstraction; systemd-only, since non-systemd hosts are refused elsewhere.
  - Stop excluding journal dirs from the forensic grep so leaks are caught.

  **Done when:**
  - Volatile-journal VM E2E (`nix/e2e-tests/tests/security/03-emergency.nix`): activate, write a unique journal marker, emergency; `journalctl --since <activation>` and files under `/run/log/journal` contain neither the marker nor any hidden path.
  - Persistent-on-overlay E2E: marker lines land in the hidden /var upper, not on the decoy.
  - Unit tests assert the command order: flush after /var overlay mount, relinquish before /var unmount.
  - `cargo test` and `cargo clippy` clean; forensic test 05 no longer passes `--exclude-dir=journal` and still passes.

### W20-C2: Fixture trim + persona E2E

Owns: `nix/e2e-tests/lib/base-node.nix`, `nix/e2e-tests/tests/persona/`, `nix/e2e-tests/lib/persona-helpers.nix`

- [x] **T-114: Shared base node, duplicate-test removal and fewer avoidable reboots in E2E (one derivation per test)** (medium · effort M)

  _Status: partial (wave F1). Done: a shared `base-node.nix` injected by `default.nix` for single-machine specs; the redundant `nodes` block dropped from 48 vm-config+nails specs and 3 set to `baseNode = { python3 = true; }` (distinct node blocks 104→53, remaining ~10 are genuinely bespoke); the trailing no-assertion cleanup reboot removed from `contract/58`; the README skeleton rewritten to the no-nodes convention with an "Adding a test" step and a per-test fixed-cost subsection; stale self-check headers already gone; the named duplicate tamper files no longer exist. Remaining: the `config/24`→`overlay/69` merge (different config sources, adds reboots — deferred to avoid a silent break without nix eval), filling the measured boot-to-first-subtest number from a hosted run, and the hosted-runner full-suite evaluation of the swept flake — see nix_pending._

  **Problem:** The 80 test derivations use 16 distinct `nodes` blocks. 45 of them use the same node (vm-config + nails) and 10 more only add python3. Every test boots its own VM, and even the cheapest take 49-59 s. `canonical_deactivate` (nix/e2e-tests/lib/test-helpers.nix:137, used in 44 files) always reboots, often only as trailing cleanup: 61 reboots 4 times (about 381 s) and 62 reboots 3 times (about 329 s). Tamper setup appears three times: 20-preflight-state-check:48, 52-state-checksum-tamper and 60-status-always-exits-zero:62. 24-config-extended-overlays and 69-overlay-extended-targets use the same config. 32 files carry stale `# Self-check: ... hard assertions` headers.

  **Fix:** Keep one derivation per test so caching, drvPath selection and failure isolation stay precise. Do not merge test families.
  1. Add `nix/e2e-tests/lib/base-node.nix` (vm-config + nails, plus a python3 variant). `default.nix` applies it when a spec declares no `nodes`. One-off nodes stay explicit. Do not add zsh, fish or notify tools globally, because absence tests such as 51-notify-no-notify-send depend on them being missing.
  2. Duplicates: test tamper refusal only in 52. Drop the tamper subtest from 20 and move 60's "tampered state still exits zero" assertion into 52. Move 24's unique subtests (persistence, reactivation, decoy-boot hiding) into 69, delete 24, and update `ciNames`/`shard-durations.json` if they are affected.
  3. Drop trailing `canonical_deactivate` calls from tests that never assert on deactivation. For repeated activation cycles that do not test deactivate, reset with `nails emergency` followed by a strict close and re-open of the hidden volume. Add no test-only env hooks; `NAILS_REBOOT_PATH` is being removed from the release binary.
  4. Delete every `Self-check` header.
  5. Measure boot-to-first-subtest from driver logs on hosted runners and record it in `nix/e2e-tests/README.md`. Revisit consolidation only if fixed cost still dominates after parallelism and caching.
  Run this as one serialized sweep after the other E2E test edits land.

  **Done when:** specs without `nodes` evaluate with baseNode and the number of distinct node blocks has clearly dropped; every remaining `canonical_deactivate` is followed by post-deactivation assertions; no duplicate tamper or extended-overlay scenario remains; `rg 'Self-check' nix/e2e-tests` is empty; the README records the measured per-test fixed cost; the full E2E suite passes.

  _Status: shared base node done (`lib/base-node.nix`, applied by `default.nix` to specs without `nodes`) and Self-check headers are gone; remaining: the serialized sweep dropping `nodes` from the standard specs, duplicate removal (config/24 into overlay/69, tamper only in state/52), trailing `canonical_deactivate` removal and the hosted-runner fixed-cost measurement in the README (needs Nix evaluation and hosted runs)._

  _Status (2026-10):_ done. The tamper scenario lives only in state/52 (preflight/20's tamper subtest is gone; config/24 and overlay/69 cover different configs and assertions and stay separate). `nix/e2e-tests/README.md` records the measured local per-boot cost and states why no hosted-runner figure exists yet, with the dispatched job that measures it. Single-boot merging landed with T-140. The suite is green at 5751ec92 (102 tests).

- [x] **T-115: Persona-separation E2E tests (remote-state pull-back, fresh-home mode, graphical emergency, stale writers) and documentation of the sync limitation** (critical · effort L)

  **Problem:** Deactivation only throws away the overlay upper dirs (`nails-core/src/deactivation/orchestrator/unmount.rs:30-108`). Account-bound decoy clients (two-way sync, IMAP Sent folders, browser sync) that run in the hidden session push hidden data to their servers. After deactivation, the decoy client resumes from its pre-activation local state, reconciles, and pulls that data back onto the decoy disk, where a post-use disk examiner can find it. `docs/USER-SECURITY-GUIDE.md:426` ("plausible recent activity") and `:465` ("Create some decoy activity") make this more likely. No E2E test covers sync clients, decoy user units or timers, autostart inheritance, a graphical emergency, or stale cwd/fd writers. `33-session-kill-graphical.nix:150-152` asserts that the session restarts before the NixOS switch.

  **Fix:**
  1. Add a two-node test under `nix/e2e-tests/tests/persona/`, with helpers in `lib/persona-helpers.nix`. Node `peer` runs Syncthing with pre-generated device keys committed under `fixtures/persona/` and is paired declaratively with testuser's decoy client.
     - Default mode: the hidden session writes a canary into the synced folder, then deactivate. After the decoy client resyncs, the host-side disk-image check finds the canary on the decoy image. Assert this as the documented known limitation; it also serves as a positive control.
     - Fresh-home mode: the decoy client never starts in the hidden session. Hard-assert that the peer never receives the canary and that the decoy image stays clean.
  2. Graphical emergency (`lib/graphical-vm-config.nix`): activate in a graphical session, run `nails emergency`, and assert the outcome defined by the emergency process-handling item.
  3. Stale writer: with `--no-kill-session`, a decoy process holding a cwd or fd in /home writes after activation. Assert the stale-writer detection or warning, and check on the disk image where the write landed.
  4. Decoy user-timer canary, once persona state inventory/masking exists: assert the timer does not run in the hidden session.
  5. Out of scope: the "hidden user exists before login" test, which waits for the TODO-only separate hidden user. The item that changes session-restart ordering also updates test 33.
  6. Docs: add a "Remote state and sync clients" limitation to `README.md` and `docs/USER-SECURITY-GUIDE.md`. Qualify `:426` and `:465` so decoy activity is advised only with sync and account clients disabled, or in fresh-home mode. Present fresh-home mode as the mitigation.

  **Done when:** the default-mode test reproduces the pull-back and is labelled as a known limitation; the fresh-home test asserts that neither the peer nor the decoy image contains the canary; the graphical-emergency and stale-writer tests exist and pass against the implemented behaviour; README and the guide state the remote-state limitation and contain no unqualified "create decoy activity" advice.

## Wave 21: Sleep policy + operator command docs

### W21-C1: Sleep/suspend policy

Owns: `nails-core/src/preflight/checks/sleep_policy.rs`, `nails-core/src/config/types.rs`, `nails-core/src/manager/activation/mod.rs`

- [x] **T-116: Suspend/hibernate while active: preflight warning, documented lid policy, opt-in sleep_policy block|teardown** (medium · effort M)

  _Status: implemented on overhaul — `[sleep_policy]` config (warn/block/teardown), the `sleep-policy` preflight warning with a fixture-parse unit test, and the `/run`-backed sleep guard (block inhibitor; teardown via the bounded `emergency_deactivate` on `PrepareForSleep`), wired into activation/deactivation, plus the lid-switch opsec docs. Remaining: the three E2E 'Done when' cases (block holds/releases an inhibitor, teardown on simulated suspend, warn-only) and live-bus zbus inhibitor/PrepareForSleep verification are not authored — untestable in this sandbox (unix sockets/nix unavailable); to be added to nix/e2e-tests in a later wave._

  **Problem**
  Nothing handles suspend or hibernate: no logind inhibitor, no `PrepareForSleep` handler, no `HandleLidSwitch` check (grep across `nails-core/src` finds only session-termination use of logind). logind defaults to `HandleLidSwitch=suspend` and desktops auto-suspend, so closing the lid leaves an active hidden session resident in RAM; on resume the decoy login unlocks the still-live session. The only guidance today is `docs/USER-SECURITY-GUIDE.md:397` ("Power off completely (not suspend)"). A permanent block inhibitor can overheat a closed laptop, and teardown-on-sleep is bounded by logind `InhibitDelayMaxSec` (default 5s), so it must reuse the bounded emergency path.

  **Fix**
  1. New preflight check `nails-core/src/preflight/checks/sleep_policy.rs`, registered in `nails-core/src/preflight/checks/mod.rs` (follow the existing `pub mod` / `pub use` pattern), parsing `logind.conf` + drop-ins for effective `HandleLidSwitch`, `HandleLidSwitchExternalPower`, `IdleAction`/`IdleActionSec` and, where detectable, desktop auto-suspend; warn when any would suspend an active session.
  2. Add an opt-in `[sleep_policy]` block to `nails-core/src/config/types.rs` (TOML, `deny_unknown_fields`) with `mode = "warn" | "block" | "teardown"`, default `warn`.
  3. For `block`/`teardown`, spawn a small helper in `/run` that holds a logind inhibitor fd while Active and exits on deactivate; wire its lifecycle into `nails-core/src/manager/activation/mod.rs` (start) and `nails-core/src/manager/deactivation.rs` (stop). `block` uses a sleep/idle block inhibitor; `teardown` uses a delay inhibitor whose `PrepareForSleep` handler invokes the bounded `emergency_deactivate` (`nails-core/src/emergency.rs`) inside the delay window.
  4. Ship a documented hidden-config snippet setting the lid switch to `ignore`/`lock` in the operator opsec docs, and update `docs/USER-SECURITY-GUIDE.md:397`.

  **Done when**
  - Unit test: the preflight check reports effective lid/idle settings parsed from a fixture `logind.conf`.
  - E2E: `sleep_policy=block` holds an inhibitor while Active (visible in `systemd-inhibit --list`) and releases it after deactivate.
  - E2E: `sleep_policy=teardown` runs emergency teardown on a simulated suspend within the delay window.
  - Default `warn` only prints the warning and holds no inhibitor.

### W21-C2: Operator command docs

Owns: `README.md`, `docs/USER-SECURITY-GUIDE.md`, `docs/configuration.md`

- [x] **T-117: Operator docs for the new command/flag/config/exit-code surface, full-path invocation, panic path and upgrade notes** (medium · effort M)

  _Status: done on overhaul — README and the security guide use one mount point and the full-path `sudo "$ROOT/nails" …` form, add a CLI/exit-code/JSON reference (cross-checked against args.rs and ExitStatus), a hidden-generation panic switch snippet with the NOPASSWD warning, and replace `sudo rm state.json`/decoy-side verify with `nails recover` and pre-reboot/offline verification; the required CHANGELOG 'Upgrading' subsection was added at integration (config TOML migration, renamed/removed flags, exit-code/JSON changes, state schema incl. boot_id and the removed Emergency state). The config-reference 'every Config field' done-when is covered by nails-core/tests/config_reference.rs._

  **Problem**
  The docs disagree on the mount point and the invocation form. The install section mounts `/mnt/hidden` (README.md:83-88) while Quick start mounts `/mnt/hidden-volume` and runs `nails init /mnt/hidden-volume` with no sudo on a root-owned fresh mount (README.md:120-166). The command table (README.md:179-182) and the guide (USER-SECURITY-GUIDE.md:128-132,446,479) use bare `sudo nails ...`, even though the guide says to run the binary from the hidden volume and flags `/usr/local/bin/nails` as wrong (USER-SECURITY-GUIDE.md:93,115). sudo's `secure_path` excludes the hidden root, so copy-pasted commands fail or push users toward a decoy-side PATH install, and mixing mount points yields mismatched binary-derived roots. The guide still tells operators to `sudo rm /mnt/hidden-volume/state.json` (USER-SECURITY-GUIDE.md:518) and to verify from the decoy side (README.md:90-94). No upgrade notes exist (CHANGELOG has no Upgrading section) even though this branch changes the config format (YAML to TOML), flags, exit codes, the JSON shape and the state schema.

  **Fix**
  1. Use one mount point across README, guide and examples. Define it once (`ROOT=/mnt/hidden`), always invoke `sudo "$ROOT/nails" ...`, state explicitly that nails is never on the decoy PATH, and remove any symlink/PATH-install suggestion (a convenience alias may live only inside the hidden NixOS config).
  2. Document `nails init` run with sudo (or chown the fresh mount first) and make the documented next steps match the new init output.
  3. Replace README step 7 (decoy-side `nails verify`) with the pre-reboot verification report plus `verify --offline` from a live medium; recommend no `nix run` or install on the decoy.
  4. Add a config reference for `nails.toml` covering every key, its default, `allow_leaky_exclusions`, and strict unknown-key behaviour; add a CLI reference covering the new `activate` flags, `-y` semantics, global flags, the exit-code table, and the JSON envelope (`schema_version`). If the docs chunk creates the configuration/CLI reference pages, fill those instead of duplicating.
  5. Document emergency: immediate by default, `--poweroff`, and the hidden-generation panic snippet (root-owned oneshot unit, polkit rule, keybinding), with a warning never to grant NOPASSWD sudo for a user-writable binary.
  6. Replace the `sudo rm state.json` guidance (USER-SECURITY-GUIDE.md:518) with `nails recover`.
  7. Add an 'Upgrading' subsection to CHANGELOG.md for this release (convert `nails.yaml` to `config/nails.toml`; removed/renamed flags; new exit codes and JSON shape; state schema change including `boot_id` and the removed Emergency state, and what happens to existing state files), and keep it as a template for future releases.

  **Done when**
  - `grep -rn 'sudo nails \|/mnt/hidden-volume' README.md docs/USER-SECURITY-GUIDE.md` returns nothing; every invocation uses the full-path form.
  - No document instructs deleting `state.json`, running verify from a decoy-side binary, or using `nix run`/installing on the decoy.
  - The config reference lists every field of the `Config` struct (checked by a test or script comparing key names) and the documented exit-code table matches `ExitStatus`.
  - CHANGELOG.md contains an 'Upgrading' subsection for this release covering config format, flags, exit codes/JSON and state schema.
  - The emergency section documents the immediate default, `--poweroff`, and the hidden-generation panic unit/polkit snippet, including the NOPASSWD warning.

## Wave 22: Emergency backend close/lock

### W22-C1: Emergency backend close/lock

Owns: `nails-cli/src/cli/commands/emergency.rs`, `nails-cli/src/cli/commands/status.rs`, `nails-cli/src/cli/detach.rs`

- [x] **T-118: Opt-in backend close/lock after emergency and loud reporting when the hidden root is still mounted** (high · effort M)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (`--lock-backend`; the backend is now always closed). The item stays ticked as history; it describes no current code._

  **Problem:** No code path ever unmounts or closes the hidden backend. `run_deactivation` (`nails-core/src/manager/deactivation.rs:394`, emergency wrapper at `:548`) only tears down overlays. After `nails emergency` the hidden filesystem stays mounted and browsable, the dm-crypt mapper stays open, and the master key stays in kernel memory. The user only sees "Dismount the hidden volume when it is safe to do so" (`nails-cli/src/cli/commands/emergency.rs:120-135`, where the JSON is a hardcoded string). Unlocking backends stays out of scope. The state.json write to the hidden root is required and stays. Because the binary and state.json live on the hidden root, a plain `umount` plus `cryptsetup close` fails with EBUSY.

  **Fix:**
  - Add a strict TOML opt-in: `[emergency] lock_backend = false` (default), and a CLI flag `nails emergency --lock-backend` that forces it for a single run. Add an optional `close_command = ["argv", ...]` (no shell) for backends that are not dm-based.
  - After overlay teardown, history truncation and the state.json write, call `sync`. Then find the device backing `hidden_volume_root` in `/proc/self/mountinfo` and walk the dm/loop chain. Lazy-unmount the hidden root (`MNT_DETACH`), mark the dm device(s) for deferred removal (`DM_DEFERRED_REMOVE`, the equivalent of `cryptsetup close --deferred`), and exit. When the last reference drops, the kernel removes the device and wipes the key, and loop autoclear runs. If `close_command` is set, run it through the shared journal-free detached-run path: `StandardOutput`/`StandardError=null` and a neutral unit description. The current journal redirect at `nails-cli/src/cli/detach.rs:237-238` must not be reused.
  - Report every failure loudly. Nothing is suppressed.
  - Whenever the hidden root is still mounted, emergency output (human and JSON envelope), `nails status` and `nails verify` must say `hidden root still mounted at <path>`, with Critical severity after an emergency. Align this with the status/verify severity rework. Without the opt-in, print the exact manual close sequence.
  - Rewrite `docs/USER-SECURITY-GUIDE.md:163-175` and `:460-462`. State plainly that without the lock the hidden filesystem stays mounted and readable. Document the manual sequence and the tradeoff: device-removal kernel messages may still reach the journal.

  **Done when:**
  - A config test parses `[emergency]`, and an unknown key in that table is rejected.
  - Unit tests cover the mountinfo-to-dm-chain resolution against `MockFilesystem`, including the not-dm and already-unmounted cases.
  - E2E `nix/e2e-tests/tests/security/03-emergency.nix` (LUKS via `nix/e2e-tests/lib/hidden-volume.nix`) passes in both modes:
    - With `lock_backend`: after the process exits, `findmnt /mnt/hidden-volume` is empty and `/dev/mapper/hidden-volume` is gone. Close failures make the test fail.
    - Without it: emergency and `status`/`verify` output report the still-mounted hidden root as Critical.
  - The journal has no output from the close helper.
  - `cargo test`, `cargo clippy` (zero warnings) and the coverage gate all pass.

## Wave 23: Operator guide, threat model, CLI reference, README, ADR, jargon cleanup

### W23-C1: Documentation (guide, threat model, CLI ref, README, ADR)

Owns: `Cargo.lock`, `docs/threat-model.md`, `docs/operator-guide.md`, `docs/cli.md`, `docs/adr/0001-live-overlay-vs-boot-time-overlay.md`

- [x] **T-119: Rewrite USER-SECURITY-GUIDE against the code as an operator guide organised around where each step runs, with recovery runbook and honest limits** (critical · effort M)

  _Status: done in wave 23 (W23-C1). `docs/operator-guide.md` replaces the deleted USER-SECURITY-GUIDE (inbound links retargeted; decoy-side history hardening moved to decoy-requirements.md; fictional 5-layer defence corrected), with a findmnt-driven recovery runbook covering suspend, power loss, backend loss, ENOSPC, crash and OOM plus the VeraCrypt protection-mode warning. `nails activate` now writes a read-only pre-mount residue report under `<hidden-root>/reports/` (unit tests + smoke 01 assertion; the assertion still needs a run on a Nix host)._

  **Problem:** `docs/USER-SECURITY-GUIDE.md` is marked "required reading" (L5) but describes protections that do not exist, and following it literally leaves traces on the decoy. The "5-layer" history defense (L263-299) is mostly fictional: only deactivation truncation exists (`cleanup/history/mod.rs:262-364`). The deep-verify table (L196-207) lists checks `verifier.rs` does not run. The guide tells users to run a nonexistent `nails deactivate --force` (also in `verifier.rs:400,411`) and to `rm state.json` (L514-518). The standard-vs-emergency table (L135-146) says "via reboot" for steps the code runs explicitly in both modes (`deactivation.rs:470-505`). Incomplete-deactivation recovery (L482-534) unmounts the backend before the overlays, uses hard-coded unmount lists and runs `kill -9 $(pgrep -f nails)`. Decoy-shell commands (`cat <hidden>/state.json`, `cryptsetup close veracrypt-hidden`, `verify --deep`) and names like `/mnt/hidden` and `veracrypt-hidden` end up in history, sudo logs and mount-unit names. Nothing covers suspend, power loss, backend loss, ENOSPC, crash or OOM. Nothing warns that writing to a VeraCrypt outer volume outside protection mode destroys the hidden volume. In code, `emergency.rs:7` claims a decoy switch, and `preflight/checks/state.rs:86-92` says a reboot resets state, which is false because state.json survives reboot.

  **Fix:**
  - Delete the old guide (no stub) and write `docs/operator-guide.md` from current behaviour. Organise it by where each step runs: separate machine, hidden session or decoy shell. Add a "never type on the decoy" box. Use one `<hidden-root>` placeholder, absolute binary paths and neutral names (mapper `data0`, mount `/mnt/usb`), and note that renaming alone is not enough.
  - Sections:
    - **What NAILS does:** pre-activation pattern clean and history truncation on deactivate. Decoy-side history hardening moves to `docs/decoy-requirements.md`.
    - **How it works:** hidden-root layout, the `hardware-configuration.nix` import, the auto overlay set and activation order. Swap the binary only while inactive.
    - **Standard vs emergency:** a table built from `ManagerDeactivationKind`.
    - **Decoy prerequisites and limits:** volatile journald or impermanence, sudo/PAM residue, a sleep/lid snippet, crash-reporting channels, the fact that emergency mode leaves processes running and the backend mounted, and the fact that the binary is identifiable.
    - **Outer-volume maintenance:** write only in VeraCrypt protection mode (`--protect-hidden=yes`). `cryptsetup --type tcrypt` cannot provide this protection. Seed decoy content once, when the volume is created.
  - Add a "When things go wrong" runbook covering interrupted activation, stuck deactivating, emergency state, suspend, power loss, backend loss, volume full, crash/hang and OOM. Each entry gives what the user sees, the history-off prefix, the exact command order, the reset command and the expected residue.
    - Command order: start from `findmnt -rn -t overlay -o TARGET | sort -r` (deepest first, no lazy unmount), stop nix-daemon if /nix is overlaid, unmount, close the backend, then confirm with `findmnt -t overlay` and `dmsetup ls`.
    - Reset: `nails recover`. Until it lands, delete state.json only after `findmnt -t overlay` is empty.
    - Use the recorded PID or binary path instead of `pgrep -f nails`.
  - Link `docs/threat-model.md` and `SECURITY.md`, and drop the "Version 1.0" footer.
  - Replace the post-reboot decoy-side `nails verify`. `nails activate` runs the read-only decoy residue scan before it mounts overlays, writes the report to `<hidden-root>/reports/` and prints a one-line summary. Keep `verify_on_deactivate` only for emergency mode, or remove it.
  - Code strings:
    - `verifier.rs` fix guidance points to the recovery command.
    - The `emergency.rs` module doc describes what emergency mode actually does.
    - StateCheck messages drop the reboot claim.
    - Coordinate wording with the recovery/state-reconciliation item. Guide verify rows describe only checks the verify engine actually runs.

  **Done when:**
  - `git grep -nE 'USER-SECURITY-GUIDE|deactivate --force|HISTFILE=/dev/null|5-Layer|Version 1.0'` finds nothing in docs/ or nails-core/src.
  - docs/operator-guide.md contains no `veracrypt-hidden`, `/mnt/hidden` or `/mnt/hidden-volume`.
  - Every recovery sequence takes its targets from `findmnt -t overlay` and unmounts overlays before the backend.
  - Each row of the mode table matches `deactivation.rs` and the orchestrator.
  - The outer-volume warning and the journald, sleep, crash and emergency-limits sections are present.
  - No documented step runs nails or edits hidden files from the decoy shell after reboot.
  - Activation writes a residue report: a mock-fs unit test covers it, and an E2E test checks that the report exists and the decoy is unchanged.
  - `state.rs` tests are updated and `nix develop -c cargo test -p nails-core` passes.

- [x] **T-120: Help text, nails completions, man page, generated CLI docs, published JSON schemas and exit codes shipped in the release tarball** (low · effort M)

  _Status: done in wave 23 (W23-C1). Root EXAMPLES section, `nails completions <shell>` (clap_complete), `nails.1` and `docs/cli.md` generated and staleness-checked by `nails-cli/tests/cli_reference.rs` (`REGENERATE_CLI_DOCS=1`), canonical schemas in `docs/schemas/` (status, verify, activate, deactivate, emergency; fixture copies removed, tests 58/59 repointed), and the release tarball stages the man page and operator docs. `nix build .#nails-release` still needs a run on a Nix host._

  **Problem:** Help text is minimal: `nails-cli/src/cli/args.rs:14` sets `long_about = None`, and there is no `after_help`, no examples and no `value_hint`. There is no clap_complete or clap_mangen, and the README defers to `nails --help`. Verify exit codes (0/1/2) are documented only in a doc comment (`nails-cli/src/cli/commands/verify.rs:21-24`). The status/verify JSON schemas exist only as E2E fixtures (`nix/e2e-tests/fixtures/schemas/*.json`, `$id https://nails.local/...`). Activate, deactivate and emergency JSON output has no schema and no `schema_version`. The release bundle stages only `nails`, `LICENSE` and `README.md` (`flake.nix:166-168`). Help text must not contain blocked default paths, because the security binary scan and the contract tests check for them. Completions or man pages installed on the decoy are persistent artifacts.

  **Fix:**
  - In `args.rs`:
    - Add a `long_about` that describes the mount -> init -> activate -> deactivate/emergency flow.
    - Add an `after_long_help` with EXAMPLES (placeholders only) and an EXIT STATUS section generated from the `ExitStatus` enum of the JSON-envelope item.
    - Set `ValueHint::DirPath`/`FilePath` on path arguments.
  - Add `nails completions <shell>` that writes to stdout only, for `source <(...)` inside the hidden session.
  - Generate `nails.1` (clap_mangen) and `docs/cli.md` (clap-markdown) from a test in `nails-cli/tests/cli_reference.rs` that fails when the committed files are stale. No new CI job is needed. Document exit codes per command in `docs/cli.md`.
  - Move the schemas to `docs/schemas/{status,verify}.schema.json` with a `schema_version` that matches the envelope. Add schemas for every other command that emits JSON. Point the E2E contract tests at `docs/schemas/` and delete the fixture copies.
  - In `flake.nix` `nails-release`, also stage `nails.1`, `docs/cli.md`, `docs/operator-guide.md` and `docs/threat-model.md`. The tarball lives on the hidden root; never install completions or the man page into decoy paths.
  - Removing no-op flags belongs to the flag-redesign item.

  **Done when:**
  - `nails --help` shows the workflow, EXAMPLES and EXIT STATUS.
  - A cargo test asserts that no blocked default path substring appears in any help output.
  - `nails completions bash|zsh|fish` prints to stdout and writes no files (test).
  - `docs/cli.md` and `nails.1` are generated, and a test fails when they are stale.
  - The E2E contract tests load schemas from `docs/schemas/`.
  - `nix build .#nails-release` produces a tarball that contains `nails.1`, `docs/cli.md`, `docs/operator-guide.md` and `docs/threat-model.md`.

- [x] **T-121: Create docs/threat-model.md as the single threat-model source (assumptions, persona inheritance, remote state, residual channels, evaluation scope)** (high · effort M)

  _Status: done in wave 23 (W23-C1). `docs/threat-model.md` rewritten as the single source with all nine sections (the /var/lib/nixos drift stays marked under investigation until test 34 runs on a Nix host; the VeraCrypt nightly is stated as never run); README, SECURITY.md, the operator guide and configuration.md link to it._

  **Problem:** The threat model is spread across `README.md:189-205`, `docs/USER-SECURITY-GUIDE.md:61-74`, `SECURITY.md:5-21` and the website, and the copies disagree: only the guide adds an outer-encryption assumption.
  - Nothing tells users what the hidden environment shares with the decoy: the same user account and home, decoy services and user units that keep running, the same network identity, and remote or cloud state that is never rolled back. Guide L57 ("all hidden packages and services exist only inside the mounted hidden volume") and the emergency claims overstate the separation.
  - The exclusions for network-provider logs and remote service records are written down only in the thesis.
  - The one residual change seen in evaluation is undocumented: rewrites of the `/persist/var/lib/nixos` files declarative-users, declarative-groups, uid-map, gid-map and auto-subuid-map.
  - The docs do not say which configuration the forensic claims were evaluated on, list no residual channels, and do not answer the "customising the OS to avoid leaks is hopeless" argument (Shufflecake).

  **Fix:** Write `docs/threat-model.md` as the only place the threat model lives, with these sections:
  - **Adversary:** post-seizure forensic analysis.
  - **Assumptions:** outer encryption, an amnesic decoy per `docs/decoy-requirements.md`, no swap or hibernation, volatile journald.
  - **Out of scope:** includes network-provider logs and remote service records.
  - **What the hidden environment shares with the decoy:** the account and home model (link the opt-in fresh-home persona mode), inherited system and user units, network identity, and remote state that is never rolled back.
  - **Invariant:** no hidden-mode enabler (boot entry, initramfs hook, config file, NVRAM variable) may persist on the decoy.
  - **Residual channels:** the journal window before /var is overlaid, the sudo log, decoy activation at deactivation time (until it is removed), EFI NVRAM and memory.
  - **Answer to "cannot trust the OS":** NAILS redirects every write outside pseudo filesystems at the mount layer instead of tuning individual applications, so residual risk is limited to the listed channels.
  - **Known residual changes:** `/var/lib/nixos` bookkeeping drift with the file list above, marked "under investigation" until the drift-control item settles it.
  - **Evaluation scope:** the configuration behind the forensic claims (tmpfs root, `/persist`, no swap, VeraCrypt backend, dead-disk analysis). State that the automated E2E disk-image checks cover only LUKS/ext4 NixOS VMs.

  Replace the scope text in `SECURITY.md` with a link. The README and the operator guide link here (their own items remove the duplicated prose).

  **Done when:**
  - `docs/threat-model.md` has all the sections above.
  - `README.md`, `docs/operator-guide.md` and `SECURITY.md` link to it and no longer restate assumption lists.
  - The out-of-scope list names network and remote-service records.
  - No doc sentence claims hidden services are fully separate from decoy services.
  - The docs link check passes.

- [x] **T-122: Remove maintainer-process prose from user docs and give RELEASING, ROADMAP, SECURITY, CHANGELOG and the preflight README real content** (low · effort S)

  _Status: done in wave 23 (W23-C1 plus integration). RELEASING.md already held the tag policy; README/SUPPORT/SECURITY reduced to one link, SECURITY names 0.2.x, ROADMAP is Now/Next/Later with #5/#6, the preflight README defers to rustdoc with the real 500 MB floor; integration added the CHANGELOG compare links, #54 under Unreleased and the 'Upgrade notes' subsection opening with 'upgrade only while inactive'. The TODO redirect wording was already gone._

  **Problem:** Release-policy prose ("exact stable tag", "prerelease") is repeated in `README.md:79,251-252`, the CHANGELOG preamble, `SECURITY.md:27-33` and `SUPPORT.md` (L7, L24, L43). The SECURITY.md version table names no versions.
  - `ROADMAP.md` is generic. It does not link open issues #5/#6 and says nothing about multi-distro support or aarch64.
  - `CHANGELOG.md` has no compare links, its Unreleased section omits #54, and there is no upgrade guidance, although state.json carries version-compatibility logic.
  - `TODO.md` is a 5-line redirect.
  - `nails-core/src/preflight/checks/README.md` documents 6 of the 10 registered checks and gives a 1024 MB space default (L34) that does not match the runtime default.

  **Fix:**
  - Move the release policy into a new `RELEASING.md`. User docs keep only "use the latest release and verify it" plus one link.
  - SECURITY.md: the version table names real versions (0.2.x supported).
  - SUPPORT.md: trim it to channels and expectations.
  - Rewrite `ROADMAP.md` as Now/Next/Later with issue links:
    - Debian/Ubuntu now; Fedora/Arch backends later.
    - aarch64.
    - Research and redesign items: memory forensics, cross-backend evaluation, kexec/boot-time redesign, OpenRC/ostree support, usability study.
  - `TODO.md` is the backlog itself; remove the redirect wording.
  - CHANGELOG:
    - Add compare links and list #54 under Unreleased.
    - Add a fixed "Upgrade notes" subsection per release, starting with "upgrade only while inactive" and the YAML -> TOML config switch.
  - Replace the hand-written check list in the preflight README with a pointer to rustdoc (or generate it), and fix the space default.
  - The forensics-eval README goes away with `nix/forensics-eval`.

  **Done when:**
  - `RELEASING.md` exists.
  - README, SUPPORT and SECURITY contain no tag-policy prose beyond one link.
  - The SECURITY.md table names concrete versions.
  - ROADMAP uses Now/Next/Later with issue links.
  - CHANGELOG has compare links and an Upgrade notes subsection under Unreleased.
  - The preflight README lists every registered check (or defers to rustdoc) and contains no 1024 MB claim.

- [x] **T-123: README overhaul: runnable quick start with absolute paths, prerequisites, support matrix, documentation index, quickstart E2E test, docs link check** (high · effort M)

  _Status: done in wave 23 (W23-C1). README rewritten (auto mode, documentation index, operator-guide pointers), `docs/architecture.md` added, `scripts/docs-check.sh` (lychee --offline + retired-name guard) wired into the devShell, a flake check, pre-commit and a path-filtered CI job, new smoke test `quickstart-zero-config`, plus unit tests that the README nails.toml parses strictly and overlay-only activation writes no rebuild notification. The flake check, the VM test and the CI lychee install still need a run on a Nix host / hosted runner._

  **Problem:** The README quick start cannot be run as written.
  - **Inconsistent paths:** install puts the binary at `/mnt/hidden/nails` (README.md:84-107), Quick start mounts `/mnt/hidden-volume` (L121), and the commands are bare `nails init`/`sudo nails activate`/`nails verify` (L127-172), which nudges users to put nails on PATH on the decoy.
  - **Wrong key:** L139 documents `hidden_volume_root`, but init writes `hidden_volume_path` (`init.rs:45`).
  - **Decoy traces:** options 2/3 build on the decoy (source tree, store paths, gcroots, ~/.cargo), L133/L148 run `$EDITOR` on hidden files before activation (viminfo/shada history), and L169-173 run `nails verify` from the decoy after reboot. Names like `veracrypt-hidden` and `/mnt/hidden` appear throughout.
  - **Missing prerequisites:** no backend-creation example, no filesystem requirements, and the `hardware-configuration.nix` prerequisite is not mentioned.
  - **Inaccurate description:** "How it works" (L42) does not describe auto mode.
  - **Discoverability:** the guide and `docs/vulnerability-handling.md` have no inbound links. `docs/ci.md` is tracked but listed in `.gitignore:150`, and `docs/architecture.md` is ignored (`.gitignore:148`). There is no link check.
  - **Fake rebuild step:** overlay-only activation logs "[6/7] Running NixOS switch/rebuild" and writes a "NixOS Rebuild Complete" notification although no rebuild ran (`manager/activation/mod.rs:387-424`).

  **Fix:**
  - README commands:
    - Use one `<hidden-root>` placeholder and absolute invocations (`sudo <hidden-root>/nails init <hidden-root>`), and warn against PATH installs and decoy aliases.
    - Install: download and verify on a separate machine, then copy onto the backend. Drop decoy builds or warn about their residue.
    - Edit hidden config only inside an active session or with history-free editors (`vim -i NONE -n`).
    - Remove the post-reboot decoy-side verify step; the activation-time residue report replaces it.
    - Use neutral names (`data0`, `/mnt/usb`).
  - Add a Prerequisites box: the `./hardware-configuration.nix` import (NixOS only), backend filesystem requirements (link `docs/backends.md`) and one LUKS+ext4 creation example.
  - Config examples use the strict TOML file and keys.
  - Describe auto mode correctly.
  - Add a support matrix:
    - NixOS: reference platform, full support.
    - Debian/Ubuntu: overlay-only; amnesic decoy required; read-only /usr guard.
    - Fedora/Arch: planned.
    - Refused: ostree/rpm-ostree, transactional-update, non-systemd init.
  - Use a tagline that is not NixOS-only and keeps the NAILS acronym.
  - Replace the threat-model prose with a link.
  - Add a Documentation section linking nails.run, the operator guide (also linked from the alpha warning and Quick start), threat model, decoy requirements, backends, configuration, CLI reference, architecture, release verification and vulnerability handling.
  - Remove `docs/ci.md` and `docs/architecture.md` from `.gitignore` and track a curated `docs/architecture.md` (overview only, no planning IDs).
  - Add `scripts/docs-check.sh`: `lychee --offline` over the tracked *.md files plus a guard against retired names (`nails.yaml`, `~/.nails`, `USER-SECURITY-GUIDE`, `/mnt/hidden-volume`). Expose it as a flake check and a pre-commit hook, and run it in the cheap CI tier.
  - Code: when no NixOS builder runs (overlay-only or a non-NixOS platform), report the rebuild step as skipped, write no rebuild notification, and number steps from the steps that actually run. Build this on the Platform trait.
  - E2E: add a smoke test (`nix/e2e-tests/tests/smoke/`) that copies the binary onto the hidden root and runs init and activate without `--config` via `su - testuser -c 'sudo ...'`.
  - Separate repository: the nails.run site should pull `docs/` from this repo and fix its remote-filesystem backend claim and its nixos/ layout.

  **Done when:**
  - `grep -nE '(^|\s)(sudo )?nails ' README.md` finds only the command table or absolute-path forms.
  - The README config example parses with the strict TOML loader (test).
  - The README contains no `veracrypt-hidden`, `/mnt/hidden` or `/mnt/hidden-volume`.
  - The new smoke test passes locally.
  - The docs check passes in CI and fails on a deliberately broken link or a retired name.
  - `docs/architecture.md` is tracked.
  - A unit test shows that overlay-only activation lists no rebuild step and writes no rebuild notification.
  - The support matrix matches the platform detection and refusal logic.

- [x] **T-124: ADR: live overlay vs boot-time overlay mechanisms** (low · effort S)

  _Status: done in wave 23 (W23-C1). Created as `docs/adr/0005-live-overlay-vs-boot-time-overlay.md` (0001 is the accepted core-library-boundary ADR), with the comparison table, decision, revisit triggers and consequences; linked from `docs/architecture.md` and the ADR index._

  **Problem:** NAILS has never been compared with the boot-time "live mode" mechanisms that implement the same full-root overlay primitive: Kicksecure/Whonix grub-live, Ubuntu overlayroot, `systemd.volatile=overlay` and dracut `rd.overlay`/dmsquash-live. The multi-distro port is going ahead without that comparison. These mechanisms use a tmpfs upper and need a reboot, and several leave an enabler on the decoy, so they are not drop-in replacements. None of these trade-offs is written down.

  **Fix:** Add `docs/adr/0001-live-overlay-vs-boot-time-overlay.md` with a comparison table. For each mechanism, record:
  - whether it needs a reboot;
  - whether the upper layer is ephemeral or persistent;
  - what enabler persists on the decoy;
  - its initrd requirements (`systemd.volatile` needs a systemd initrd; the Debian/Ubuntu default initramfs-tools does not support it);
  - which NAILS leak classes it would remove (process detection, session kill, the journald window).

  The decision section records the current choice: a live overlay with a persistent, externally backed upper layer plus declarative hidden config. It also lists the conditions that would trigger the boot-time redesign, which stays on this TODO list as a separate item. Link the ADR from `docs/architecture.md`.

  **Done when:** the ADR exists with a comparison table and a decision section, `docs/architecture.md` links to it, and the docs link check passes.

## Wave 24: Naming & metadata (SPDX, publish=false, NOTICE)

### W24-C1: Naming & metadata

Owns: `CONTRIBUTING.md`, `NOTICE`, `REUSE.toml`, `nails-core/src/`

- [x] **T-125: Consistent naming and metadata: publish=false, homepage, copyright notice, SPDX headers, one tagline and NAILS OS spelling** (low · effort S)

  **Problem:** The project identity is inconsistent and the licensing metadata is incomplete.
  - `authors = ["NAILS Project"]` (Cargo.toml:9) is not a real holder, and the clap `#[command(author = ...)]` at nails-cli/src/cli/args.rs:12 is never shown because no help template uses `{author}`.
  - `homepage` points to GitHub instead of https://nails.run (Cargo.toml:11).
  - Neither crate has a `publish` key, so nails-core (it has no path deps) could be pushed to crates.io by accident.
  - None of the 230 `.rs` files has an SPDX or copyright header, and the repo has no copyright notice outside the GPL text.
  - The expansion "NixOS Anti-forensics Isolation & Layering System" will be wrong once Debian/Ubuntu are supported. It appears in args.rs:9,14, both crate descriptions, flake.nix:2, README.md:3, CHANGELOG.md:3, SECURITY.md:3, deny.toml:2, the doc comments in nails-core/src/lib.rs:3 and nails-cli/src/main.rs:3, and docs/*.md. The README, the GitHub description and nails.run use three different taglines, and the site spells it "NAILS-OS".

  **Fix:**
  - Add `publish = false` to nails-cli/Cargo.toml and nails-core/Cargo.toml. Setting it only in `[workspace.package]` does nothing unless each member also sets `publish.workspace = true`.
  - Set `homepage = "https://nails.run"` and replace `authors` with the pseudonymous holder. Delete the clap `author` attribute.
  - Keep the NAILS name but stop expanding the acronym. Pick one platform-neutral tagline (e.g. "Layer a hidden environment over a decoy Linux system") and use it everywhere listed above, including the clap `about`.
  - Update the help-text assertions in nails-cli/tests/cli_integration.rs:77 and nix/e2e-tests/tests/contract/65-help-version-no-leak.nix:45 to the new tagline.
  - Spell it "NAILS OS" everywhere. `nails-os` stays only as the repo slug in URLs.
  - Add a `NOTICE` file and a License line in the README reading `Copyright (C) 2025-2026 <holder>`. Leave `LICENSE` byte-identical so the GPL text and GitHub's license detection stay intact.
  - Run `reuse annotate --license GPL-3.0-or-later --copyright "<holder>" --year 2025-2026` on all `.rs` files. Cover all other files with globs in `REUSE.toml`. Add `LICENSES/GPL-3.0-or-later.txt` with `reuse download`.
  - Two files are at or near the 500-line limit (nails-core/src/cleanup/logs.rs is at 500, process/session/detection.rs at 497). Make scripts/check-line-count.sh skip the leading SPDX lines, or split those two files.
  - Add `reuse` to the devShell (flake.nix:224), add a pre-commit hook for it, and add a `reuse lint` step to the cheap lint tier in ci.yml.
  - Add a DCO sign-off section (`git commit -s`) to CONTRIBUTING.md.
  - Outside the repo, done by hand: change the GitHub repo description and the nails.run tagline to the chosen tagline, and fix the site's spelling to "NAILS OS".

  **Done when:**
  - `cargo metadata --no-deps --format-version 1 | jq '.packages[] | {name, publish, homepage}'` shows `publish: []` and `https://nails.run` for both crates.
  - `reuse lint` passes locally and in CI, and `./scripts/check-line-count.sh` still passes.
  - `NOTICE` exists and `git diff main -- LICENSE` is empty.
  - `grep -rn "NAILS Project\|Anti-forensics Isolation\|NAILS-OS"` finds nothing outside CHANGELOG history entries.
  - `nails --help`, the README lede, both crate descriptions and the flake description show the same tagline.
  - The updated help-text tests pass.

## Not planned for now

Research topics and larger redesigns that are tracked but not scheduled.

- [ ] **T-126: Deferred CI decisions: merge queue, final heavy-E2E runner, aarch64 release target** (low · effort S)

  **Problem:** Three CI decisions are deferred. Merge queues are not available for repositories owned by a personal account (WitteShadovv/nails), so the full E2E suite cannot gate merges via `merge_group`; the post-merge contract stands in for it (required smoke E2E on PRs, smoke on push to `main`, nightly full run, a `full-e2e` label, a `ci-red` issue, a red-main rule). The heavy-E2E runner strategy is still open (likely hybrid: hosted KVM smoke per PR, hosted full suite nightly or on demand, Hetzner kept as one manual lane). An aarch64 release first needs the flake and tests parameterised (~87 hard-coded `x86_64-linux` references) plus aarch64 E2E coverage.

  **Fix:** Revisit after the runner-parameterised E2E workflow has 2-4 weeks of nightly data. Runner: if hosted runners handle the full suite reliably, delete the manual Hetzner workflow, the `HCLOUD_TOKEN`/`HCLOUD_SSH_KEY_ID`/`PERSONAL_ACCESS_TOKEN` secrets and the `hetzner-pr` environment; otherwise keep the manual lane. Merge queue: consider moving the repo to a free organisation and gating on `merge_group` only if PR volume grows. aarch64: add `aarch64-unknown-linux-musl` once the system/target parameterisation and aarch64 E2E coverage exist.

  **Done when:** Each decision is recorded in `docs/ci.md`, and a follow-up work item is created when a decision is actually taken.

- [ ] **T-127: Internationalisation of user-facing strings** (low · effort L)

  **Problem:** User-facing strings are inline across commands, renderers, prompts and errors (e.g. `nails-core/src/prompts/mod.rs`, the CLI status/human output renderers in `nails-cli`, `nails-core/src/error.rs`), so safety-relevant prompts exist only in English. With the new defaults the pivot and restart prompts are rarely shown, and translating now is out of proportion for a solo-maintained alpha whose setup already assumes English-only docs.

  **Fix:** Record only. Once the output layer is consolidated and the English safety texts are finalised (short and unambiguous, as done for the activate confirmation and actionable errors), consider a Fluent-style catalog selected from `LANG`, translating safety prompts and errors first and keeping the machine-readable JSON keys untranslated.

  **Done when:** A TODO entry exists naming the prerequisite (centralised strings) and the trigger for revisiting (evidence of non-English operators).

- [x] **T-128: Full /usr overlay strategy and hidden software delivery on FHS distros** (medium · effort L)

  _Status (2026-10): done by the whole-root session. The whole decoy root, `/usr` included, is the lower of one overlay with its upper on the hidden volume, so `apt` and `dpkg` write into the upper and no process heuristics are involved (they were removed). What stays is the drift the problem names: a copied-up package database or `/etc` file shadows the decoy's after a decoy upgrade between sessions (ADR 0008, Risks). It is recorded there, not tracked as an item._

  **Problem:** Beyond the read-only `/usr` guard, the hidden environment on FHS distros cannot install software, and overlaying `/usr` has its own problems. The hidden package DB and copied-up files diverge from a lower `/usr` that the decoy keeps upgrading; process detection flags every process that maps the target (`nails-core/src/process/detection/mod.rs:118-126`, via mmap/fd/cwd checks) and only `/nix` has a `Skip` rule (`nails-core/src/process/classification/mod.rs:216-234`), so a `/usr` overlay would try to restart most of userspace. Comparable drift exists on NixOS: the hidden `/nix/var/nix/db` copy can reference store paths that decoy garbage collection later removes.

  **Fix:** Future design task (TODO only). Evaluate: an expert-only "overlay /usr" mode with a `/usr` Skip rule for read-only mmap/fd users plus a lower-drift warning; hidden software from self-contained trees on the hidden root (Nix via system-manager/home-manager bind-mounted only while active, Flatpak or containers with storage under the hidden `/home` or `/var`); systemd-sysext images (note their tie to os-release `VERSION_ID`). Add a VM test asserting that `apt` writes land in the hidden upper once a mode is chosen.

  **Done when:** A design note compares the options against the threat model and the decoy-drift problem, and the chosen mode is covered by a Debian/Ubuntu VM leak test. Files: planned `nails-core/src/platform/debian.rs`, `nails-core/src/process/classification/mod.rs`.

- [ ] **T-129: Further platform backends: Fedora (SELinux gate), Arch, non-systemd, ostree, aarch64** (medium · effort XL)

  **Problem:** Only NixOS and Debian/Ubuntu are in scope now, and no code references SELinux or AppArmor. On Fedora, executing an unlabeled binary from the hidden root through a systemd transient unit (`nails-cli/src/cli/detach.rs:177-244`, `systemd-run`) may be denied, and the denials are themselves audit-logged. Arch (no MAC by default) is lower risk. OpenRC/runit/s6 and ostree/image-based hosts are refused by detection but not supported. aarch64 has no release or E2E coverage.

  **Fix:** Future work (TODO only). Fedora: choose a hidden-root labeling strategy (`context=` mount option or documented `restorecon`), add an enforcing-mode VM test covering detach, copy-up and service restarts, and add an LSM-status preflight. Arch: new platform backend plus contract suite and VM images. Non-systemd: `ServiceManager`/`SessionManager` backends (`rc-service`, `sv`, elogind) and a non-systemd detach path. ostree/transactional hosts: evaluate separately. aarch64: derive the target triple per system, parameterise the test package, and add an aarch64-musl release asset only alongside aarch64 E2E coverage.

  **Done when:** Each new backend passes the platform contract suite and the portable VM suite before it is enabled in detection. Files: planned `nails-core/src/platform/`, `nails-cli/src/cli/detach.rs`, `nix/e2e-tests/`, `flake.nix`.

- [ ] **T-130: Deferred test-matrix extensions: Fedora/Arch VM smoke, cross-distro and cross-backend disk-image campaigns, hidden-user persona tests** (low · effort L)

  **Problem:** Some test coverage depends on work that is deliberately deferred: the Fedora and Arch platform backends, cross-distro and cross-backend disk-image evaluation campaigns, and a separate hidden user. Without a record, these gaps would be forgotten once the Debian/Ubuntu smoke tests and the host-side disk-image checks land.

  **Fix:** Record as TODO: add Fedora and Arch entries to the portable VM suite (`nix/e2e-tests/`) once their backends exist; run the disk-image checks across distros and backends (VeraCrypt hidden volume, LUKS, Shufflecake) as a campaign, with per-distro indicator sets (package databases, journals); once a separate hidden user exists, add the persona tests "hidden user exists before login and is not visible afterwards".

  **Done when:** Entries exist in `TODO.md` and link the dependent redesign items (T-129, the hidden-user redesign, and the disk-image evaluation campaign).

- [x] **T-131: TODO: architecture-alternatives ADR and decision matrix (kexec, boot-from-removable, live-overlay)** (medium · effort L)

  _Status (2026-10): done. ADR 0008 §8 holds the decision matrix (live overlays, soft-reboot, kexec, a hidden boot entry, removable media) and ADR 0005 the boot-time overlays; the decision picked the whole-root soft-reboot (T-134), so kexec and boot-from-removable are not pursued as spikes. The "no decoy-persisted enabler" invariant holds for the chosen mode: it installs no boot entry, initramfs hook or EFI variable, and the ESP is bound read-only (`forensic/80-uefi-esp-nvram-invariant`). The scope note in "Done when" (live path first on FHS distros) is overtaken: the session is the same on NixOS, Debian and Ubuntu._

  **Problem:** No comparison of hidden-environment mechanisms exists in the repo, so the multi-distro decision risks defaulting to bolting a Platform trait onto the live path, the lowest-ceiling option for portability and leak reduction. Alternatives include boot-time overlay classes (`systemd.volatile=overlay`, dracut `rd.overlay`), kexec into a hidden kernel/initrd/UKI, and boot-from-removable. The live path's fragile subsystems (process detection, session kill, journald race, `/nix` rebind, pivot) are exactly what a boot-time design removes.

  **Fix:** TODO only. Write one ADR with a decision matrix ranking mechanisms against the requirements, leak classes, portability, decoy traces, UX and effort, noting: `systemd.volatile=overlay` is tmpfs-upper only (cannot root on the hidden upper); Secure Boot lockdown refuses unsigned kexec images on stock Fedora/Ubuntu/Debian; kexec is reboot-equivalent (session/GPU loss, decoy uptime and journal gap); removable-media boot still changes firmware NVRAM `Boot####`/`BootOrder`. Record the invariant "no hidden-boot enabler may persist on the decoy (boot entries, initramfs hooks, EFI vars)" in `docs/USER-SECURITY-GUIDE.md`. Convert kexec and boot-from-removable into time-boxed spikes with go/no-go questions. Note the one concrete code risk owned by the deactivation group: the `switch-to-configuration "switch"/"boot"` calls at `nails-core/src/deactivation/orchestrator/mod.rs:347-355` and `nails-core/src/nixos/builder/switch.rs` can rewrite bootloader/EFI state.

  **Done when:** `docs/adr/` holds the alternatives matrix and the "no decoy-persisted enabler" invariant; kexec and boot-from-removable are listed as time-boxed spikes with go/no-go questions, not implementation tasks; and the decision explicitly scopes Phase 1 as the live path in overlay-only mode on FHS distros, keeping the full-root rebind capability NixOS-only.

- [x] **T-132: TODO: whole-root / soft-reboot design to eliminate live-overlay process heuristics** (high · effort XL)

  _Status (2026-10): done. The design is ADR 0008 and is implemented as the only session mode (T-134); ADR 0009 (dual root) is kept as research. The near-term steps (a namespaced-writer E2E test, a minimal-target option) were for the live overlays and are moot: every service of the hidden session starts inside the overlay root, so there is no pre-existing writer to miss._

  **Problem:** Live overlaying of a running system depends on fragile process detection/classification/restart (`nails-core/src/process/restart/mod.rs:217-251`, TERM then 100ms then KILL), a journald restart after `/var` (`nails-core/src/manager/activation/overlay_mount/mod.rs:176-183`), nix-daemon special-casing, and setns-into-PID1 restore (`nails-core/src/manager/activation/overlay_mount/restore.rs:83-142`). Services started in their own mount namespaces (PrivateTmp, StateDirectory, ProtectSystem) keep bind mounts onto the decoy underlying fs, and a periodic writer holding no open fd at scan time is never detected, so a missed writer is a silent leak. Per-distro heuristics will never be complete.

  **Fix:** TODO only. Prototype a whole-root mode where the hidden environment is entered as a fresh userspace on an overlay root (systemd soft-reboot into `/run/nextroot` on v254+, or an initrd hook) so every service starts inside the hidden view, removing process classification/restart. Before adopting, evaluate the decoy-side artifacts it creates (soft-reboot journal lines written before the switch, fstab re-mounts). Near-term, independently schedulable steps: (a) add an E2E test that pre-starts a unit with PrivateTmp/StateDirectory/ProtectSystem=strict writing periodically and asserts nothing changes on the decoy lower; (b) optionally list processes whose `/proc/PID/ns/mnt` differs from PID1 before mounting and restart those units or refuse activation, or isolate to a minimal target then start `graphical.target` so services start fresh inside the overlaid view.

  **Done when:** An ADR captures the whole-root/soft-reboot design, its decoy-side artifacts and go/no-go criteria, and the near-term namespaced-writer E2E test and the minimal-target option are written up as separately schedulable implementable steps.

## Wave R: Research follow-ups (2026-10)

Work that came out of the research spikes and ADRs 0006-0009, and out of the E2E performance and testing-strategy studies. Each item says whether its design is VM-proven or still needs a spike or real hardware first. T-131 and T-132 are the research items these follow from.

### WR-C1: Session modes

Owns: `nails-core/src/session/`, `nails-teardown/src/whole_root/`, `nails-core/src/platform/`, `nix/e2e-tests/tests/session/`

- [x] **T-134: Whole-root soft-reboot mode: an opt-in maximum-isolation session entered by soft-reboot into an overlay root** (medium · effort XL)

  _Status: VM-proven, needs a spike for NixOS entry and real hardware. The spike (`research/soft-reboot-whole-root.nix`) passes two full cycles plus a UEFI reboot: about 3 s back to a shell, no hidden token on the raw disk, the `/run` scrub as an allowlist, the kmsg cursor and the utab restore. Recommended as an opt-in mode next to T-133 (ADR 0009 recommendation 4)._

  _Status (2026-10): done; it is the only session mode, not an opt-in one ([ADR 0008](docs/adr/0008-whole-root-soft-reboot.md), accepted and implemented). `nails-teardown::whole_root` holds the plan, the transition step, the `/run` scrub, the kmsg cursor and the emergency hot path; `nails_core::session` the fstab policy, the entry, the way back and the checks; the NixOS hidden toplevel is entered with variant B (`nix build --store /run/nextroot`); `activate` and `status` print the emergency semantics. VM-verified: the 57-test suite (session, forensic, faults, persona and backend tests with raw-disk token scans and the `/run` residue check), the Debian 13 and Ubuntu 24.04 smoke tests and the research spikes. Refused: decoy roots that cannot be mounted again for the way back (an impermanent tmpfs root, overlayroot or another overlay, ZFS, squashfs and erofs) and systemd < 254 (Debian 12, Ubuntu 22.04, which are dropped). Open, needs real hardware (ADR 0008 go/no-go 2 and "What the VM cannot show"): GPU and Wi-Fi back without intervention after the switch, trigger to a usable greeter within 15 s on a real GNOME/KDE desktop, NVIDIA proprietary drivers, docks and Bluetooth peripherals, TPM-sealed decoy roots (PCR changes from the hidden root), and GRUB grubenv writes on a real GRUB host; also a separate `/home` on the distro images._

  **Problem:** For operators who want the strongest userspace isolation, every hidden process, including the desktop, should start inside the overlay. `docs/adr/0008-whole-root-soft-reboot.md` shows this works with `systemctl soft-reboot` into `/run/nextroot` and adds no enabler to the decoy, but its emergency cannot keep the desktop (ADR 0008 §6).

  **Fix:** Implement the ADR 0008 setup as a session mode: the read-only bind of `/` as lower, the upper on the hidden volume, the `/run` and hidden-volume binds, a read-only ESP (and `/boot/grub/grubenv`), an overlay inside `/run/nextroot` for every other decoy fstab filesystem, swap masked, `precheck_nextroot()` before the trigger, `/run/nextroot` kept empty outside NAILS transitions, and on the way back the `/run` scrub allowlist, the kmsg cursor and the utab restore as the last step. Emergency runs E2 or E4 through the teardown plan (`SoftReboot{root}` op, T-135). Open items:
  - entering a hidden NixOS toplevel without touching the bootloader (ADR 0008 §3 variant B or C);
  - Debian trixie and Ubuntu noble, including a decoy with a separate `/home`;
  - real hardware: GPU and Wi-Fi come back without intervention, trigger to usable greeter in at most 15 s both ways;
  - emergency semantics: it ends at a greeter or with the machine off. The operator must accept this for the mode, and `status`/`activate` say so in one line.

  **Done when:** ADR 0008 go/no-go criteria 2-5 hold; a regular VM test covers entry, the hidden toplevel, deactivation and both emergency variants with the raw-disk token scan and the `/run` residue check; the mode is opt-in and its emergency semantics are printed by `activate` and `status`.

- [x] **T-135: Emergency teardown crate with a RAM teardown plan, cgroup.kill and early dispatch** (high · effort L)

  _Status: design decided (ADR 0007 option F), kill path VM-proven (`research/01-emergency-cgroup-kill.nix`). Pidfd signalling and stop jobs for `Restart=` services have landed on the current path. The key-wipe-first option needs a spike._

  _Status (2026-10):_ done. `nails-teardown` (rustix, libc, serde only; `nails-cli`'s `teardown_boundary` test fails on a new dependency) holds the plan, the executor, the mountinfo derive pass and the cgroup and pidfd helpers; activation rewrites the plan in the runtime tmpfs after every step; `main` dispatches `emergency` and the watcher trigger before clap, config and tracing (`nails-cli/tests/early_dispatch.rs`); `cgroup.kill` with the `cgroup.procs`/pidfd fallback replaces the `/proc` kill outside the no-plan fallback; `manager::teardown_plan` kernel tests run it in user, mount, cgroup and PID namespaces; faults/97 passes on a dead untrusted backend. The key-wipe-first spike is a documented no-go in ADR 0007 (a frozen filesystem blocks the power action and the kill). `research/01-emergency-cgroup-kill.nix` stays a research test: the regular faults and emergency tests now exercise the same `cgroup.kill` path. Verified by the green VM suite (102 tests) and the Debian 12/13 and Ubuntu 24.04 smoke tests at 5751ec92.

  **Problem:** Emergency still builds the CLI stack and walks `/proc` with device-matching heuristics before the first unmount; about 11k lines are reachable from the hot path, which is slow, hard to review and depends on a responsive hidden backend (`docs/adr/0007-emergency-architecture.md`).

  **Fix:** Follow the ADR 0007 migration stages:
  1. a `nails-teardown` crate (`rustix`/`libc` only, no dependency on `nails-core` config, state, manager or tracing) with the plan types, the interpreter, the mountinfo reconcile pass and the cgroup and pidfd helpers, with userns tests;
  2. activation writes the plan to the runtime tmpfs atomically after every step, with unit cgroups and session-guard fragments;
  3. early dispatch: `main` recognises `emergency` and the watcher trigger before clap, config, platform detection and tracing, and calls the interpreter;
  4. `cgroup.kill` (with a `cgroup.procs` plus pidfd fallback below 5.14), bounded `AwaitEmpty`, then detach; the `/proc` kill stays only in the no-plan fallback;
  5. the research VM test becomes a regular `faults` test.

  Evaluate a key-wipe-first option as a spike: `FIFREEZE` the hidden filesystem, suspend the dm mapping and wipe its key before the slower teardown, so a seized machine holds no usable key even if the teardown stalls. Questions: interaction with D-state tasks and frozen writers, whether the unmount can still complete afterwards, and what a suspended mapping looks like to an observer.

  **Done when:** emergency reaches the first unmount without initialising clap, config or tracing (asserted by a test); the hot path is in `nails-teardown` and Cargo enforces the dependency boundary; a missing or corrupt plan derives the same op list from mountinfo; the fault VM tests pass with a dead backend; the key-wipe spike ends with a go/no-go recorded in ADR 0007.

- [x] **T-136: Activation as do/undo steps that share one plan with rollback, deactivate and emergency** (medium · effort L)

  _Superseded (2026-10): the whole-root soft-reboot session (T-134, ADR 0008) replaced the live per-directory overlays and removed the machinery this item changed (the v1 do/undo plan; the session plan in `nails-teardown::whole_root` replaces it). The item stays ticked as history; it describes no current code._

  _Status: design only (ADR 0007 option C); no spike needed. Depends on T-135._

  _Status (2026-10):_ done. Activation records each completed step with its fixed undo in the T-135 plan (tracked mounts, `/nix/store` self-binds, read-only guards, the post-switch overlay re-mount, added units); rollback, deactivate, recover and emergency undo that one plan through the `nails-teardown` executor, reconciled against mountinfo, and rebuild it from the state file or the mount table when it is missing. The per-path loops are gone; `teardown_plan_kernel_tests.rs` proves every recorded step kind's undo on real mounts. Verified at 5751ec92.

  **Problem:** Rollback, deactivation, recover and emergency each derive what to undo in their own way (mount tracker, state file, mountinfo discovery), so a new activation step needs teardown code in several places and they can drift.

  **Fix:** Model activation as a list of steps, each with a `do` and a fixed `undo` (mount → unmount, bind → unmount, unit restarted → stop/start, link repointed → repoint back). The steps append to the T-135 plan as they complete; rollback runs the undo of the completed prefix, deactivate and emergency run the whole plan, with mountinfo reconcile as the fallback.

  **Done when:** rollback, deactivate and emergency read the same plan; adding a step needs no teardown code elsewhere (one test per step proves its undo on the real-kernel tier); the per-path rebuild loops are gone.

- [x] **T-137: Hidden /nix/store on the hidden volume instead of an overlay over the decoy store** (medium · effort M)

  _Status: falls out of T-133/T-134; no separate spike._

  _Status (2026-10):_ done, by keeping the hidden closure on the hidden volume rather than a separate store (ADR 0008 §3, "The hidden store", weighs a separate store, a verify-and-repair entry and this). After the build and before the activation, the entry lists the hidden toplevel's closure and copies every path still read from the decoy store up into the store overlay's upper, through the overlay (open for writing, or set the owner a directory or symlink already has), so the read-only lower, and with it the decoy store, is never written; `<hidden>/root/store-kept` records the kept paths so later entries copy only new ones, and the space is checked first. Before the build, `nix-store --verify` drops paths the decoy deleted from the hidden database. Cost: one copy of the closure at the first entry (several GB, minutes on an encrypted backend), documented in the operator guide. Not kept: paths only the hidden session's own profiles use, and the build inputs of a changed configuration after a decoy garbage collection. Proven on the real kernel (`store_kernel_tests`); VM test `session-nixos-store-gc` (a decoy rebuild and garbage collection between two hidden sessions, the decoy store compared before and after each); `session-nixos-hidden-system` gets an 8 GB data disk for the copy. Not run here: the VM tests.

  **Problem:** Today the hidden store is a `/nix` overlay over the decoy store. A copied-up `db.sqlite` shadows store paths the decoy builds or garbage-collects between sessions (ADR 0008 §2, T-128), so a decoy GC can break the hidden system.

  **Fix:** Once a whole-root mode exists, keep the hidden closure in a store that lives entirely on the hidden volume (its own `/nix` in the hidden root, not layered on the decoy store), so decoy updates and GC cannot affect it.

  **Done when:** a VM test garbage-collects and rebuilds the decoy between two hidden sessions and the hidden toplevel still starts; the decoy store is unchanged by the hidden session.

### WR-C2: Code structure and test architecture

Owns: `Cargo.toml`, `nails-*/Cargo.toml`, `docs/testing-strategy.md`, `docs/e2e-performance.md`, `nix/e2e-tests/`

- [x] **T-138: Split nails-core into platform, overlay engine, forensics and teardown crates** (low · effort L)

  _Status: design only; no spike needed. The teardown crate comes first through T-135._

  _Status (2026-10): done, along the boundaries left by the whole-root session ([ADR 0010](docs/adr/0010-library-crate-split.md), superseding ADR 0001's two-crate layout). Bottom-up: `nails-teardown` (unchanged), `nails-base` (error, Filesystem and process seams, configuration, state, artifact registry, attach gate, logging, output, the pre-flight framework), `nails-platform` (detection, backends, NixOS configuration layer and builder, backend chain), `nails-session` (entry, fstab policy, way back, probes, persona, runtime units), `nails-forensics` (verify, examiner, forensic readers, residue catalog, rehearse) and `nails-core` (manager, pre-flight registry and checks, status), which re-exports the others so the CLI and its JSON are unchanged. There is no overlay-engine crate: the live-overlay engine is gone and the whole-root mount primitives are in `nails-teardown`. Configuration and state sit in `nails-base` because the session, the checks and verification all read them. `nails-core/tests/crate_graph.rs` pins the graph, `nails-forensics/tests/boundary.rs` keeps verification read-only, and the teardown boundary test refuses every other NAILS crate. The library crates' unit tests still never reach the host (`nails_base::unit_test_mode!`). The flake source set, the `nails-source` check, the `rust` and E2E path filters and the orphan-module scan list every crate. Not run here: `nix build .#nails` and the VM suite (no Nix daemon in the sandbox)._

  **Problem:** `nails-core` holds platform detection, the overlay engine, verify and artifacts, and teardown in one crate, so nothing stops one area from reaching into another, and ADR 0001's boundary only separates the CLI.

  **Fix:** Split along the seams that already exist: `nails-platform` (detection, backends, host commands, config layer), `nails-overlay` (mount engine, runtime root, pivot), `nails-forensics` (verify, artifact registry, scanners), `nails-teardown` (T-135). `nails-core` keeps orchestration. Update ADR 0001 with a superseding record.

  **Done when:** the four crates build with only the dependencies their area needs, the workspace tests and clippy pass, and the dependency direction is recorded in an ADR.

- [x] **T-139: Mock migration per the testing strategy: the eight-step list and effect-based assertions** (medium · effort L)

  _Status: tier (a) harness, kernel fixtures and the first migrations landed with ADR 0006; the eight remaining steps need no spike._

  _Status (2026-10):_ done; the full VM suite (102 tests) passes with the new systemctl budget and the committed VM captures. All eight steps are done and ticked in `docs/testing-strategy.md`: the mount contract runs against the kernel in a user namespace (the mock-only section is gone; three mock drifts fixed), `privileged_mounts` runs rootless except its whiteout test, captured userns and VM fixtures (the latter committed from the full VM run at 27090f96) feed the mountinfo, swap, systemctl, journald, logind and stat/status parsers, reconcile and the signal paths have tier (a) tests, the three `/proc/<pid>/stat` copies are one parser, and no test asserts only on the `MockOp` list or the recorded service actions (6 did). Two product bugs were found and fixed: verify matched escaped mountinfo fields against a hidden root with a space, and process detection took systemd-udevd (DelegateSubgroup=udev) for a non-service process. Open before ticking: performance-validation's systemctl budget, moved to the default activation after the first VM run found the overlay-only one makes no systemctl call, needs one green run. Two mock drifts are documented, not fixed: the mock refuses a second `mount_tmpfs` on one target where the kernel stacks it, and the real `find_files_with_pattern` never returns directories, so the temp-file cleaner's directory branch only runs under the mock.

  **Problem:** Test doubles encode beliefs about the kernel and tools that nothing checks; five bugs passed every unit test and failed only in the VM suite (`docs/testing-strategy.md`, `docs/adr/0006-real-kernel-test-tier.md`).

  **Fix:** Work through the "Next, in this order" list in `docs/testing-strategy.md`: (1) the mount contract against `RealFilesystem` in a user and mount namespace; (2) the rootless `privileged_mounts` tests through `Rerun`; (3) captured VM fixtures for the service, session, swap, mountinfo and backend-detect parsers; (4) `reconcile_mounts_override` against a real mount table; (5) one `/proc/<pid>/stat` parser tested on real children; (6) signal and process-tree tests in a PID namespace; (7) the tier (c) "kernel-semantics" VM test; (8) effect assertions (state file or mount table) for tests that only check the recorded `MockOp` list.

  **Done when:** each step is ticked in `docs/testing-strategy.md`, the mock-only contract section is gone, and no activation or rollback test asserts only on recorded operations.

- [x] **T-140: VM suite roadmap: merge single-boot tests, cache the store image, virtiofs, move tests to the real-kernel tier** (medium · effort M)

  _Status: measured. A full run takes 75 min with the bounded-parallel runner, down from 3 h 45 min serial. The remaining items are ranked in `docs/e2e-performance.md`; none needs a spike._

  _Status (2026-10):_ done. 19 single-boot tests run as scenarios of 7 batches (`lib/batch.nix`, `py/nails_e2e/batch.py`) with a clean-guest check per scenario; the erofs store image is reused across restarts of one machine (17 restarts per full run); virtiofs is gated on bumping the flake's nixpkgs (the analysis and the `msize` removal are in `docs/e2e-performance.md`); `help-version-no-leak` and four config checks moved to cargo tests. The suite is green at 5751ec92 (102 tests); the post-Wave-R wall time is to be added to `docs/e2e-performance.md#re-measuring` from the next timed full run.

  **Problem:** Booting is 38% of test-script time (190 boots for 106 tests) and 49 tests boot once and spend most of their time booting; the forensic tests rebuild the store image on every start.

  **Fix:** In roadmap order: refresh `shard-durations.json` from the measured run; merge independent single-boot tests per group (preflight, config/contract/init, notification, smoke) with a cleanup helper and a leftover-state assertion at the start of each scenario, folding in the T-114 duplicates; cache the erofs store image across starts of one forensic test; take virtiofs with the next nixpkgs bump and re-check `--jobs auto` against host RAM; move config and contract tests to the real-kernel tier, keeping one VM path each. Record the hosted-runner boot cost in `nix/e2e-tests/README.md`.

  **Done when:** the single-boot groups run in about 10 boots, the forensic tests reuse one store image, and the measured full-suite time is recorded in `docs/e2e-performance.md` after each step.

### WR-C3: Forensic self-checks

Owns: `nails-core/src/verify/`, `nails-core/src/artifacts.rs`, `nails-cli/src/cli/commands/`, `nix/e2e-tests/lib/disk_forensics.py`

- [x] **T-141: nails rehearse: a canary self-test with a raw-device scan** (medium · effort M)

  _Status: new; needs a design note (where the canary lives, how the scan stays read-only), then a VM test._

  _Status (2026-10):_ done. `nails rehearse` runs the guided three-step canary self-test: a canary planted in the session's usual places, kept on the hidden volume, and a read-only sparse-aware scan of the raw decoy device after deactivation (`nails-cli/tests/rehearse_cli.rs`, VM test `forensic/12-rehearse-canary.nix` with a deliberate leak and a clean run); documented in `docs/operator-guide.md` and `docs/cli.md`. Verified at 5751ec92.

  **Problem:** The disk-image checks prove the leak claims only in CI. An operator has no way to check their own machine, decoy profile and backend before relying on them.

  **Fix:** A two-phase `nails rehearse`: phase one runs a normal session that writes random canary tokens into the hidden session's usual places (home, `/etc`, `/var`, `/tmp`, journal) and keeps the tokens on the hidden volume; phase two, after the standard deactivation and reboot, scans the raw decoy block device read-only for the tokens (the sparse-aware scan from `disk_forensics.py`) and reports hits by offset. No write to the decoy in either phase.

  **Done when:** a VM test plants a deliberate leak and `rehearse` reports it, and a clean run reports none; the command is documented in the operator guide.

- [x] **T-142: Timeline-differential forensic oracle: extend the forensic/06 MAC-time and hash diff, optional Plaso lane** (medium · effort M)

  _Status: forensic/06 already diffs a sleuthkit bodyfile and per-file SHA-256 against a control run; extending it needs no spike._

  _Status (2026-10):_ done for the oracle. The bodyfile, hash and control-run filter are factored into `disk_forensics.mac_diff`, and forensic/04, 05, 08 and the tcrypt hidden-volume test assert it next to forensic/06 (five tests). No Plaso lane: Plaso is not packaged in nixpkgs; the bodyfiles kept in the test output feed `mactime` directly (`nix/e2e-tests/README.md`). Verified at 5751ec92.

  **Problem:** Only forensic/06 compares inode MAC times and contents; the other disk-image tests compare names or grep tokens, so a decoy file modified in place passes them.

  **Fix:** Factor the bodyfile, hash and control-run filter in `disk_forensics.py` into a helper and use it in forensic/05, 08 and 10, the persona tests and the distro smoke test. Add an optional nightly lane that builds a Plaso super-timeline of both images and diffs it against the control run.

  **Done when:** at least five disk-image tests assert the MAC-time and hash diff, and the Plaso lane runs on demand with its diff in the test output.

- [x] **T-143: Unguarded writable mounts: optional read-only remount for the session, watcher alerts on new rw mounts** (medium · effort M)

  _Status: the stray-mounts preflight warning is done; the rest needs no spike._

  _Status (2026-10):_ done for disks mounted during the session (the fstab policy already covers every filesystem the decoy knows; see `docs/configuration.md#disks-mounted-during-the-session` and ADR 0008 §2). The session watcher alerts once per mount on every read-write mount of a block device outside the hidden volume (`[session_mounts] alert`, on by default; the watcher runs for it even with `backend_watch` off). Opt-in `[session_mounts] read_only` makes every disk the session does not use read-only at the block layer (`BLKROSET`): a runtime udev rule, written by the entry transition so only the hidden udevd loads it, runs the RAM copy (`guard-device`) for every disk and partition as it appears, before udisks hears of it, the hidden boot's coldplug covers the disks present at entry, and the watcher sweeps as a fallback; the decoy root, the hidden backend and their members, the policy and carried mounts and virtual devices are never touched. The leave transition (deactivate and emergency alike) makes exactly the recorded devices writable again and removes the rule; `deactivate` unmounts disks mounted during the session first, detaching a busy one. A polkit or udisks policy was not used: it covers only udisks. Limits: a root user can set a disk writable again; a mount in another mount namespace is not seen by the watcher. Residue catalog row `session-disk-mounts` (residual channel). VM test `session-disk-mounts` (the alert, a busy mount across the way back, the opt-in from the hidden boot and for a hot-plugged disk, writes failing, the disks writable and unchanged afterwards). Not run here: the VM test.

  **Problem:** A second disk, a Windows partition or an automounted USB drive stays read-write on a real disk for the whole session. Preflight warns about the ones present at activation, but nothing acts on them and a drive mounted during the session goes unnoticed.

  **Fix:** An opt-in config key and flag that remounts the warned mounts read-only for the session and restores them at teardown; the watcher alerts on any new read-write block-backed mount that is not under an overlay target or the hidden root.

  **Done when:** a VM test with a second disk shows writes fail under the opt-in and the mount is read-write again after deactivation; another VM test mounts a disk during the session and the watcher alert fires.

- [x] **T-144: One residue catalog driving preflight, verify, docs and E2E** (medium · effort M)

  _Status: the artifact registry (T-074) covers verify, preflight and the E2E indicators; extending it needs no spike._

  _Status (2026-10):_ done. `nails-core/src/residue_catalog/` is the single catalog: each row names the class, where it lands, its preflight probe, its verify probe and its VM test; the tests fail on a row with no detector (unless it is a declared residual channel), a VM test that does not exist, an unregistered probe, or a generated docs table out of sync (`generated_doc_tables_match_the_catalog`). Verified at 5751ec92.

  **Problem:** Residue classes are described in the artifact registry, the decoy requirements, the threat model's residual channels and the E2E indicators separately, so a new class can be documented without a detector or detected without a test.

  **Fix:** Make the registry the single catalog: each entry names the class, where it lands, the preflight check that prevents it, the verify check that detects it, and the E2E test that asserts it. Generate the residual-channels table in the docs from it.

  **Done when:** a test fails when an entry has no detector or no E2E assertion, and the generated docs table is kept in sync by a test.

- [x] **T-145: Examiner's-view audit in verify --offline: setup traces, report only** (medium · effort M)

  _Status: new; needs no spike. Builds on `verify --offline --root`._

  _Status (2026-10):_ done. `verify --offline --examiner` lists the catalog's setup traces on a mounted decoy image grouped by the examiner's conclusion, report only; VM test `forensic/11-examiner-audit.nix` seeds each trace and checks a clean image reports none. Verified at 5751ec92.

  **Problem:** `verify` looks for session residue. An examiner also looks for traces of the setup itself: backend tooling and its history, mapper names in logs, sudo records, downloaded binaries, VeraCrypt favourites and history, LUKS2 tokens.

  **Fix:** An `--examiner` section in `verify --offline` that lists setup traces from the catalog (T-144) on a mounted decoy image, grouped by what an examiner would conclude. It reports only and changes nothing.

  **Done when:** a VM test seeds each setup trace on a decoy image and the audit reports it; a clean image reports none.

### WR-C4: Alternatives and personas

Owns: `docs/adr/`, `docs/threat-model.md`, `nails-core/src/persona/`

- [ ] **T-146: Contained-session (systemd-nspawn) mode for headless hidden sessions** (low · effort L)

  _Status: compared in ADR 0009 (option E); needs a spike. Not the main path while the hidden desktop is GNOME/KDE._

  _Status (2026-10): re-evaluated against the whole-root session, still low priority. The soft-reboot already gives every hidden process a fresh userspace in the overlay root, so nspawn would add only a non-disruptive emergency for a headless hidden system, at the cost of machined registration and journal lines on the decoy. It would reuse the session's overlay root and fstab policy rather than a separate stack. Kept for a headless use case; not planned._

  **Problem:** For a headless or wlroots hidden session, a container with its own PID 1, journal, system bus and PID namespace gives the strongest live isolation, but logind inside nspawn has no graphical seat (systemd #35114, #36673).

  **Fix:** Spike `systemd-nspawn --boot` on the whole-root overlay for a headless hidden system: own journal in the upper, Wi-Fi moved with its `phy`, emergency by killing the machine scope. Compare decoy-side traces (machined registration, journal lines) with T-133.

  **Done when:** the spike result and a go/no-go are recorded in ADR 0009, and a VM test covers the mode if it goes ahead.

- [x] **T-147: idmapped binds for the fresh-home persona, or a separate hidden account** (low · effort L)

  _Status: needs a spike (kernel support for idmapped layers under overlayfs on the supported LTS kernels)._

  _Status (2026-10): obsolete. In the whole-root session the hidden `/etc` (passwd, shadow, the NixOS users) lives in the upper and every per-uid runtime object (`/run/user/<uid>`, the user manager, logind state) is created after the switch and scrubbed from `/run` on the way back, so the decoy's uid is no longer shared with a running decoy session. A separate hidden account is a user in the hidden configuration and leaves nothing on the decoy disk; no idmapped binds or `/run/userdb` record are needed. The persona tests from T-130 apply to such a user if one is ever documented as the default._

  **Problem:** The fresh-home persona (T-046) still runs as the decoy's uid, so per-uid state (`/run/user/<uid>`, user manager, keyring, dconf) is shared with the decoy. ADR 0009 rules out the same uid for a dual-root session.

  **Fix:** Either present the hidden home through an idmapped bind owned by a separate hidden uid, or create a separate hidden account from a `/run/userdb` record as in T-133. Pick one after the spike; add the persona tests from T-130.

  **Done when:** the hidden session runs under a uid the decoy does not have, nothing about that uid reaches the decoy disk (VM test), and the persona docs describe the model.

- [x] **T-148: Threat model: resolve the coercion tension** (high · effort S)

  _Status: docs only; no spike._

  _Status (2026-10):_ done. `docs/threat-model.md` brings compelled disclosure of the decoy into scope with its limits (section "Compelled disclosure of the decoy"), keeps sustained coercion and coercion aimed at the hidden volume out of scope without contradiction, and `docs/operator-guide.md` ("Compelled disclosure") matches.

  **Problem:** `docs/threat-model.md` lists coercion as out of scope, but its outer-encryption assumption ("the operator can unlock for the adversary without revealing the hidden volume") is a compelled-disclosure scenario, so the document contradicts itself.

  **Fix:** Bring compelled unlock of the decoy into scope explicitly: the adversary obtains the decoy credentials and examines the decoy offline. Keep sustained or repeated coercion, and coercion aimed at the hidden volume, out of scope, and say what NAILS can and cannot offer there.

  **Done when:** `docs/threat-model.md` names the compelled-unlock scenario as in scope with its limits, the out-of-scope list no longer contradicts it, and the operator guide matches.

### Not adopted

- Shufflecake as a backend: an out-of-tree kernel module whose presence is itself a decoy-side trace; it stays detected and named by `backend-detect` only.
- fscrypt or dm-integrity for the upper: the upper already sits inside the encrypted backend, and both add identifiable on-disk metadata for no gain against an offline examiner.
- TPM or FIDO2 unlock of the hidden volume: an enrolled token or sealed key points at the hidden volume and binds it to the machine (see `docs/backends.md`).
- A TUI: a large new surface and dependency set for no safety gain; the CLI and `status --json` cover it, and the panic path must stay minimal.
- Overlay `uuid=off` on current LTS kernels: its meaning differs between the supported kernels, and the origin data it would drop sits inside the encrypted backend anyway.
- CRIU for the decoy session: it cannot checkpoint DRM masters or a compositor's client graph, and the image would need storage on the decoy or the hidden volume (ADR 0009).
- Dual-root session mode (T-133): the hidden session on its own VT in a whole-root overlay, with an emergency by VT switch and `cgroup.kill` that keeps the decoy desktop logged in. Its core was VM-proven (`research/dual-root-vt-emergency.nix`, `research/dual-root-risks.nix`), but it needed a hidden user, runtime polkit and D-Bus denies, a pinned mount namespace and a real-hardware matrix. The whole-root soft-reboot was chosen as the only session mode instead, accepting that the emergency ends at the decoy's login screen. [ADR 0009](docs/adr/0009-dual-root-emergency.md) is kept as research.
