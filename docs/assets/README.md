# Documentation assets

Images used by the README and the docs. Every file here is plain text (SVG or a
text capture) except `logo.png`, so changes show up in a diff.

## Logo and banner

| File | What it is |
|---|---|
| `logo.svg` | The NAILS mark: a nail through a snowflake, its lower part fading out. Follows the viewer's colour scheme. |
| `banner-light.svg`, `banner-dark.svg` | The README banner, for light and dark backgrounds. The README picks one with `<picture>` and `prefers-color-scheme`. |
| `logo.png` | The earlier raster version of the mark. The docs no longer use it. |

The SVGs are hand-written; edit them directly.

## Terminal screenshots

`screenshots/` holds terminal "screenshots" as SVG. Each `NAME.svg` is rendered
from `NAME.txt`, a capture of real NAILS output with a short header that says
which command produced it and where (a local build or a named NixOS VM test).
The renderer wraps long lines and colours the status markers; it changes nothing
else.

| Screenshot | Source |
|---|---|
| `help.svg` | `nails -h` from a local build |
| `check.svg` | `nails check` in the `session-readme-captures` NixOS VM test |
| `activate.svg` | `nails activate` in the `session-readme-captures` NixOS VM test, standard output and standard error together |
| `status-json.svg` | `nails status --json` in the hidden session, `session-readme-captures` NixOS VM test |

To refresh one, replace the output below the `---` line of its capture with a
new real capture, update the header, then render:

```bash
scripts/render-terminal-svg.py --all docs/assets/screenshots          # rewrite every SVG
scripts/render-terminal-svg.py --all docs/assets/screenshots --check  # fail if one is stale
```

The `--check` run compares each SVG with its capture only; it cannot tell
that a capture no longer matches what NAILS prints. Refresh all four for every
release, as [RELEASING.md](../../RELEASING.md) says.

The VM captures come from one run of the `session-readme-captures` test, cut
from its log. Each caption names that run and its date: the `nix build`
command for a local run, or the run's ID (the number in its URL,
`actions/runs/<ID>`) for a run of the E2E workflow on GitHub's hosted runners.
The test sets the VM up as
[decoy-requirements.md](../decoy-requirements.md) recommends for a clean decoy
and runs the binary from the hidden volume through `sudo`, as the README's quick
start does, so a capture shows no warning that only a test VM causes; the test
fails when `check` or `activate` prints a warning. It also gives the VM QEMU's
emulated Intel IOMMU, turned on with `intel_iommu=on`, which the
[operator guide](../operator-guide.md#cold-boot-and-running-memory-attacks)
advises and the decoy requirements do not ask for. That is why `dma-protection`
passes in the `check` capture, and its caption says so: with Linux 5.14 or
newer, that check warns on a machine whose IOMMU does not remap the DMA of
every device. Run
`nix build -L .#e2e.session-readme-captures` and copy the command's output from
the log (the test prints the `check` output, the activation log and the status
JSON). The test driver puts `machine: ` in front of the first line of the
`check` output and of the status JSON; that prefix belongs to the log, not to
the output. A test that is already built prints no log: `nix log` on the same
installable prints the stored one, and `nix build --rebuild` runs the test
again.

When a caption names a run of the E2E workflow (`e2e.yml`), that run was
dispatched in mode `execute` for this test, from a commit that also keeps and
uploads the log of a passing test, which the workflow otherwise deletes
(`run_drivers` in `ci/e2e/run.py` and the workflow's `Upload failure logs`
step). Neither file goes into nails or the test. GitHub keeps that log, the
run's `e2e-logs-shard-1` artifact, for 14 days, and the run's job logs, which
show that the test passed but not its output, for 90 days.
