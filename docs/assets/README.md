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
| `check.svg` | `nails check` in the `session-lifecycle` NixOS VM test |
| `activate.svg` | `nails activate` in the `session-lifecycle` NixOS VM test (standard-error log lines left out) |
| `status-json.svg` | `nails status --json` in the hidden session, `session-lifecycle` NixOS VM test |

To refresh one, replace the output below the `---` line of its capture with a
new real capture, update the header, then render:

```bash
scripts/render-terminal-svg.py --all docs/assets/screenshots          # rewrite every SVG
scripts/render-terminal-svg.py --all docs/assets/screenshots --check  # fail if one is stale
```

The VM captures come from the test's build log: run
`nix build -L .#e2e.session-lifecycle` and copy the command's output from the log
(the test prints the `check` output, the activation log and the status JSON).
