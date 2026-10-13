# Captured forensic tool output

These files are real output from the host-side forensic tools, captured once and
committed so `lib/tests/test_disk_forensics.py` can exercise the parsers in
`lib/disk_forensics.py` in the fast lane -- no VM, no root, seconds to run.

| File | Source |
|---|---|
| `fls-sample.txt` | `fls -r -p` over an ext4 partition, including deleted (`*`) and reallocated (`(realloc)`) entries. |
| `strings-sample.txt` | an excerpt of `strings -a` over a raw decoy image, with a planted canary. |
| `journal-sample.txt` | `journalctl --directory ... -o cat` over a recovered persistent journal, with a planted canary. |
| `bodyfile-sample.txt` | `fls -r -m /` (sleuthkit 4.14) over a small ext4 image made with `mke2fs -d`: a name holding `\|` and spaces, a symlink (` -> target`) deleted with `debugfs rm`, and the `$OrphanFiles` virtual directory. |
| `store.sqlite` | a minimal Nix store database with the real `ValidPaths` schema and three rows. |

Regenerate only when the tool output format itself changes; the canary tokens
are deliberately distinctive so a parser regression is obvious.
