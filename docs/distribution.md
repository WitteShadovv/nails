# Distribution channels

How NAILS reaches a machine decides what traces it leaves. A package manager
writes to the decoy disk, records the install in its database, and often keeps a
cached copy; a registry entry is a permanent public record that the tool exists.
The threat model treats any such trace on the decoy as a compromise (see
[Keeping NAILS off the decoy](operator-guide.md#keeping-nails-off-the-decoy)).
This page lists the channels that respect that and the ones that do not.

## Supported

- **Static release binary, verified off the decoy.** Download and verify the
  published bundle outside the decoy system (a live environment that keeps
  nothing, or a separate machine), following
  [Verify a release](verify-release.md), then copy the verified `nails` binary
  onto the mounted hidden root. This is the only first-install path, because it
  is the only one that can be checked without touching the decoy.
- **Source or Nix build from inside an active hidden session, for upgrades.**
  Once a hidden session is active, `cargo build` or `nix build` may be used to
  rebuild NAILS in place. Every build cache (`~/.cargo`, `/nix/store`, the
  `result` GC root) then lands on the hidden upper layer, not the decoy. Do not
  use this for a first install: before a session is active there is no hidden
  upper to catch the caches, so the build pollutes the decoy.

## Unsupported

None of these is offered, and none should be used, because each writes a lasting
indicator onto the decoy or into a public index:

- **crates.io.** Every workspace crate sets `publish = false`. A crate on a registry is a
  permanent, indexed record, and `cargo install` writes to the decoy's
  `~/.cargo`.
- **nixpkgs.** A nixpkgs package leaves `nails`-named `/nix/store` paths and is a
  public record in the package set.
- **`.deb` / `.rpm` packages.** A system package manager records the install in
  its database and caches the archive on the decoy disk.
- **Any decoy-side NixOS module or overlay.** NAILS exposes no `nixosModules`
  flake output. A module imported into a decoy's configuration would name the
  tool in the system's own configuration and store.

## Platform support

The channels above are independent of which host the tool then runs on. Which
hosts are supported, provisional or refused is listed once, in the
[README](../README.md#requirements).
