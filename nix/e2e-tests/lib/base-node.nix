# Shared base node for E2E specs.
#
# Most specs boot one machine that is nothing more than the standard decoy VM
# (`vm-config.nix`) with the nails binary installed, and about a quarter of them
# only add `python3` so an in-guest heredoc can run. Spelling that `nodes.machine`
# block out in every file duplicates the same two or three lines dozens of times
# and hides the handful of specs that genuinely need a bespoke node.
#
# `default.nix` applies this node to any spec that declares no `nodes` of its own,
# so such a spec can drop the boilerplate entirely. A spec that needs python3 in
# the guest (or extra packages) sets a top-level `baseNode` attribute instead of a
# full `nodes` block, for example:
#
#   baseNode = { python3 = true; };
#
# A spec with bespoke hardware, a second machine or a non-default VM config keeps
# declaring `nodes` explicitly; this helper deliberately covers only the common
# single-machine case and never installs zsh, fish or notification tools, because
# absence tests (for example notify-no-notify-send) depend on those being missing.
{ self, pkgs }:
let
  mkNode =
    {
      python3 ? false,
      extraPackages ? [ ],
    }:
    { ... }:
    {
      imports = [ ./vm-config.nix ];
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.nails
      ]
      ++ pkgs.lib.optional python3 pkgs.python3
      ++ extraPackages;
    };
in
{
  inherit mkNode;

  # The default single-machine node: vm-config + the nails binary.
  node = mkNode { };

  # The same node with python3 available in the guest.
  pythonNode = mkNode { python3 = true; };
}
