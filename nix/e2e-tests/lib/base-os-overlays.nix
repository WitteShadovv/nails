# Base-OS overlay stanzas for explicit e2e configs.
#
# The writable-trees pre-flight check refuses activation when a base-OS tree
# that exists as a real directory (/usr, /bin, /sbin, /lib, /lib64) is neither
# overlaid nor kept read-only, because a hidden-session write there would reach
# the decoy disk. The NixOS test VMs keep no tree read-only and have /usr, /bin
# and /lib64 as real directories, so every explicit config that is meant to
# activate (or to fail pre-flight for a different reason) must overlay them.
#
# Interpolate `toml` on its own line inside a config heredoc; `tomlFor root`
# does the same for a hidden root other than /mnt/data (for example a Python
# f-string placeholder such as "{hidden_root}"). Tests that compare the mounted
# set against an exact list add `targets` (a Python list literal via
# `pythonTargets`) to the set they configure themselves.
let
  names = [
    "usr"
    "bin"
    "lib64"
  ];
  stanza = root: name: ''
    [[overlays]]
    name = "${name}"
    lower = "/${name}"
    upper = "${root}/${name}"
    work = "${root}/.work/${name}"
    target = "/${name}"
  '';
  tomlFor = root: builtins.concatStringsSep "\n" (map (stanza root) names);
  targets = map (name: "/${name}") names;
in
{
  inherit targets tomlFor;
  pythonTargets = builtins.toJSON targets;
  toml = tomlFor "/mnt/data";
}
