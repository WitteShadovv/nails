# Hidden-configuration marker module shared by the real-rebuild and forensic
# E2E tests.
#
# It adds exactly two observable facts to the hidden NixOS system — a declarative
# /etc marker file and a single oneshot service — so a test can prove the hidden
# configuration (not the decoy generation) was built and switched to: the marker
# only exists in the hidden toplevel's /etc, and the oneshot's /run stamp only
# appears once that toplevel is activated.
_: {
  # The decoy already builds its own documentation; the hidden system does not
  # need it, and dropping it keeps the extra closure the marker build pulls in
  # to a minimum.
  documentation.nixos.enable = false;

  environment.etc."nails-hidden-marker".text = "hidden-rebuild-active";

  systemd.services.nails-hidden-canary = {
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "/bin/sh -c 'echo hidden-oneshot-ran > /run/nails-hidden-oneshot'";
    };
  };
}
