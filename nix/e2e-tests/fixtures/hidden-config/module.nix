# Hidden-configuration marker module shared by the real-rebuild and forensic
# E2E tests.
#
# It adds a few observable facts to the hidden NixOS system — a declarative /etc
# marker file, a single oneshot service, and a declarative canary user/group with
# a fixed id — so a test can prove the hidden configuration (not the decoy
# generation) was built and switched to, and can then check that the hidden
# user never leaked onto the persisted decoy state. The marker only exists in
# the hidden toplevel's /etc, the oneshot's /run stamp only appears once that
# toplevel is activated, and the canary's name and id must appear only while the
# hidden session is live — never in the decoy's persisted /var/lib/nixos,
# /etc/passwd, /etc/group or journal after deactivation.
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

  # A declarative canary user that exists only in the hidden configuration. Its
  # distinctive name and fixed id let a forensic check prove containment: after a
  # hidden session is deactivated, neither must survive on the persisted decoy
  # state. It is a system user with no shell, home or package so the hidden
  # toplevel's closure stays small and still builds offline.
  users.groups.hiddencanary.gid = 64123;
  users.users.hiddencanary = {
    isSystemUser = true;
    uid = 64123;
    group = "hiddencanary";
    description = "nails hidden-session canary";
  };
}
