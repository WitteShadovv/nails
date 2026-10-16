# A notification server on the operator's session bus, for the alert tests.
#
# NAILS shows its desktop alerts (the session watcher's, and the notification
# `rehearse plant` uses as a canary channel) on the operator's own session bus,
# as the operator. These tests stub nothing on that path: a user service of
# testuser owns org.freedesktop.Notifications on testuser's bus, the way a
# desktop's notification daemon does, and records every Notify call with the
# uid and the program of the process that made it (notification_recorder.py).
# The records go to $XDG_RUNTIME_DIR/notifications.jsonl, a tmpfs that ends
# with the user's session, so nothing reaches the decoy disk.
#
# The service starts with testuser's user manager: logging testuser in on the
# console (nails_e2e.desktop.login_on_console) is all a test does. The same
# login is what makes testuser the owner of the active session on seat0, whom
# the session watcher alerts.
{ pkgs, ... }:
let
  python = pkgs.python3.withPackages (ps: [ ps.dbus-fast ]);
in
{
  systemd.user.services.notification-recorder = {
    description = "Notification server that records each call";
    wantedBy = [ "default.target" ];
    unitConfig.ConditionUser = "testuser";
    serviceConfig = {
      Type = "dbus";
      BusName = "org.freedesktop.Notifications";
      # -P: the script's store directory is not a place to import from.
      ExecStart = "${python}/bin/python3 -P ${./notification_recorder.py} %t/notifications.jsonl";
    };
  };
}
