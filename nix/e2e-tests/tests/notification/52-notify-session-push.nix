# Test 52: Notify Session Push
#
# A detached graphical activation whose hidden NixOS switch fails (with
# `nixos_switch_required = false`) keeps the overlays, restarts the session and
# commits; the "NixOS Rebuild Failed" result it raised must then reach the
# operator's graphical session without waiting for a login dispatcher. The
# worker pushes the queued results into the session through the user's service
# manager, which runs `notify-send` against the session bus.
#
# The VM's window manager runs no XDG autostart, so the push is the only path
# that can deliver here. The session bus carries a stub notification server
# (D-Bus activated, so it survives the session restart) that records every
# Notify call; testuser lingers so its user manager and bus outlive the
# restarted logind session. The queue on the hidden volume must be empty
# afterwards (delivered = dequeued) and `nails status` must list nothing as
# undelivered.

{ self, pkgs, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  assertions = import ./../../lib/assertions.nix;
  sessionHelpers = import ./../../lib/session-helpers.nix;

  stubLog = "/var/lib/notify-stub/session-calls.log";

  # A minimal org.freedesktop.Notifications server: answers the capability and
  # server-information queries libnotify makes and appends every Notify call to
  # the log as a JSON line [app_name, summary, body].
  notificationServer =
    pkgs.writers.writePython3 "nails-e2e-notification-server"
      {
        libraries = [ pkgs.python3Packages.jeepney ];
        flakeIgnore = [ "E501" ];
      }
      ''
        import json

        from jeepney import HeaderFields, MessageType, new_error, new_method_return
        from jeepney.bus_messages import message_bus
        from jeepney.io.blocking import open_dbus_connection

        LOG = "${stubLog}"

        conn = open_dbus_connection(bus="SESSION")
        conn.send_and_get_reply(message_bus.RequestName("org.freedesktop.Notifications"))

        while True:
            msg = conn.receive()
            if msg.header.message_type != MessageType.method_call:
                continue
            member = msg.header.fields.get(HeaderFields.member)
            if member == "Notify":
                app, _replaces, _icon, summary, body, _actions, _hints, _timeout = msg.body
                with open(LOG, "a", encoding="utf-8") as log:
                    log.write(json.dumps([app, summary, body]) + "\n")
                conn.send(new_method_return(msg, "u", (1,)))
            elif member == "GetCapabilities":
                conn.send(new_method_return(msg, "as", (["body"],)))
            elif member == "GetServerInformation":
                conn.send(new_method_return(msg, "ssss", ("stub", "nails-e2e", "1", "1.2")))
            else:
                conn.send(new_error(msg, "org.freedesktop.DBus.Error.UnknownMethod"))
      '';

  notificationService = pkgs.writeTextDir "share/dbus-1/services/org.freedesktop.Notifications.service" ''
    [D-BUS Service]
    Name=org.freedesktop.Notifications
    Exec=${notificationServer}
  '';
in
{
  name = "notify-session-push";
  meta.tags = [ "notification" ];

  nodes.machine =
    { lib, ... }:
    {
      imports = [ ./../../lib/graphical-vm-config.nix ];
      environment.systemPackages = [ self.packages.x86_64-linux.nails ];
      nix.settings.experimental-features = [
        "nix-command"
        "flakes"
      ];
      nix.settings.substituters = lib.mkForce [ ];
      services.dbus.packages = [ notificationService ];
      # Keep the user manager (and its session bus) across the session restart
      # the activation performs, so the push finds the bus.
      users.users.testuser.linger = true;
      systemd.tmpfiles.rules = [ "d /var/lib/notify-stub 0777 root root -" ];
    };

  testScript = _: ''
    import json
    import shlex

    ${testHelpers.writeHeadlessConfigFn}
    ${testHelpers.readStatusJsonFn}
    ${testHelpers.waitForStatusStateFn}
    ${assertions.assertOverlayMountedFn}
    ${sessionHelpers.waitForActivationTransientUnitFn}

    TRIVIAL_LOCK = '{"nodes":{"root":{}},"root":"root","version":7}'
    stub_log = "${stubLog}"
    queue_dir = "/mnt/data/notifications"
    headless_config = "/tmp/nails-headless.toml"
    flake_ref = "/mnt/data/nixos#nails-e2e"

    def stub_calls():
        if machine.execute(f"test -s {stub_log}")[0] != 0:
            return []
        return [json.loads(line) for line in machine.succeed(f"cat {stub_log}").splitlines() if line.strip()]

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.wait_for_unit("display-manager.service")
    machine.wait_until_succeeds("systemctl is-active user@1000.service")
    machine.wait_until_succeeds("test -S /run/user/1000/bus")

    with subtest("the session bus delivers a notification to the stub server"):
        machine.succeed(
            "su - testuser -c 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus "
            + "notify-send probe probe-body'"
        )
        machine.wait_until_succeeds(f"grep -q probe-body {stub_log}", timeout=60)
        machine.succeed(f"rm -f {stub_log}")

    with subtest("prepare a broken hidden flake so the hidden switch fails"):
        write_headless_config(headless_config)
        machine.succeed(
            "sed -i "
            + shlex.quote("/^hidden_volume_root = /a nixos_flake = \"" + flake_ref + "\"")
            + " "
            + shlex.quote(headless_config)
        )
        machine.succeed(f"grep -qx 'nixos_switch_required = false' {shlex.quote(headless_config)}")
        machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
        machine.succeed("mkdir -p /mnt/data/nixos")
        machine.succeed("""cat > /mnt/data/nixos/flake.nix <<'EOF'
    {
      outputs = { self }: {
        nixosConfigurations.nails-e2e.config.system.build.toplevel =
          builtins.throw "deliberately broken hidden configuration";
      };
    }
    EOF""")
        machine.succeed(
            "printf '%s' " + shlex.quote(TRIVIAL_LOCK) + " > /mnt/data/nixos/flake.lock"
        )

    with subtest("a detached graphical activation commits with the switch failure as a warning"):
        machine.succeed(
            "env DISPLAY=:0 XDG_SESSION_TYPE=x11 SUDO_UID=1000 SUDO_USER=testuser "
            + "SHELL=/run/current-system/sw/bin/bash "
            + f"nails --config {headless_config} activate -y"
        )
        wait_for_activation_transient_unit()
        machine.wait_until_succeeds("systemctl is-active display-manager.service")
        assert_overlay_mounted("/home")
        wait_for_status_state("Active", config_path=headless_config)
        status = read_status_json(config_path=headless_config)
        assert status.get("hidden_config_warning"), status

    with subtest("the rebuild-failed result reached the operator's session and left the queue"):
        machine.wait_until_succeeds(f"grep -q 'NixOS Rebuild Failed' {stub_log}", timeout=120)
        calls = stub_calls()
        failed = [call for call in calls if call[1] == "NixOS Rebuild Failed"]
        assert len(failed) == 1, calls
        assert failed[0][0] == "NAILS", calls
        assert any(call[1] == "NAILS Overlay Active" for call in calls), calls
        machine.wait_until_succeeds(
            f"test -z \"$(find {queue_dir} -maxdepth 1 -name '*.json')\"", timeout=60
        )

    with subtest("status lists nothing as undelivered and no activation in flight"):
        status = read_status_json(config_path=headless_config)
        assert "undelivered_notifications" not in status, status
        assert "notify_send_missing" not in status, status
        assert "activation_in_flight" not in status, status
        assert status["last_activation"]["duration_ms"] > 0, status
        machine.fail(f"test -e {queue_dir}/.result-pending")
  '';
}
