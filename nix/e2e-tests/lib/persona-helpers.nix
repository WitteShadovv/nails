# Helpers for the persona-separation E2E tests (tests/persona/).
#
# These tests ask a question the overlay cannot answer on its own: when the
# hidden session reuses the decoy's account-bound clients (sync daemons, mail,
# browser sync), hidden data leaves the machine and is pulled back onto the decoy
# disk after deactivation, because deactivation only discards the overlay upper
# dirs and never rolls back what a remote already holds. Reproducing that needs a
# real remote, so the sync tests are two-node: a `peer` machine runs a second
# Syncthing that the decoy client pairs with.
#
# Syncthing keys: the design calls for pre-generated device keys committed under
# fixtures/persona/. They cannot be generated in the development sandbox (no
# syncthing/openssl, and a device ID is the base32 Luhn digest of the DER cert),
# so each node lets its own Syncthing generate a valid key on first boot and the
# test reads the resulting device IDs over the REST API and pairs the two nodes
# at runtime. The pairing is still fully scripted and deterministic within a run;
# only the key bytes differ between runs. Discovery and relaying are disabled so
# the two nodes only ever talk to each other over the test network.
{ self, pkgs }:
let
  inherit (pkgs) system;
  baseOs = import ./base-os-overlays.nix;

  # Shared Syncthing options for both nodes: no discovery, no relays, no usage
  # reporting. The nodes reach each other by static addresses the test sets when
  # it pairs them, so nothing leaves the test network.
  isolatedSyncthingOptions = {
    localAnnounceEnabled = false;
    globalAnnounceEnabled = false;
    relaysEnabled = false;
    natEnabled = false;
    urAccepted = -1;
    crashReportingEnabled = false;
  };
in
rec {
  # Config-dir locations the REST helpers read the API key and device ID from.
  clientConfigDir = "/home/testuser/.config/syncthing";
  peerConfigDir = "/var/lib/syncthing/.config/syncthing";

  # The folder the decoy client and the peer share, and where it lives on each.
  syncFolderId = "persona-canary";
  clientSyncPath = "/home/testuser/Sync";
  peerSyncPath = "/var/lib/syncthing/Sync";

  # The decoy "client": the standard decoy VM plus nails, python3 and the sync
  # tooling, with a Syncthing that runs *as the decoy user* and keeps its config
  # and synced folder in the decoy home. That placement is the whole point: the
  # /home overlay (shared-home) or the fresh-home bind decides whether this client
  # is live in the hidden session, exactly as it would on a real decoy.
  clientNode =
    { ... }:
    {
      imports = [ ./vm-config.nix ];
      environment.systemPackages = [
        self.packages.${system}.nails
        pkgs.python3
        pkgs.curl
        pkgs.jq
      ];
      services.syncthing = {
        enable = true;
        user = "testuser";
        group = "users";
        configDir = clientConfigDir;
        dataDir = "/home/testuser/.local/share/syncthing";
        guiAddress = "127.0.0.1:8384";
        overrideDevices = false;
        overrideFolders = false;
        settings.options = isolatedSyncthingOptions;
      };
      systemd.tmpfiles.rules = [
        "d ${clientSyncPath} 0700 testuser users -"
      ];
    };

  # The paired "peer": a second machine that holds the shared folder, so a canary
  # pushed from the hidden session lands on a real remote and can be pulled back
  # after deactivation.
  peerNode =
    { ... }:
    {
      imports = [ ./vm-config.nix ];
      environment.systemPackages = [
        pkgs.curl
        pkgs.jq
      ];
      services.syncthing = {
        enable = true;
        configDir = peerConfigDir;
        guiAddress = "127.0.0.1:8384";
        overrideDevices = false;
        overrideFolders = false;
        settings.options = isolatedSyncthingOptions;
      };
      systemd.tmpfiles.rules = [
        "d ${peerSyncPath} 0700 syncthing syncthing -"
      ];
    };

  # Writes a nails.toml with a /home overlay and the given persona mode. The
  # base-OS trees are overlaid too, which the writable-trees pre-flight check
  # requires; /home stays the only tree the persona tests look at.
  # `mode` is "shared-home" or "fresh-home"; `mask` is a TOML array literal for
  # persona.mask_inherited (for example '["syncthing.service"]'), or null to omit.
  writePersonaConfigFn = ''
    def write_persona_config(path, mode="shared-home", mask=None):
        mask_line = f"mask_inherited = {mask}\n" if mask is not None else ""
        machine.succeed(
            """cat > %s <<'EOF'
    hidden_volume_root = "/mnt/data"
    overlay_mode = "explicit"
    risky_services = "keep"

    [persona]
    mode = "%s"
    %s
    ${baseOs.toml}
    [[overlays]]
    name = "home"
    lower = "/home"
    upper = "/mnt/data/home"
    work = "/mnt/data/.work/home"
    target = "/home"
    EOF""" % (path, mode, mask_line)
        )
  '';

  # The in-guest Syncthing REST helpers shared by the sync tests. They operate on
  # the `client` and `peer` machine globals the two-node tests define, plus the
  # config-dir constants above (pasted as Python literals by each test).
  syncClientHelpersFn = ''
    import json
    import time

    SYNC_GUI = "127.0.0.1:8384"


    def _st_apikey(node, config_dir):
        return node.succeed(
            "grep -oP '(?<=<apikey>)[^<]+' " + config_dir + "/config.xml"
        ).strip()


    def st_wait_ready(node, config_dir):
        node.wait_for_unit("syncthing.service")
        node.wait_until_succeeds(
            "test -s " + config_dir + "/config.xml "
            "&& grep -q '<apikey>' " + config_dir + "/config.xml",
            timeout=180,
        )
        for _ in range(90):
            key = _st_apikey(node, config_dir)
            rc, _out = node.execute(
                f"curl -sS -H 'X-API-Key: {key}' http://{SYNC_GUI}/rest/system/ping"
            )
            if rc == 0:
                return
            time.sleep(2)
        raise Exception("syncthing REST API never became ready")


    def st_api(node, config_dir, method, path, data=None):
        key = _st_apikey(node, config_dir)
        base = f"curl -sS -X {method} -H 'X-API-Key: {key}'"
        if data is None:
            return node.succeed(f"{base} http://{SYNC_GUI}{path}")
        node.succeed(
            "cat > /tmp/st-payload.json <<'JSON'\n" + json.dumps(data) + "\nJSON"
        )
        return node.succeed(
            f"{base} -H 'Content-Type: application/json' "
            f"--data-binary @/tmp/st-payload.json http://{SYNC_GUI}{path}"
        )


    def st_device_id(node, config_dir):
        return json.loads(st_api(node, config_dir, "GET", "/rest/system/status"))["myID"]


    def st_add_device(node, config_dir, device_id, name, address):
        st_api(
            node,
            config_dir,
            "POST",
            "/rest/config/devices",
            {"deviceID": device_id, "name": name, "addresses": [address]},
        )


    def st_add_folder(node, config_dir, folder_id, path, remote_id):
        st_api(
            node,
            config_dir,
            "POST",
            "/rest/config/folders",
            {
                "id": folder_id,
                "label": folder_id,
                "path": path,
                "type": "sendreceive",
                "devices": [{"deviceID": remote_id}],
            },
        )


    def st_connected(node, config_dir, remote_id):
        conns = json.loads(
            st_api(node, config_dir, "GET", "/rest/system/connections")
        )["connections"]
        return bool(conns.get(remote_id, {}).get("connected", False))


    def st_rescan(node, config_dir, folder_id):
        st_api(node, config_dir, "POST", f"/rest/db/scan?folder={folder_id}")


    def st_file_present(node, config_dir, folder_id, name):
        # /rest/db/file returns the global/local record for a file; an absent file
        # has an empty global version vector.
        out = st_api(
            node,
            config_dir,
            "GET",
            f"/rest/db/file?folder={folder_id}&file={name}",
        )
        try:
            record = json.loads(out)
        except json.JSONDecodeError:
            return False
        version = record.get("global", {}).get("version", [])
        return bool(version)
  '';
}
