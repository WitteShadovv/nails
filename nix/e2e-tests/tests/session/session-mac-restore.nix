# A MAC address the hidden session gives a network card is gone when the
# decoy runs again.
#
# A hidden session never goes back to the decoy: it ends in a power-off, and
# the decoy's next start is a cold boot, where the card has the permanent
# address the hardware gives it. The VM's extra card is QEMU's emulated
# NE2000 (`ne2k_pci`), whose driver refuses a live address change, as many USB
# Ethernet adapters and Wi-Fi cards do; nothing configures it (dhcpcd keeps to
# eth0).
#
#   1. The hidden session gives the card a random address the way
#      NetworkManager sets a cloned MAC address: down, the address, up.
#   2. `nails deactivate` powers the machine off for real; after the cold
#      boot the card has its permanent address (`ethtool -P`, the one the VM
#      gave it) and the decoy's sysfs says it was never set.
#   3. A second session does the same and ends with a plain
#      `nails emergency`, which powers off too: the same after the cold boot.
{ self, ... }:
let
  hiddenVolume = import ./../../lib/hidden-volume.nix;
  testHelpers = import ./../../lib/test-helpers.nix;
  # The card's permanent address, which the VM gives it.
  permanentMac = "52:54:00:6e:65:32";
in
{
  name = "session-mac-restore";
  meta.tags = [
    "security"
    "session"
  ];

  nodes.machine =
    { pkgs, ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.${pkgs.stdenv.hostPlatform.system}.nails
        pkgs.ethtool
      ];
      # The NE2000 on a user-mode network of its own, with no way out.
      virtualisation.qemu.options = [
        "-netdev user,id=ne2k,restrict=on"
        "-device ne2k_pci,netdev=ne2k,mac=${permanentMac}"
      ];
      # dhcpcd runs the test network's eth0 alone and leaves the card alone.
      networking.dhcpcd.allowInterfaces = [ "eth0" ];
    };

  testScript = _: ''
    import secrets

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}
    ${testHelpers.canonicalEmergencyFn}

    CONFIG = "/mnt/data/config/nails.toml"
    PERMANENT = "${permanentMac}"
    #: A link's administrative up flag in its sysfs flags (IFF_UP).
    IFF_UP = 0x1


    def find_card():
        # By its address: its name depends on the order in which the drivers
        # registered the links.
        found = machine.wait_until_succeeds(
            f"grep -lx {PERMANENT} /sys/class/net/*/address", timeout=60
        ).split()
        assert len(found) == 1, found
        name = found[0].split("/")[4]
        driver = machine.succeed(f"readlink /sys/class/net/{name}/device/driver").strip()
        assert driver.endswith("/ne2k-pci"), f"{name} is driven by {driver}"
        return name


    def random_address():
        # Locally administered and unicast, as NetworkManager's random ones are.
        return "02:" + ":".join(f"{byte:02x}" for byte in secrets.token_bytes(5))


    def card_address(card):
        return machine.succeed(f"cat /sys/class/net/{card}/address").strip()


    def card_up(card):
        flags = int(machine.succeed(f"cat /sys/class/net/{card}/flags").strip(), 16)
        return (flags & IFF_UP) != 0


    def set_card(card, address):
        # As NetworkManager sets a cloned MAC address where the driver
        # refuses a live change.
        machine.succeed(
            f"ip link set dev {card} down && "
            f"ip link set dev {card} address {address} && "
            f"ip link set dev {card} up"
        )
        assert card_address(card) == address, card_address(card)
        assert card_up(card), f"{card} is down"


    def assert_cold_card(where):
        """After the cold boot the card has its own address, never set."""
        card = find_card()
        address = card_address(card)
        # addr_assign_type: 0 for the permanent address, 3 once one was set.
        assign = machine.succeed(f"cat /sys/class/net/{card}/addr_assign_type").strip()
        permanent = machine.succeed(f"ethtool -P {card}").split()[-1]
        machine.log(f"{where}: {card} has {address}, addr_assign_type {assign}")
        assert address == PERMANENT and permanent == PERMANENT, (address, permanent)
        assert assign == "0", f"{where}: the decoy's {card} has a set address ({assign})"


    def session_with_random_address(label):
        canonical_activate(CONFIG, "--overlay-only", label)
        card = find_card()
        set_card(card, random_address())


    machine.start()
    machine.wait_for_unit("multi-user.target")
    assert_cold_card("the decoy")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )

    with subtest("after deactivate's power-off the card has its own address"):
        session_with_random_address("activate-1")
        canonical_deactivate(CONFIG, "deactivate")
        assert_cold_card("after deactivate")

    with subtest("after a plain emergency's power-off the card has its own address"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        session_with_random_address("activate-2")
        canonical_emergency(CONFIG, "emergency")
        assert_cold_card("after emergency")
  '';
}
