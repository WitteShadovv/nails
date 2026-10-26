# The way back setting a MAC address back on a network card whose driver
# refuses a new address while the card is up.
#
# Many drivers refuse a new MAC address while their device is up: the kernel
# answers EBUSY unless the driver takes a live change, and USB Ethernet
# adapters such as the ASIX AX88179 and many Wi-Fi cards take none. The way
# back then takes the device down for the change and brings it up again. The
# VM's extra card is QEMU's emulated NE2000 (`ne2k_pci`): its Linux driver sets
# an address with `eth_mac_addr` and takes no live change, so it refuses in the
# same way. Nothing configures the card (dhcpcd keeps to eth0); the test
# brings it up on the decoy.
#
#   1. On the decoy, a new address on the card while it is up fails with
#      "Device or resource busy", and the card keeps its address.
#   2. The hidden session gives the card a random address the way
#      NetworkManager sets a cloned MAC address: down, the address, up.
#   3. `nails deactivate`: back on the decoy, the card has its permanent
#      address again (`ethtool -P`, the one the VM gave it) and is up.
#   4. A second session does the same and ends with a plain
#      `nails emergency`, which returns through the same way back: the card
#      has its permanent address again and is up.
#
# Each way back is judged on its own. One that leaves the card with another
# address, or down, fails its subtest, the test gives the card its own address
# back by hand, and the second session still runs; the test fails at the end
# naming each way back that did. So without the down/set/up retry the log
# shows both ways back failing, not only the first. Any other failure (step 1
# or a switch) stops the test at once.
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
    from contextlib import contextmanager

    from nails_e2e import session

    ${testHelpers.canonicalActivateFn}
    ${testHelpers.canonicalDeactivateFn}

    CONFIG = "/mnt/data/config/nails.toml"
    PERMANENT = "${permanentMac}"
    #: A link's administrative up flag in its sysfs flags (IFF_UP).
    IFF_UP = 0x1


    class CardNotBack(AssertionError):
        """A way back left the card with another address than its own, or down."""


    #: What each way back that failed left the card with.
    failures: list[str] = []


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


    def card_address():
        return machine.succeed(f"cat /sys/class/net/{CARD}/address").strip()


    def permanent_address():
        # "Permanent address: 52:54:00:..."
        return machine.succeed(f"ethtool -P {CARD}").split()[-1]


    def card_up():
        flags = int(machine.succeed(f"cat /sys/class/net/{CARD}/flags").strip(), 16)
        return (flags & IFF_UP) != 0


    def log_card(where):
        # addr_assign_type: 0 for the permanent address, 3 once one was set.
        assign = machine.succeed(f"cat /sys/class/net/{CARD}/addr_assign_type").strip()
        machine.log(
            f"{where}: {CARD} has {card_address()}, up: {card_up()}, "
            f"addr_assign_type: {assign}"
        )


    def set_card(address, where):
        # As NetworkManager sets a cloned MAC address where the driver
        # refuses a live change.
        machine.succeed(
            f"ip link set dev {CARD} down && "
            f"ip link set dev {CARD} address {address} && "
            f"ip link set dev {CARD} up"
        )
        log_card(where)
        assert card_address() == address, card_address()
        assert card_up(), f"{where}: {CARD} is down"


    def assert_decoy_address(where):
        log_card(where)
        assert permanent_address() == PERMANENT, permanent_address()
        now = card_address()
        if now != PERMANENT:
            raise CardNotBack(f"{where}: {CARD} kept {now}, not its own {PERMANENT}")
        if not card_up():
            raise CardNotBack(f"{where}: the way back left {CARD} down")


    @contextmanager
    def way_back(name):
        # A subtest of its own: a way back that leaves the card with another
        # address, or down, fails it, and the test records that, gives the card
        # its own address back by hand, so that the next session starts as
        # this one did, and goes on. Any other failure stops the test.
        try:
            with subtest(name):
                yield
        except CardNotBack as failure:
            failures.append(str(failure))
            set_card(PERMANENT, "the decoy, by hand")


    machine.start()
    machine.wait_for_unit("multi-user.target")
    CARD = find_card()
    machine.succeed(f"ip link set dev {CARD} up")
    assert permanent_address() == PERMANENT, permanent_address()
    log_card("the decoy")
    machine.succeed("""${hiddenVolume.setupHiddenVolume}""")
    machine.succeed("nails init /mnt/data")
    machine.succeed(
        f"cat > {CONFIG} <<'EOF'\n"
        "hidden_volume_root = \"/mnt/data\"\n"
        "minimum_space_mb = 100\n"
        "EOF"
    )

    with subtest("the card's driver refuses a new address while the card is up"):
        rc, out = machine.execute(f"ip link set dev {CARD} address {random_address()} 2>&1")
        machine.log(f"a live address change: exit {rc}: {out}")
        assert rc != 0 and "Device or resource busy" in out, (rc, out)
        assert card_address() == PERMANENT, card_address()
        assert card_up(), f"{CARD} went down"

    with way_back("deactivate gives the card its own address back"):
        canonical_activate(CONFIG, "--overlay-only", "activate-1")
        assert card_address() == PERMANENT and card_up(), "the card as the decoy left it"
        set_card(random_address(), "the hidden session")
        canonical_deactivate(CONFIG, "deactivate")
        assert_decoy_address("after deactivate")

    with way_back("a plain emergency gives the card its own address back"):
        machine.succeed("""${hiddenVolume.reopenHiddenVolume}""")
        canonical_activate(CONFIG, "--overlay-only", "activate-2")
        assert card_address() == PERMANENT and card_up(), "the card as the decoy left it"
        set_card(random_address(), "the hidden session")
        session.follow_soft_reboot(machine, f"nails --config {CONFIG} emergency", "emergency")
        session.assert_decoy_root(machine)
        machine.wait_until_succeeds("test ! -e /dev/mapper/data", timeout=60)
        assert_decoy_address("after emergency")

    assert not failures, "; ".join(failures)
  '';
}
