// SPDX-FileCopyrightText: 2025-2026 WitteShadovv
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::filesystem::MockFilesystem;

/// The documented layout: the mapping `data`, mounted at `/mnt/data`.
const ROOT: &str = "/mnt/data";
const DATA_MOUNTINFO: &str =
    "36 35 254:0 / /mnt/data rw,relatime shared:1 - ext4 /dev/mapper/data rw\n";

/// The `configuration.nix` that `nixos-generate-config` writes on a UEFI
/// machine without a desktop preset: the template from Nixpkgs, under its MIT
/// licence (see the snippet tags). NixOS 26.05 and 26.11 write the same
/// file apart from the release in `system.stateVersion` (their templates in
/// nixos/modules/installer/tools/tools.nix are identical), so `{release}`
/// stands for it. The one line the generator fills with two spaces is left
/// empty here. Its stateVersion comment holds the word "data" twice.
// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Eelco Dolstra and the Nixpkgs/NixOS contributors
// SPDX-License-Identifier: MIT
const STOCK_CONFIGURATION: &str = r#"# Edit this configuration file to define what should be installed on
# your system. Help is available in the configuration.nix(5) man page, on
# https://search.nixos.org/options and in the NixOS manual (`nixos-help`).

{ config, lib, pkgs, ... }:

{
  imports =
    [ # Include the results of the hardware scan.
      ./hardware-configuration.nix
    ];

  # Use the systemd-boot EFI boot loader.
  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = true;

  # networking.hostName = "nixos"; # Define your hostname.

  # Configure network connections interactively with nmcli or nmtui.
  networking.networkmanager.enable = true;

  # Set your time zone.
  # time.timeZone = "Europe/Amsterdam";

  # Configure network proxy if necessary
  # networking.proxy.default = "http://user:password@proxy:port/";
  # networking.proxy.noProxy = "127.0.0.1,localhost,internal.domain";

  # Select internationalisation properties.
  # i18n.defaultLocale = "en_US.UTF-8";
  # console = {
  #   font = "Lat2-Terminus16";
  #   keyMap = "us";
  #   useXkbConfig = true; # use xkb.options in tty.
  # };

  # Enable the X11 windowing system.
  # services.xserver.enable = true;




  # Configure keymap in X11
  # services.xserver.xkb.layout = "us";
  # services.xserver.xkb.options = "eurosign:e,caps:escape";

  # Enable CUPS to print documents.
  # services.printing.enable = true;

  # Enable sound.
  # services.pulseaudio.enable = true;
  # OR
  # services.pipewire = {
  #   enable = true;
  #   pulse.enable = true;
  # };

  # Enable touchpad support (enabled default in most desktopManager).
  # services.libinput.enable = true;

  # Define a user account. Don't forget to set a password with ‘passwd’.
  # users.users.alice = {
  #   isNormalUser = true;
  #   extraGroups = [ "wheel" ]; # Enable ‘sudo’ for the user.
  #   packages = with pkgs; [
  #     tree
  #   ];
  # };

  # programs.firefox.enable = true;

  # List packages installed in system profile.
  # You can use https://search.nixos.org/ to find more packages (and options).
  # environment.systemPackages = with pkgs; [
  #   vim # Do not forget to add an editor to edit configuration.nix! The Nano editor is also installed by default.
  #   wget
  # ];

  # Some programs need SUID wrappers, can be configured further or are
  # started in user sessions.
  # programs.mtr.enable = true;
  # programs.gnupg.agent = {
  #   enable = true;
  #   enableSSHSupport = true;
  # };

  # List services that you want to enable:

  # Enable the OpenSSH daemon.
  # services.openssh.enable = true;

  # Open ports in the firewall.
  # networking.firewall.allowedTCPPorts = [ ... ];
  # networking.firewall.allowedUDPPorts = [ ... ];
  # Or disable the firewall altogether.
  # networking.firewall.enable = false;

  # Copy the NixOS configuration file and link it from the resulting system
  # (/run/current-system/configuration.nix). This is useful in case you
  # accidentally delete configuration.nix.
  # system.copySystemConfiguration = true;

  # This option defines the first version of NixOS you have installed on this particular machine,
  # and is used to maintain compatibility with application data (e.g. databases) created on older NixOS versions.
  #
  # Most users should NEVER change this value after the initial install, for any reason,
  # even if you've upgraded your system to a new NixOS release.
  #
  # This value does NOT affect the Nixpkgs version your packages and OS are pulled from,
  # so changing it will NOT upgrade your system - see https://nixos.org/manual/nixos/stable/#sec-upgrading for how
  # to actually do that.
  #
  # This value being lower than the current NixOS release does NOT mean your system is
  # out of date, out of support, or vulnerable.
  #
  # Do NOT change this value unless you have manually inspected all the changes it would make to your configuration,
  # and migrated your data accordingly.
  #
  # For more information, see `man configuration.nix` or https://nixos.org/manual/nixos/stable/options#opt-system.stateVersion .
  system.stateVersion = "{release}"; # Did you read the comment?

}
"#;
// SPDX-SnippetEnd

/// The `hardware-configuration.nix` `nixos-generate-config` writes for a
/// virtual machine, with the decoy's own filesystems only.
// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Eelco Dolstra and the Nixpkgs/NixOS contributors
// SPDX-License-Identifier: MIT
const STOCK_HARDWARE_CONFIGURATION: &str = r#"# Do not modify this file!  It was generated by ‘nixos-generate-config’
# and may be overwritten by future invocations.  Please make changes
# to /etc/nixos/configuration.nix instead.
{ config, lib, pkgs, modulesPath, ... }:

{
  imports =
    [ (modulesPath + "/profiles/qemu-guest.nix")
    ];

  boot.initrd.availableKernelModules = [ "ahci" "xhci_pci" "virtio_pci" "sr_mod" "virtio_blk" ];
  boot.initrd.kernelModules = [ ];
  boot.kernelModules = [ "kvm-amd" ];
  boot.extraModulePackages = [ ];

  fileSystems."/" =
    { device = "/dev/disk/by-uuid/0f6c1a3e-2b51-4c0e-9d9a-4f1b0a7d2c11";
      fsType = "ext4";
    };

  fileSystems."/boot" =
    { device = "/dev/disk/by-uuid/5A1B-2C3D";
      fsType = "vfat";
      options = [ "fmask=0077" "dmask=0077" ];
    };

  swapDevices = [ ];

  nixpkgs.hostPlatform = lib.mkDefault "x86_64-linux";
}
"#;
// SPDX-SnippetEnd

/// The `flake.nix` `nixos-generate-config --flake` writes on a host called
/// `nixos`.
// SPDX-SnippetBegin
// SPDX-SnippetCopyrightText: Eelco Dolstra and the Nixpkgs/NixOS contributors
// SPDX-License-Identifier: MIT
const STOCK_FLAKE: &str = r#"{
  inputs = {
    # This is pointing to an unstable release.
    # If you prefer a stable release instead, you can change the word unstable to the latest number shown here: https://nixos.org/download
    # i.e. nixos-24.11
    # Use `nix flake update` to update the flake to the latest revision of the chosen release channel.
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.zst";
  };
  outputs = inputs@{ self, nixpkgs, ... }: {
    # NOTE: 'nixos' is the default hostname
    nixosConfigurations.nixos = nixpkgs.lib.nixosSystem {
      modules = [ ./configuration.nix ];
    };
  };
}
"#;
// SPDX-SnippetEnd

/// A host whose `/etc/nixos` holds `files` and whose mount table is
/// `mountinfo`.
fn host(files: &[(&str, &str)], mountinfo: &str) -> MockFilesystem {
    let fs = MockFilesystem::new();
    for (path, content) in files {
        fs.mock_set_file_content(path, content);
    }
    let paths: Vec<&Path> = files.iter().map(|(path, _)| Path::new(*path)).collect();
    fs.mock_set_files_with_pattern("/etc/nixos", ".nix", &paths);
    fs.mock_set_file_content(SELF_MOUNTINFO, mountinfo);
    fs
}

fn scan_at(fs: &MockFilesystem, root: &str) -> BaseConfigScan {
    verify_base_config_clean(fs, Path::new(root)).unwrap()
}

/// The documented layout with `content` as the decoy's `configuration.nix`.
fn scan_configuration(content: &str) -> BaseConfigScan {
    let fs = host(&[("/etc/nixos/configuration.nix", content)], DATA_MOUNTINFO);
    scan_at(&fs, ROOT)
}

/// The one reference `scan` holds, as (line, text, kind).
fn only_reference(scan: &BaseConfigScan) -> (usize, &str, ReferenceKind) {
    assert_eq!(scan.references.len(), 1, "{scan:#?}");
    let found = &scan.references[0];
    (found.line, found.text.as_str(), found.kind)
}

#[test]
fn the_stock_configuration_of_nixos_26_05_and_26_11_is_clean() {
    for release in ["26.05", "26.11"] {
        let configuration = STOCK_CONFIGURATION.replace("{release}", release);
        let fs = host(
            &[
                ("/etc/nixos/configuration.nix", configuration.as_str()),
                (
                    "/etc/nixos/hardware-configuration.nix",
                    STOCK_HARDWARE_CONFIGURATION,
                ),
                ("/etc/nixos/flake.nix", STOCK_FLAKE),
            ],
            DATA_MOUNTINFO,
        );
        let scan = scan_at(&fs, ROOT);
        assert!(scan.is_clean(), "{release}: {scan:#?}");
        assert_eq!(scan.files_read, 3);
    }
}

/// The leak forms that name the mapping without its device path, beside the
/// device path itself in a comment: each is still refused, commented out or
/// not.
#[test]
fn every_leak_form_of_the_mapper_name_is_refused() {
    use ReferenceKind::{Device, DeviceUnit, MapperName, MountUnit};
    let cases = [
        (
            "{ boot.initrd.luks.devices.data.device = \"/dev/disk/by-uuid/1\"; }",
            (1, "data", MapperName),
        ),
        (
            "{ boot.initrd.luks.devices.\"data\".device = \"/dev/disk/by-uuid/1\"; }",
            (1, "data", MapperName),
        ),
        (
            "{ boot.initrd.luks.devices = {\n  data = { device = \"/dev/disk/by-uuid/1\"; };\n}; }",
            (2, "data", MapperName),
        ),
        (
            "{ environment.etc.crypttab.text = \"data /dev/sdb2 none tcrypt\"; }",
            (1, "data", MapperName),
        ),
        (
            "{ systemd.services.x.script = \"cryptsetup open /dev/sdb2 data\"; }",
            (1, "data", MapperName),
        ),
        (
            "{ }\n# mount /dev/mapper/data before work\n",
            (2, "/dev/mapper/data", Device),
        ),
        (
            "{ }\n# boot.initrd.luks.devices.data.device = \"/dev/disk/by-uuid/7d2c9e14\";\n",
            (2, "data", MapperName),
        ),
        (
            "{ }\n# boot.initrd.luks.devices.\"data\".device = \"/dev/disk/by-uuid/7d2c9e14\";\n",
            (2, "data", MapperName),
        ),
        (
            "{ }\n/* boot.initrd.luks.devices.data.device = \"/dev/sdb2\"; */\n",
            (2, "data", MapperName),
        ),
        (
            "{ }\n# boot.initrd.luks.devices = {\n#   data = {\n#     device = \"/dev/sdb2\";\n#   };\n# };\n",
            (3, "data", MapperName),
        ),
        (
            "{ }\n# cryptsetup open /dev/sdb2 data\n",
            (2, "data", MapperName),
        ),
        (
            "{ }\n# environment.etc.crypttab.text = \"data /dev/sdb2 none tcrypt\";\n",
            (2, "data", MapperName),
        ),
        (
            "{ environment.etc.crypttab.text = ''\n  data UUID=7d2c9e14 none luks\n''; }",
            (2, "data", MapperName),
        ),
        (
            "{ systemd.services.x.requires = [ \"systemd-cryptsetup@data.service\" ]; }",
            (1, "data", MapperName),
        ),
        (
            "{ systemd.services.x.after = [ \"mnt-data.mount\" ]; }",
            (1, "mnt-data.mount", MountUnit),
        ),
        (
            "{ systemd.services.x.after = [ \"mnt-data.automount\" ]; }",
            (1, "mnt-data.automount", MountUnit),
        ),
        (
            "{ systemd.services.x.requires = [ \"dev-mapper-data.device\" ]; }",
            (1, "dev-mapper-data.device", DeviceUnit),
        ),
        (
            "{ fileSystems.\"/srv\".device = \"/dev/disk/by-id/dm-name-data\"; }",
            (1, "/dev/disk/by-id/dm-name-data", Device),
        ),
        (
            "{ boot.initrd.luks = { devices.data.device = \"/dev/disk/by-uuid/1\"; }; }",
            (1, "data", MapperName),
        ),
        (
            "{\n  boot = {\n    initrd = {\n      luks = {\n        devices = {\n          \
             data = { device = \"/dev/disk/by-uuid/1\"; };\n        };\n      };\n    };\n  };\n}",
            (6, "data", MapperName),
        ),
        (
            "{ }\n# boot.initrd.luks = {\n#   devices.data.device = \"/dev/sdb2\";\n# };\n",
            (3, "data", MapperName),
        ),
        (
            "{ boot.initrd.luks = {\n  devices.\"data\" = { device = \"/dev/sdb2\"; };\n}; }",
            (2, "data", MapperName),
        ),
        (
            "{ boot.initrd.luks.devices = { inherit data; }; }",
            (1, "data", MapperName),
        ),
        (
            "{ }\n# device = \"/dev/disk/by-id/dm-uuid-CRYPT-LUKS2-7d2c9e14e8a14b3c9f6b0e1a2d3c4b5a-data\";\n",
            (
                2,
                "/dev/disk/by-id/dm-uuid-CRYPT-LUKS2-7d2c9e14e8a14b3c9f6b0e1a2d3c4b5a-data",
                Device,
            ),
        ),
        (
            "{ environment.etc.crypttab.text = ''\n  data /var/lib/vault.img none luks\n''; }",
            (2, "data", MapperName),
        ),
    ];
    for (content, expected) in cases {
        let scan = scan_configuration(content);
        assert_eq!(only_reference(&scan), expected, "{content}");
    }
}

/// A mount point or a mapping with a `-` in it: systemd escapes the `-` in
/// the names of its units, and a double-quoted Nix string must double the
/// backslash. Both spellings are refused.
#[test]
fn escaped_unit_names_are_refused_in_either_spelling() {
    use ReferenceKind::{DeviceUnit, MapperName, MountUnit};
    let mountinfo = "36 35 254:0 / /mnt/my-data rw - ext4 /dev/mapper/vg-data rw\n";
    let cases = [
        (
            "{ systemd.services.x.after = [ \"mnt-my\\\\x2ddata.mount\" ]; }",
            ("mnt-my\\\\x2ddata.mount", MountUnit),
        ),
        (
            "{ systemd.services.x.after = [ ''mnt-my\\x2ddata.mount'' ]; }",
            ("mnt-my\\x2ddata.mount", MountUnit),
        ),
        (
            "{ systemd.services.x.requires = [ \"systemd-cryptsetup@vg\\\\x2ddata.service\" ]; }",
            ("vg\\\\x2ddata", MapperName),
        ),
        (
            "{ systemd.services.x.requires = [ ''systemd-cryptsetup@vg\\x2ddata.service'' ]; }",
            ("vg\\x2ddata", MapperName),
        ),
        (
            "{ systemd.services.x.requires = [ \"dev-mapper-vg\\\\x2ddata.device\" ]; }",
            ("dev-mapper-vg\\\\x2ddata.device", DeviceUnit),
        ),
        (
            "{ systemd.services.x.requires = [ ''dev-mapper-vg\\x2ddata.device'' ]; }",
            ("dev-mapper-vg\\x2ddata.device", DeviceUnit),
        ),
    ];
    for (content, (text, kind)) in cases {
        let fs = host(&[("/etc/nixos/configuration.nix", content)], mountinfo);
        let scan = scan_at(&fs, "/mnt/my-data");
        assert_eq!(only_reference(&scan), (1, text, kind), "{content}");
    }
}

/// Ordinary configuration passes: the mapping name as a word or a
/// directory, and words and options that merely look related.
#[test]
fn ordinary_uses_of_the_mapper_name_pass() {
    for content in [
        "{ services.postgresql.dataDir = \"/var/lib/postgresql/data\"; }",
        "{ fileSystems.\"/srv/data\".device = \"/dev/sdb1\"; }",
        "{ }\n# keep user data on /home\n",
        "{ }\n/* the data disk\n   is mounted elsewhere */\n",
        "{ services.evolution-data-server.enable = true; }",
        "{ fileSystems.\"/mnt/data2\".device = \"/dev/sdb1\"; }",
        "{ swapDevices = [ { device = \"/dev/mapper/data-swap\"; } ]; }",
        "{ systemd.services.backup.description = \"Back up user data\"; }",
        "{ users.users.alice = {\n  data = 1;\n}; }",
        "{ services.plausible.enable = true; }",
        "{ }\n# an implausible setting\n",
        "{ }\n# plausible deniability\n",
        "{ systemd.services.x.after = [ \"srv-mnt-data.mount\" ]; }",
        "{ networking.hostName = \"data\"; }",
        "{ boot.initrd.luks.devices.\"luks-0f6c1a3e\".device = \"/dev/disk/by-uuid/0f6c1a3e\"; }",
        "{ boot.initrd.luks.devices.root.device = \"/dev/sda2\";\n  services.foo = {\n    data = 1;\n  }; }",
        "{ boot.initrd.luks = {\n  devices.root.device = \"/dev/sda2\";\n  data = 1;\n}; }",
        "{ }\n# data /home is backed up nightly\n",
    ] {
        let scan = scan_configuration(content);
        assert!(scan.is_clean(), "{content}: {scan:#?}");
    }
}

/// `nixos-generate-config` run while the hidden volume was mounted names its
/// mount point, its device and its mapping: three lines, the first reported
/// first.
#[test]
fn a_hardware_configuration_generated_with_the_volume_mounted_is_refused() {
    let leaky = STOCK_HARDWARE_CONFIGURATION.replace(
        "  swapDevices = [ ];",
        "  fileSystems.\"/mnt/data\" =\n    { device = \"/dev/mapper/data\";\n      fsType = \"ext4\";\n    };\n\n  \
         boot.initrd.luks.devices.\"data\".device = \"/dev/disk/by-uuid/7d2c9e14\";\n\n  swapDevices = [ ];",
    );
    let fs = host(
        &[("/etc/nixos/hardware-configuration.nix", leaky.as_str())],
        DATA_MOUNTINFO,
    );
    let scan = scan_at(&fs, ROOT);
    let found: Vec<_> = scan
        .references
        .iter()
        .map(|r| (r.line, r.text.as_str(), r.kind))
        .collect();
    assert_eq!(
        found,
        [
            (27, "/mnt/data", ReferenceKind::MountPoint),
            (28, "/dev/mapper/data", ReferenceKind::Device),
            (32, "data", ReferenceKind::MapperName),
        ]
    );
    assert!(
        scan.references
            .iter()
            .all(|r| r.file == Path::new("/etc/nixos/hardware-configuration.nix"))
    );
}

/// The bare word `hidden` no longer counts: GRUB's `timeoutStyle` takes it
/// as a value, and prose uses it.
#[test]
fn the_word_hidden_alone_passes() {
    for content in [
        "{ boot.loader.grub.timeoutStyle = \"hidden\"; }",
        "{ boot.kernelParams = [ \"hidden\" ]; }",
        "{ }\n# the hidden menu shows on Shift\n",
    ] {
        let scan = scan_configuration(content);
        assert!(scan.is_clean(), "{content}: {scan:#?}");
    }
}

/// A path with `hidden` in it is no trace of this hidden volume: only its
/// own mount point counts.
#[test]
fn paths_named_hidden_pass() {
    for content in [
        "{ fileSystems.\"/mnt/hidden\" = { }; }",
        "{ imports = [ /srv/hidden/extra.nix ]; }",
        "{ inputs.hidden.url = \"path:hidden/nixos\"; }",
        "{ services.nginx.virtualHosts.x.locations.\"/hidden/\".return = \"404\"; }",
    ] {
        let scan = scan_configuration(content);
        assert!(scan.is_clean(), "{content}: {scan:#?}");
    }
}

#[test]
fn nails_is_refused() {
    for (content, expected) in [
        (
            "{ ... }: { imports = [ ./nails/configuration.nix ]; }",
            (1, "./nails/configuration.nix", ReferenceKind::StagedText),
        ),
        (
            "{ config.nails.enable = true; }",
            (1, "nails", ReferenceKind::ToolName),
        ),
        ("{ }\n# NAILS\n", (2, "NAILS", ReferenceKind::ToolName)),
    ] {
        let scan = scan_configuration(content);
        assert_eq!(only_reference(&scan), expected, "{content}");
    }

    let scan = scan_configuration("{ networking.hostName = \"snails-box\"; }");
    assert!(scan.is_clean(), "{scan:#?}");
}

/// The matched text keeps the file's spelling, and every reference names its
/// file and line, in file order.
#[test]
fn references_keep_the_spelling_file_and_line() {
    let fs = host(
        &[
            (
                "/etc/nixos/modules/extra.nix",
                "{ }\n# Mounted at /MNT/DATA by hand\n",
            ),
            (
                "/etc/nixos/configuration.nix",
                "{\n  imports = [ ./modules/extra.nix ];\n  fileSystems.\"/mnt/data/nixos\".device = \"/dev/sdb1\";\n}\n",
            ),
        ],
        DATA_MOUNTINFO,
    );
    let scan = scan_at(&fs, "/mnt/data/");
    let found: Vec<_> = scan
        .references
        .iter()
        .map(|r| (r.file.to_str().unwrap(), r.line, r.text.as_str()))
        .collect();
    assert_eq!(
        found,
        [
            ("/etc/nixos/configuration.nix", 3, "/mnt/data"),
            ("/etc/nixos/modules/extra.nix", 2, "/MNT/DATA"),
        ]
    );
    assert_eq!(scan.files_read, 2);
}

#[test]
fn nothing_is_inspected_without_a_nix_file() {
    let scan = scan_at(&MockFilesystem::new(), ROOT);
    assert_eq!(scan, BaseConfigScan::default());
    assert!(scan.is_clean());
}

/// A short root such as `/data` is matched as a whole path, not as the end
/// of another one.
#[test]
fn a_short_root_matches_only_its_own_path() {
    let mountinfo = "36 35 254:0 / /data rw - ext4 /dev/mapper/vault rw\n";
    let fs = host(
        &[(
            "/etc/nixos/configuration.nix",
            "{ services.postgresql.dataDir = \"/var/lib/postgresql/data\"; }",
        )],
        mountinfo,
    );
    assert!(scan_at(&fs, "/data").is_clean());

    let fs = host(
        &[(
            "/etc/nixos/configuration.nix",
            "{ fileSystems.\"/data\".device = \"/dev/sdb1\"; }",
        )],
        mountinfo,
    );
    let scan = scan_at(&fs, "/data");
    assert_eq!(
        only_reference(&scan),
        (1, "/data", ReferenceKind::MountPoint)
    );
}

/// A pseudo source such as `tmpfs` names no device.
#[test]
fn a_root_without_a_device_has_no_device_marker() {
    let fs = host(
        &[(
            "/etc/nixos/configuration.nix",
            "{ fileSystems.\"/tmp\".fsType = \"tmpfs\"; }",
        )],
        "36 35 0:42 / /mnt/data rw - tmpfs tmpfs rw\n",
    );
    assert!(scan_at(&fs, ROOT).is_clean());
}

#[test]
fn a_custom_mount_point_is_refused_wherever_it_is() {
    let fs = host(
        &[(
            "/etc/nixos/hardware-configuration.nix",
            "{ fileSystems.\"/mnt/vault\" = { device = \"/dev/disk/by-uuid/abcd\"; }; }",
        )],
        "",
    );
    let scan = scan_at(&fs, "/mnt/vault");
    assert_eq!(
        only_reference(&scan),
        (1, "/mnt/vault", ReferenceKind::MountPoint)
    );
}

#[test]
fn the_device_of_the_hidden_root_is_refused_at_any_mount_point() {
    // The captured hidden-root scene (fixture README): the kernel's own line
    // for a filesystem from /dev/mapper/vault at "/fixture/mnt/hidden root",
    // printed with the space octal-escaped. The decoy names the device for
    // its swap, not for that mount point.
    let fs = host(
        &[(
            "/etc/nixos/hardware-configuration.nix",
            "{ swapDevices = [ { device = \"/dev/mapper/vault\"; } ]; }",
        )],
        &crate::kernel_fixtures::userns("mountinfo-hidden-root.txt"),
    );
    let scan = scan_at(&fs, "/fixture/mnt/hidden root");
    assert_eq!(
        only_reference(&scan),
        (1, "/dev/mapper/vault", ReferenceKind::Device)
    );

    // In the same scene /fixture/home is an overlay: the device backs
    // another mount, so it is no trace of that root.
    assert!(scan_at(&fs, "/fixture/home").is_clean());
}

#[test]
fn a_malformed_mountinfo_line_is_skipped() {
    let fs = host(
        &[(
            "/etc/nixos/hardware-configuration.nix",
            "{ swapDevices = [ { device = \"/dev/mapper/vault\"; } ]; }",
        )],
        "garbage line without separator\n36 35 254:0 / /mnt/vault rw - ext4 /dev/mapper/vault rw\n",
    );
    let scan = scan_at(&fs, "/mnt/vault");
    assert_eq!(
        only_reference(&scan),
        (1, "/dev/mapper/vault", ReferenceKind::Device)
    );
}

#[test]
fn an_unrelated_filesystem_entry_passes() {
    let fs = host(
        &[(
            "/etc/nixos/hardware-configuration.nix",
            "{ fileSystems.\"/\" = { device = \"/dev/sda1\"; fsType = \"ext4\"; }; }",
        )],
        "",
    );
    assert!(scan_at(&fs, "/mnt/vault").is_clean());
}

#[test]
fn every_kind_says_what_it_is_and_what_to_do() {
    for kind in [
        ReferenceKind::StagedText,
        ReferenceKind::Device,
        ReferenceKind::DeviceUnit,
        ReferenceKind::Storage,
        ReferenceKind::MountPoint,
        ReferenceKind::MountUnit,
        ReferenceKind::MapperName,
        ReferenceKind::ToolName,
    ] {
        assert!(!kind.reason().is_empty());
        assert!(
            kind.remedy().starts_with("Remove it from that file"),
            "{kind:?}"
        );
    }
    assert!(ReferenceKind::MapperName.remedy().contains("under a name"));
    assert!(ReferenceKind::MountPoint.remedy().contains("at a path"));
    assert!(ReferenceKind::MountUnit.remedy().contains("at a path"));
}
