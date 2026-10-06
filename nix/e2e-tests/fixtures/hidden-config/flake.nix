{
  description = "NAILS real-rebuild E2E hidden configuration";

  # No inputs: the hidden system toplevel is not evaluated in the guest. A real
  # in-VM NixOS evaluation offline is not feasible without reproducing the test
  # framework's own modules, so instead the test VM declares a `nails-hidden`
  # specialisation (the running system plus fixtures/hidden-config/module.nix).
  # That specialisation's toplevel is built on the host together with the VM, so
  # it is already in the guest store. `@toplevel@` is replaced at test time with
  # its resolved `/nix/store/…-nixos-system-*` path; `builtins.storePath` keeps
  # the flake a bare realise of that existing path (no nixpkgs evaluation, no
  # build, no fetch) and only needs `--impure`, which nails' `nix build` already
  # passes.
  #
  # Because the hidden system is the VM system plus a marker module, switching to
  # it leaves the test framework's instrumentation (the driver backdoor, the
  # qemu-vm filesystems) in place, where a bare from-scratch system would have
  # had switch-to-configuration stop the backdoor and unmount those filesystems.
  outputs =
    { ... }:
    {
      nixosConfigurations.nails-e2e.config.system.build.toplevel = builtins.storePath "@toplevel@";
    };
}
