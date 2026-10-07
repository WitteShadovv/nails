{
  detectTcgThresholdMultiplierFn = ''
    def detect_tcg_threshold_multiplier():
        cpu_model = machine.succeed("cat /proc/cpuinfo").strip()
        is_tcg = "QEMU TCG" in cpu_model
        return is_tcg, (3.0 if is_tcg else 1.0)
  '';

  # Times a command inside the guest. A host-side clock would also count the
  # round trip through the driver's shell and any stall of the host, which
  # on a shared runner can dwarf what is being measured.
  guestElapsedMsFn = ''
    def guest_elapsed_ms(command):
        import shlex

        script = (
            "set -e; start=$(date +%s%N); "
            + command
            + " > /dev/null; end=$(date +%s%N); echo $(( (end - start) / 1000000 ))"
        )
        return int(machine.succeed("bash -c " + shlex.quote(script)).strip().splitlines()[-1])
  '';
}
