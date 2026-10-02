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

  # nails times its own operations and logs the result as duration_ms:
  # `activate --json` streams an activation_complete event carrying it, and
  # every completed teardown logs a "Deactivation complete" line with it.
  nailsDurationFns = ''
    def activation_duration_ms(ndjson):
        import json

        for line in ndjson.splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            event = json.loads(line)
            if event.get("event") == "activation_complete" and "duration_ms" in event:
                return int(event["duration_ms"])
        raise AssertionError(
            "activate --json streamed no activation_complete event with duration_ms:\n" + ndjson
        )

    def deactivation_duration_ms(log_text):
        import re

        plain = re.sub(r"\x1b\[[0-9;]*m", "", log_text)
        for line in plain.splitlines():
            if "Deactivation complete" not in line:
                continue
            match = re.search(r"\bduration_ms=(\d+)", line)
            if match:
                return int(match.group(1))
        return None
  '';
}
