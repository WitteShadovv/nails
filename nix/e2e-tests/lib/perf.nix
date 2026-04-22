{
  detectTcgThresholdMultiplierFn = ''
    def detect_tcg_threshold_multiplier():
        cpu_model = machine.succeed("cat /proc/cpuinfo").strip()
        is_tcg = "QEMU TCG" in cpu_model
        return is_tcg, (3.0 if is_tcg else 1.0)
  '';

  p95Fn = ''
    def p95(values):
        assert values, "p95() requires at least one sample"
        sorted_values = sorted(values)
        return sorted_values[int((len(sorted_values) - 1) * 0.95)]
  '';

  p99Fn = ''
    def p99(values):
        assert values, "p99() requires at least one sample"
        sorted_values = sorted(values)
        return sorted_values[int((len(sorted_values) - 1) * 0.99)]
  '';
}
