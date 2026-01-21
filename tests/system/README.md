# System Tests (Phase 2 - Optional)

This directory contains system-level tests for forensic validation and performance benchmarking.

⚠️ **These tests are optional for Phase 1 (thesis deliverable).** Unit + integration tests provide sufficient validation for thesis defense.

## Forensic Validation Tests (`forensic/`)

**Objective:** Validate RQ1 (forensic undetectability)

**Requirements:**
- Privileged Docker/Podman container
- Forensic tool suite (Autopsy, Sleuth Kit, Volatility)
- Test VM image

**Running:**
```bash
./forensic/validation.sh
```

## Performance Benchmarks (`benchmarks/`)

**Objective:** Validate RQ2 (2-5 second switching performance)

**Requirements:**
- Criterion benchmarking framework
- Consistent hardware specs

**Running:**
```bash
cd ../.. && cargo bench
```

## Setup Instructions

### Docker Container for Forensic Tests

```dockerfile
FROM nixos/nix:latest

# Install forensic tools
RUN nix-env -iA nixpkgs.autopsy
RUN nix-env -iA nixpkgs.sleuthkit
RUN nix-env -iA nixpkgs.volatility3

# Install NAILS
COPY target/release/nails /usr/local/bin/nails

CMD ["./tests/system/forensic/validation.sh"]
```

**Build and run:**
```bash
docker build -t nails-forensic-test .
docker run --privileged nails-forensic-test
```

### VM Image Setup

1. Create clean NixOS VM
2. Take snapshot: `qemu-img snapshot -c clean-state vm.qcow2`
3. Set environment variable: `export NAILS_FORENSIC_VM_IMAGE=/path/to/vm.qcow2`

## Phase 1 vs Phase 2

**Phase 1 (Thesis Minimum):**
- ✅ Unit tests (100% coverage)
- ✅ Integration tests (command flows)
- ⚠️ System tests are **optional**

**Phase 2 (Full Validation):**
- ✅ All Phase 1 tests
- ✅ Forensic validation (RQ1 strongest evidence)
- ✅ Performance benchmarks (RQ2 validation)

## Expected Results

### Forensic Validation Pass Criteria

```
✅ Autopsy: 0 traces detected
✅ Sleuth Kit: 0 traces detected  
✅ Volatility: Minimal RAM traces (acceptable within documented threat model)

Pass: 0% detection rate
```

### Performance Benchmark Pass Criteria

```
✅ Activation (after build): p95 < 5.0s
✅ Emergency deactivation: p95 < 3.0s
✅ Status query: p95 < 500ms

Pass: All targets met
```
