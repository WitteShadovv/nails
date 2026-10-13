# The VM-only contract tests, one VM boot for both.
#
# verify-json-schema (verify JSON across scan modes) and
# contract-active-session (active-session JSON, ASCII rendering and colour on a
# real TTY) were single-boot tests with the same node: the standard decoy VM
# plus nails and a Python with jsonschema to validate against the committed
# schemas. Their node derivations were identical, and this test declares that
# node unchanged. Each runs as a scenario (lib/batch.nix): it starts from a
# guest as clean as it booted and the guest is reset before the next one.
# contract-active-session activates, so it runs last. The old test names stay
# aliases of this test.

args@{ self, pkgs, ... }:
let
  batch = import ./../../lib/batch.nix { inherit (pkgs) lib; };
  scenario = path: import path args;
  pythonWithJsonschema = pkgs.python3.withPackages (ps: [ ps.jsonschema ]);
in
batch.mkBatch {
  name = "contract-json-schema";
  tags = [ "contract" ];

  nodes.machine =
    { ... }:
    {
      imports = [ ./../../lib/vm-config.nix ];
      environment.systemPackages = [
        self.packages.x86_64-linux.nails
        pythonWithJsonschema
      ];
    };

  scenarios = map scenario [
    ./../../scenarios/contract/59-verify-json-schema.nix
    ./../../scenarios/contract/58-contract-active-session.nix
  ];
}
