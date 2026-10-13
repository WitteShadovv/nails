# Persona E2E fixtures

The persona-separation tests (`nix/e2e-tests/tests/persona/`) pair two Syncthing
instances across a `client` and a `peer` node to reproduce remote-state
pull-back. A Syncthing device identity is an X.509 key pair whose device ID is the
base32 Luhn digest of the certificate's DER encoding, so a "pre-generated" key is
only meaningful once Syncthing itself has produced a valid certificate.

Rather than commit opaque key material, each node lets its own Syncthing generate
a certificate on first boot, and the test reads the two device IDs over the REST
API and pairs the nodes at runtime (`lib/persona-helpers.nix`,
`syncClientHelpersFn`). Discovery, relaying and usage reporting are disabled, so
the only traffic is between the two test nodes over the test network. The pairing
is fully scripted and deterministic within a run; only the key bytes differ
between runs, which does not affect what the tests assert.

If a future change needs byte-stable device IDs (for example to pin a folder
password or to pair declaratively through the NixOS module), regenerate the key
pairs with `syncthing generate --home <dir>` on a trusted machine and commit the
`cert.pem` / `key.pem` pairs here, then wire them in through
`services.syncthing.cert` / `.key` and replace the runtime pairing with the
device IDs printed by `syncthing --device-id --home <dir>`.
