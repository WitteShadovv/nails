{ pkgs }:

let
  inherit (pkgs) lib;

  normalize =
    value:
    let
      lower = lib.toLower value;
      cleaned = builtins.replaceStrings [ "/" "_" " " "." ] [ "-" "-" "-" "-" ] lower;
    in
    lib.strings.sanitizeDerivationName cleaned;

  mkDigest =
    values: builtins.substring 0 16 (builtins.hashString "sha256" (lib.concatStringsSep ":" values));
in
rec {
  inherit normalize;

  mkNamespace =
    {
      scenarioId,
      profileId,
      lane ? "default",
    }:
    let
      digest = mkDigest [
        (normalize scenarioId)
        (normalize profileId)
        (normalize lane)
      ];
    in
    "nails-feval-${digest}";

  mkToken = { namespace, label }: "${namespace}-${normalize label}";

  mkSet =
    {
      scenarioId,
      profileId,
      lane ? "default",
      labels ? [
        "document"
        "history"
        "tmp"
        "nested"
        "filename"
      ],
    }:
    let
      namespace = mkNamespace { inherit scenarioId profileId lane; };
    in
    {
      inherit
        lane
        labels
        namespace
        profileId
        scenarioId
        ;
      tokens = builtins.listToAttrs (
        map (
          label:
          lib.nameValuePair label (mkToken {
            inherit namespace label;
          })
        ) labels
      );
    };
}
