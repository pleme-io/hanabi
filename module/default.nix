# Hanabi home-manager module — daemon service
#
# Namespace: services.hanabi.daemon.*
#
# Runs hanabi as a persistent BFF/gateway service for local development.
# Hanabi reads its config from a YAML file (CONFIG_PATH env var).
#
# Module factory: receives { hmHelpers } from flake.nix, returns HM module.
{ hmHelpers }:
{
  lib,
  config,
  pkgs,
  ...
}:
with lib; let
  inherit (hmHelpers) mkLaunchdService mkSystemdService;
  cfg = config.services.hanabi.daemon;
  isDarwin = pkgs.stdenv.isDarwin;
in {
  options.services.hanabi.daemon = {
    enable = mkOption {
      type = types.bool;
      default = false;
      description = "Enable Hanabi BFF/gateway service";
    };

    package = mkOption {
      type = types.package;
      default = pkgs.hanabi;
      description = "Hanabi package";
    };

    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to hanabi config.yaml";
    };

    logLevel = mkOption {
      type = types.str;
      default = "hanabi=info";
      description = "RUST_LOG filter string";
    };

    extraEnv = mkOption {
      type = types.attrsOf types.str;
      default = {};
      description = "Additional environment variables (REDIS_SESSION_PASSWORD, HMAC_SECRET, NATS_URL, etc.)";
    };
  };

  config = let
    env = {
      RUST_LOG = cfg.logLevel;
    }
    // optionalAttrs (cfg.configFile != null) { CONFIG_PATH = toString cfg.configFile; }
    // cfg.extraEnv;
  in mkMerge [
    (mkIf (cfg.enable && isDarwin)
      (mkLaunchdService {
        name = "hanabi";
        label = "io.pleme.hanabi";
        command = "${cfg.package}/bin/hanabi";
        inherit env;
        logDir = "${config.home.homeDirectory}/Library/Logs";
      }))

    (mkIf (cfg.enable && !isDarwin)
      (mkSystemdService {
        name = "hanabi";
        description = "Hanabi BFF/gateway service";
        command = "${cfg.package}/bin/hanabi";
        inherit env;
      }))
  ];
}
