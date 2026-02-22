# Hanabi NixOS module — system-level service
#
# Namespace: services.hanabi.*
{ config, lib, pkgs, ... }:
with lib; let
  cfg = config.services.hanabi;
in {
  options.services.hanabi = {
    enable = mkEnableOption "Hanabi BFF/gateway service";

    package = mkPackageOption pkgs "hanabi" {};

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

  config = mkIf cfg.enable {
    systemd.services.hanabi = {
      description = "Hanabi BFF/gateway service";
      after = ["network.target"];
      wantedBy = ["multi-user.target"];
      serviceConfig = {
        ExecStart = "${cfg.package}/bin/hanabi";
        DynamicUser = true;
        Restart = "on-failure";
        RestartSec = 5;
        ProtectSystem = "strict";
        ProtectHome = true;
        NoNewPrivileges = true;
      };
      environment = {
        RUST_LOG = cfg.logLevel;
      }
      // optionalAttrs (cfg.configFile != null) { CONFIG_PATH = toString cfg.configFile; }
      // cfg.extraEnv;
    };
  };
}
