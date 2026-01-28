{ config, lib, pkgs, ... }:

with lib;
let
  cfg = config.fudo.aegis;

  # Decrypt a secret from aegis-secrets repo
  decrypt-script = { secret-name, source-file, target-file, host-master-key
    , user, group, permissions, dry-run }:
    pkgs.writeShellScript "decrypt-aegis-secret-${secret-name}.sh"
    (if dry-run then ''
      # DRY-RUN MODE: Decrypt to /run/aegis/ and log what would be done
      mkdir -p /run/aegis
      rm -f /run/aegis/${secret-name}
      touch /run/aegis/${secret-name}
      chmod 0600 /run/aegis/${secret-name}

      # Decrypt to dry-run location
      ${pkgs.age}/bin/age -d -i ${host-master-key.key-path} -o /run/aegis/${secret-name} ${source-file}

      echo "[AEGIS DRY-RUN] Successfully decrypted: ${secret-name}"
      echo "[AEGIS DRY-RUN] Would copy to: ${target-file}"
      echo "[AEGIS DRY-RUN] Would set owner: ${user}:${group}"
      echo "[AEGIS DRY-RUN] Would set mode: ${permissions}"

      # Show first line of decrypted content (for validation)
      echo "[AEGIS DRY-RUN] Content preview:"
      head -n 1 /run/aegis/${secret-name} | sed 's/^/[AEGIS DRY-RUN]   /'
    '' else ''
      # PRODUCTION MODE: Decrypt directly to target location
      rm -f ${target-file}
      touch ${target-file}
      chown ${user}:${group} ${target-file}
      chmod ${permissions} ${target-file}

      # Decrypt to target
      ${pkgs.age}/bin/age -d -i ${host-master-key.key-path} -o ${target-file} ${source-file}

      echo "[AEGIS] Decrypted: ${secret-name} -> ${target-file}"
    '');

  # Create a systemd service for decrypting a secret
  secret-service = target-host: secret-name:
    { source-file, target-file, user, group, permissions, ... }: {
      description = if cfg.dry-run then
        "[DRY-RUN] Decrypt aegis secret ${secret-name}"
      else
        "Decrypt aegis secret ${secret-name} to ${target-file}";

      wantedBy = [ "multi-user.target" ];
      requiredBy = [ cfg.secret-target ];
      requires = [ "local-fs.target" ];
      before = [ cfg.secret-target ];
      after = [ "local-fs.target" ];
      restartIfChanged = true;

      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;

        # Prepare target directory
        ExecStartPre =
          pkgs.writeShellScript "aegis-secret-prep-${secret-name}.sh" ''
            TARGET_DIR=${dirOf target-file}
            if [ ! -d "$TARGET_DIR" ]; then
              mkdir -p "$TARGET_DIR"
              chown ${user}:${group} "$TARGET_DIR"
              chmod ${
                if (group == "root") then "0550" else "0750"
              } "$TARGET_DIR"
            fi
          '';

        # Decrypt the secret
        ExecStart =
          let host-master-key = config.fudo.hosts."${target-host}".master-key;
          in decrypt-script {
            inherit secret-name source-file target-file host-master-key user
              group permissions;
            dry-run = cfg.dry-run;
          };

        # Cleanup (only in production mode)
        ExecStop = if cfg.dry-run then
          pkgs.writeShellScript "aegis-cleanup-${secret-name}.sh" ''
            echo "[AEGIS DRY-RUN] Would remove ${target-file}"
            rm -f /run/aegis/${secret-name}
          ''
        else
          pkgs.writeShellScript "aegis-cleanup-${secret-name}.sh" ''
            rm -f ${target-file}
          '';
      };

      path = [ pkgs.age ];
    };

  # Secret options submodule
  secretOpts = { name, ... }: {
    options = with types; {
      source-file = mkOption {
        type = path;
        description = "Path to encrypted .age file in aegis-secrets repo";
      };

      target-file = mkOption {
        type = str;
        description =
          "Target file path on the host where secret will be decrypted";
      };

      user = mkOption {
        type = str;
        description = "User (on target host) to which the file will belong";
        default = "root";
      };

      group = mkOption {
        type = str;
        description = "Group (on target host) to which the file will belong";
        default = "root";
      };

      permissions = mkOption {
        type = str;
        description =
          "Permissions to set on the target file (e.g., 0400, 0600)";
        default = "0400";
      };

      service = mkOption {
        type = str;
        description = "Systemd service name for decrypting this secret";
        default = "aegis-secret-${name}.service";
      };
    };
  };

in {
  options.fudo.aegis = with types; {
    enable = mkOption {
      type = bool;
      description = "Enable aegis secrets management";
      default = false;
    };

    dry-run = mkOption {
      type = bool;
      description = ''
        Dry-run mode: decrypt secrets to /run/aegis/ and log actions
        without actually deploying to target locations. Use this for
        testing before switching to production mode.
      '';
      default = true;
    };

    secrets-repo = mkOption {
      type = path;
      description = "Path to aegis-secrets repository";
      example = "/path/to/aegis-secrets";
    };

    host-secrets = mkOption {
      type = attrsOf (attrsOf (submodule secretOpts));
      description = ''
        Map of hostname to secret name to secret configuration.

        Example:
          host-secrets.lambda = {
            ssh-keys = {
              source-file = "\${secrets-repo}/build/hosts/lambda/ssh-keys.age";
              target-file = "/run/openssh/private/ssh-keys";
            };
            nexus-key = {
              source-file = "\${secrets-repo}/build/hosts/lambda/nexus-key.age";
              target-file = "/run/nexus/client.key";
              user = "nexus";
              group = "nexus";
            };
          };
      '';
      default = { };
    };

    secret-target = mkOption {
      type = str;
      description = "Systemd target indicating all aegis secrets are available";
      default = "aegis-secrets.target";
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = hasAttr "hosts" config.fudo;
        message =
          "fudo.aegis requires fudo.hosts to be defined (from fudo-entities)";
      }
      {
        assertion = config.instance.hostname != "";
        message = "fudo.aegis requires instance.hostname to be set";
      }
    ];

    # Show warning if in dry-run mode
    warnings = optional cfg.dry-run
      "Aegis secrets are in DRY-RUN mode! Secrets will be decrypted to /run/aegis/ for validation only.";

    systemd = let
      hostname = config.instance.hostname;

      # Get secrets for this host
      host-secrets = if (hasAttr hostname cfg.host-secrets) then
        cfg.host-secrets.${hostname}
      else
        { };

      # Create systemd services for each secret
      host-secret-services = let
        strip-service = service-name:
          let match = builtins.match "^(.+)[.]service$" service-name;
          in if match != null then head match else service-name;
      in mapAttrs' (secret: secretOpts:
        (nameValuePair (strip-service secretOpts.service)
          (secret-service hostname secret secretOpts))) host-secrets;

      # Create tmpfiles rules for secret directories
      host-secret-paths = mapAttrsToList (secret: secretOpts:
        let
          perms = if secretOpts.group != "root" then "0750" else "0550";
          target-dir = dirOf secretOpts.target-file;
        in "d ${target-dir} ${perms} ${secretOpts.user} ${secretOpts.group} - -")
        host-secrets;

    in {
      # Tmpfiles rules for creating directories
      tmpfiles.rules = unique host-secret-paths;

      # Services for decrypting secrets
      services = host-secret-services;

      # Target that indicates all secrets are ready
      targets = let
        strip-ext = filename:
          let match = builtins.match "^(.+)[.]target$" filename;
          in if match != null then head match else filename;
      in {
        ${strip-ext cfg.secret-target} = {
          description = if cfg.dry-run then
            "[DRY-RUN] Aegis secrets validated and ready"
          else
            "Aegis secrets decrypted and ready";
          wantedBy = [ "multi-user.target" ];
        };
      };
    };

    # Create /run/aegis directory for dry-run mode
    systemd.tmpfiles.rules =
      mkIf cfg.dry-run [ "d /run/aegis 0750 root root - -" ];
  };
}
