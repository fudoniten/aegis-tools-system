# Aegis Migration Guide: From fudo-secrets to aegis

This guide covers the complete migration from `fudo-secrets` to `aegis` secrets management.

## Overview

Aegis provides a modern Python-based secrets management system to replace the Nix-heavy `fudo-secrets` approach. The migration will happen in parallel, with both systems running simultaneously until full validation is complete.

## Migration Strategy

### Phase 1: Import Existing Secrets
### Phase 2: Parallel Deployment (Dry-Run)
### Phase 3: Validation & Testing
### Phase 4: Production Cutover
### Phase 5: Cleanup

---

## Phase 1: Import Existing Secrets

### Prerequisites

1. **Secure storage location** with your unencrypted secrets
2. **aegis-secrets repository** initialized
3. **Admin key** in `aegis-secrets/keys/admin.pub`
4. **fudo-entities** repository at `/net/projects/niten/nix-entities`

### Import SSH Keys

For each host, import SSH private keys (key types and public keys auto-detected):

```bash
aegis import-ssh-key <hostname> \
  --key /secure/storage/<hostname>.ed25519.key \
  --key /secure/storage/<hostname>.ecdsa.key \
  --key /secure/storage/<hostname>.rsa.key \
  --secrets-path ./aegis-secrets \
  --entities-path /net/projects/niten/nix-entities
```

**Example:**
```bash
aegis import-ssh-key lambda \
  --key /secure/lambda.ed25519.key \
  --key /secure/lambda.ecdsa.key
```

**What happens:**
- Auto-detects key type (ed25519, ecdsa, or rsa)
- Validates each private key
- Derives public keys automatically
- Creates `src/hosts/lambda.toml` if it doesn't exist (from entities)
- Encrypts keys with host master key + admin key
- Stores in `build/hosts/lambda/ssh-keys.age`

### Import Nexus Keys

```bash
aegis import-nexus-key <hostname> \
  --file /secure/storage/<hostname>.nexus.hmac \
  --secrets-path ./aegis-secrets \
  --entities-path /net/projects/niten/nix-entities
```

**Example:**
```bash
aegis import-nexus-key lambda \
  --file /secure/lambda.nexus.hmac
```

**Key format expected:** `HmacSHA512:base64encodedkey`

### Import Kerberos Realms

```bash
aegis import-kerberos-realm <REALM> \
  --realm-key /secure/storage/realms/<REALM>/realm.key \
  --principals-dir /secure/storage/realms/<REALM>/principals/ \
  --secrets-path ./aegis-secrets
```

**Example:**
```bash
aegis import-kerberos-realm SEA.FUDO.ORG \
  --realm-key /secure/sea-fudo-org/realm.key \
  --principals-dir /secure/sea-fudo-org/principals/
```

**Structure expected:**
```
/secure/sea-fudo-org/
  realm.key
  principals/
    krbtgt_SEA.FUDO.ORG.key
    host_lambda.sea.fudo.org.key
    ssh_lambda.sea.fudo.org.key
```

### Import Custom Secrets

For service-specific or custom secrets:

```bash
aegis import-secret <hostname> <secret-name> \
  --file /secure/storage/<secret-file> \
  --target /run/service/secret.conf \
  --user myservice \
  --group myservice \
  --mode 0600 \
  --secrets-path ./aegis-secrets \
  --entities-path /net/projects/niten/nix-entities
```

**Example:**
```bash
aegis import-secret lambda postgresql-password \
  --file /secure/lambda-postgres.passwd \
  --target /run/postgresql/password \
  --user postgres \
  --group postgres \
  --mode 0400
```

### Batch Import Script

Create a script to import all secrets at once:

```bash
#!/usr/bin/env bash
set -euo pipefail

SECURE_DIR="/path/to/secure/storage"
SECRETS_REPO="/path/to/aegis-secrets"
ENTITIES="/net/projects/niten/nix-entities"

# Import SSH keys for all hosts
for host in lambda nostromo legatus; do
  echo "Importing SSH keys for $host..."
  aegis import-ssh-key "$host" \
    --key "$SECURE_DIR/ssh/$host.ed25519.key" \
    --key "$SECURE_DIR/ssh/$host.ecdsa.key" \
    --secrets-path "$SECRETS_REPO" \
    --entities-path "$ENTITIES"
done

# Import Nexus keys
for host in lambda nostromo legatus; do
  echo "Importing Nexus key for $host..."
  aegis import-nexus-key "$host" \
    --file "$SECURE_DIR/nexus/$host.hmac" \
    --secrets-path "$SECRETS_REPO" \
    --entities-path "$ENTITIES"
done

# Import Kerberos realms
for realm in SEA.FUDO.ORG FUDO.ORG; do
  echo "Importing Kerberos realm $realm..."
  aegis import-kerberos-realm "$realm" \
    --realm-key "$SECURE_DIR/kerberos/realms/$realm/realm.key" \
    --principals-dir "$SECURE_DIR/kerberos/realms/$realm/principals/" \
    --secrets-path "$SECRETS_REPO"
done

echo "Import complete!"
```

---

## Phase 2: Parallel Deployment (Dry-Run)

### Add Aegis to NixOS Config

In `nixos-config/flake.nix`:

```nix
{
  inputs = {
    # ... existing inputs ...
    
    aegis-tools = {
      url = "github:fudoniten/aegis-tools-system";  # or path:/path/to/aegis-tools-system
      inputs.nixpkgs.follows = "nixpkgs";
    };
    
    aegis-secrets = {
      url = "path:/path/to/aegis-secrets";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, aegis-tools, aegis-secrets, ... }@inputs: {
    # ... in your host configuration ...
    nixosConfigurations.lambda = nixpkgs.lib.nixosSystem {
      modules = [
        aegis-tools.nixosModules.default  # Import aegis module
        {
          fudo.aegis = {
            enable = true;
            dry-run = true;  # IMPORTANT: Start in dry-run mode!
            secrets-repo = aegis-secrets;
          };
        }
        # ... other modules ...
      ];
    };
  };
}
```

### Define Secrets for Services

For each service that uses secrets, add aegis definitions **alongside** existing fudo-secrets definitions:

**Example: Nexus Service**

```nix
# config/service/nexus.nix
{ config, lib, pkgs, ... }:

let
  hostname = config.instance.hostname;
  hostSecrets = config.fudo.secrets.host-secrets."${hostname}";
  
  # Check if running aegis
  useAegis = config.fudo.aegis.enable or false;
in {
  # Keep existing fudo-secrets definition
  fudo.secrets.host-secrets."${hostname}".nexus-key = {
    source-file = config.fudo.secrets.files.nexus-hmacs."${hostname}";
    target-file = "/run/nexus/client.key";
  };
  
  # Add parallel aegis definition
  fudo.aegis.host-secrets."${hostname}".nexus-key = lib.mkIf useAegis {
    source-file = "${config.fudo.aegis.secrets-repo}/build/hosts/${hostname}/nexus-key.age";
    target-file = "/run/nexus/client.key";
    user = "nexus";
    group = "nexus";
    permissions = "0400";
  };
  
  # Service depends on BOTH targets during transition
  systemd.services.nexus-client = {
    after = [ "fudo-secrets.target" ] ++ lib.optional useAegis "aegis-secrets.target";
    requires = [ "fudo-secrets.target" ] ++ lib.optional useAegis "aegis-secrets.target";
  };
}
```

### Deploy and Observe

```bash
# Build and deploy to test host
nixos-rebuild switch --flake .#lambda

# After deployment, check systemd services
systemctl status aegis-secrets.target
systemctl list-dependencies aegis-secrets.target

# Check dry-run output
journalctl -u 'aegis-secret-*' -n 100

# Verify decrypted secrets in /run/aegis/
ls -la /run/aegis/
cat /run/aegis/nexus-key  # Should show decrypted content
```

**Expected log output:**
```
[AEGIS DRY-RUN] Successfully decrypted: nexus-key
[AEGIS DRY-RUN] Would copy to: /run/nexus/client.key
[AEGIS DRY-RUN] Would set owner: nexus:nexus
[AEGIS DRY-RUN] Would set mode: 0400
[AEGIS DRY-RUN] Content preview:
[AEGIS DRY-RUN]   HmacSHA512:dGVzdGtleQ==...
```

---

## Phase 3: Validation & Testing

### Validate Decrypted Secrets

Compare aegis-decrypted secrets with fudo-secrets:

```bash
# On the host
diff /run/aegis/nexus-key /run/nexus/client.key
diff /run/aegis/ssh-keys /run/openssh/private/ssh-keys

# Should be identical!
```

### Test Service Functionality

1. **Ensure services still work** (they're using fudo-secrets)
2. **Manually test with aegis secrets:**
   ```bash
   # Example: Test SSH with aegis keys
   cp /run/aegis/ssh-keys /tmp/test-keys
   # ... test functionality ...
   ```

3. **Check all expected secrets are present:**
   ```bash
   ls -la /run/aegis/
   # Should see: nexus-key, ssh-keys, etc.
   ```

---

## Phase 4: Production Cutover

### Per-Service Migration

Migrate one service at a time for safety:

#### 1. Choose a Non-Critical Service First

Example: Nexus on a test host

#### 2. Switch to Production Mode

```nix
# In host configuration
fudo.aegis = {
  enable = true;
  dry-run = false;  # PRODUCTION MODE!
  secrets-repo = aegis-secrets;
};
```

#### 3. Remove fudo-secrets Definition

```nix
# Comment out or remove fudo-secrets definition
# fudo.secrets.host-secrets."${hostname}".nexus-key = { ... };

# Keep only aegis definition
fudo.aegis.host-secrets."${hostname}".nexus-key = {
  source-file = "${config.fudo.aegis.secrets-repo}/build/hosts/${hostname}/nexus-key.age";
  target-file = "/run/nexus/client.key";
  user = "nexus";
  group = "nexus";
  permissions = "0400";
};
```

#### 4. Deploy and Test

```bash
nixos-rebuild switch --flake .#lambda
systemctl status nexus-client
# Verify service works with aegis secrets!
```

#### 5. Roll Out to All Hosts

Once validated on test host, deploy to all hosts for that service.

### Full Migration Checklist

- [ ] SSH keys migrated and tested
- [ ] Nexus keys migrated and tested
- [ ] Kerberos keytabs migrated and tested
- [ ] Service-specific secrets migrated and tested
- [ ] All hosts updated to `dry-run = false`
- [ ] All `fudo.secrets.host-secrets` definitions removed
- [ ] Services only depend on `aegis-secrets.target`

---

## Phase 5: Cleanup

Once fully migrated and stable:

### 1. Remove fudo-secrets

```nix
# In nixos-config/flake.nix, remove:
# - fudo-secrets input
# - fudo-secrets module imports
```

### 2. Archive Old Secrets

```bash
# DON'T DELETE! Archive for safety
cd /net/projects/niten
mv fudo-secrets fudo-secrets.archive.$(date +%Y%m%d)
```

### 3. Update Documentation

- Update deployment docs to use aegis
- Update secrets rotation procedures
- Document aegis workflow for new services

---

## Troubleshooting

### Decryption Fails

**Error:** `age: error: no identity matched any of the recipients`

**Solution:** Ensure host master key matches between entities and on-host key.

```bash
# On host
cat /path/to/master-key-location  # Check key path from entities

# Verify it can decrypt
age -d -i /path/to/master-key < /run/aegis-secrets/build/hosts/hostname/secret.age
```

### Secrets Not Found

**Error:** Service starts before `aegis-secrets.target`

**Solution:** Add proper systemd dependencies:

```nix
systemd.services.my-service = {
  after = [ "aegis-secrets.target" ];
  requires = [ "aegis-secrets.target" ];
};
```

### Permission Denied

**Error:** Service can't read secret file

**Solution:** Check ownership and permissions in aegis config:

```nix
fudo.aegis.host-secrets."${hostname}".my-secret = {
  user = "my-service-user";
  group = "my-service-group";
  permissions = "0400";  # or "0440" for group-readable
};
```

---

## Quick Reference

### Import Commands

```bash
# SSH keys (type and pubkey auto-detected)
aegis import-ssh-key <host> --key <path> --key <path>

# Nexus keys
aegis import-nexus-key <host> --file <path>

# Kerberos realms
aegis import-kerberos-realm <REALM> --realm-key <path> --principals-dir <path>

# Generic secrets
aegis import-secret <host> <name> --file <path> --target <path> --user <user> --group <group> --mode <mode>
```

### Build Commands

```bash
# Generate new secrets
aegis build                      # Build all
aegis build-ssh-keys             # Just SSH
aegis build-nexus-keys           # Just Nexus
aegis build-keytabs              # Just Kerberos
```

### NixOS Configuration

```nix
fudo.aegis = {
  enable = true;
  dry-run = true;  # false for production
  secrets-repo = aegis-secrets;
  
  host-secrets."${hostname}".<secret-name> = {
    source-file = "${config.fudo.aegis.secrets-repo}/build/hosts/${hostname}/<file>.age";
    target-file = "/run/service/secret";
    user = "service-user";
    group = "service-group";
    permissions = "0400";
  };
};
```

---

## Support

For issues or questions:
1. Check logs: `journalctl -u 'aegis-secret-*'`
2. Verify dry-run output: `cat /run/aegis/<secret-name>`
3. Compare with fudo-secrets: `diff /run/aegis/<secret> /run/fudo/<secret>`
