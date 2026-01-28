# Aegis System Administration Tools

Command-line tools for managing Aegis encrypted secrets. Used by system administrators to build and manage secrets for infrastructure hosts.

## Installation

### NixOS (Recommended)

Add to your flake inputs:

```nix
{
  inputs = {
    aegis-tools-system.url = "github:fudoniten/aegis-tools-system";
  };
}
```

Then either:

1. **Add to environment.systemPackages:**
   ```nix
   environment.systemPackages = [ inputs.aegis-tools-system.packages.${system}.default ];
   ```

2. **Use the overlay:**
   ```nix
   nixpkgs.overlays = [ inputs.aegis-tools-system.overlays.default ];
   environment.systemPackages = [ pkgs.aegis ];
   ```

3. **Run directly:**
   ```bash
   nix run github:fudoniten/aegis-tools-system -- --help
   ```

### Development

```bash
git clone https://github.com/fudoniten/aegis-tools-system
cd aegis-tools-system
nix develop
```

## Usage

```bash
aegis --help
```

### Finding the Secrets Repository

The `aegis` command needs to know where your `aegis-secrets` repository is. It searches in this order:

1. **`--secrets-path` argument** - Explicit path
2. **`AEGIS_SYSTEM` environment variable** - Set this to your secrets repo path
3. **Current directory** - If it looks like a secrets repo
4. **Relative paths** - `./aegis-secrets` or `../aegis-secrets`

If none of these work, you'll see an error with instructions.

### Common Commands

```bash
# Show status of all secrets
aegis status

# Initialize a new host
aegis init-host myhost --services=host,ssh

# Import existing secrets
aegis import-ssh-key lambda --key /secure/lambda.ed25519.key --key /secure/lambda.ecdsa.key
aegis import-nexus-key lambda --file /secure/lambda.nexus.hmac
aegis import-kerberos-realm SEA.FUDO.ORG --realm-key /secure/realm.key --principals-dir /secure/principals/

# Add a user with access to specific hosts
aegis add-user alice --hosts=host1,host2

# Build all secrets (SSH keys, Nexus keys, keytabs, user secrets)
aegis build

# Build specific types
aegis build-ssh-keys
aegis build-nexus-keys
aegis build-keytabs
aegis build-user-secrets

# Initialize a Kerberos realm
aegis init-realm EXAMPLE.ORG

# Create a role (e.g., KDC)
aegis init-role kdc kdchost

# List secrets for a host
aegis list myhost

# Verify secrets are properly formatted
aegis verify myhost
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AEGIS_SYSTEM` | Path to aegis-secrets repository |
| `AEGIS_SCRIPTS` | Path to Kerberos scripts (set automatically by Nix) |

## Commands Reference

### Build Commands

| Command | Description |
|---------|-------------|
| `aegis build` | Run full build (SSH keys, Nexus keys, keytabs, user secrets) |
| `aegis build-ssh-keys` | Generate SSH host keys |
| `aegis build-nexus-keys` | Generate Nexus DDNS authentication keys |
| `aegis build-keytabs` | Generate Kerberos keytabs |
| `aegis build-user-secrets` | Process user secrets from user repos |

### Import Commands

| Command | Description |
|---------|-------------|
| `aegis import-ssh-key <host>` | Import SSH private keys (derives public keys) |
| `aegis import-nexus-key <host>` | Import Nexus DDNS authentication key |
| `aegis import-kerberos-realm <REALM>` | Import Kerberos realm with principals |
| `aegis import-secret <host> <name>` | Import generic secret with metadata |

### Configuration Commands

| Command | Description |
|---------|-------------|
| `aegis init-host <hostname>` | Add a new host to configuration |
| `aegis add-user <username>` | Add a user and generate their keypair |
| `aegis add-secret <host> <name> <file>` | Add a custom secret for a host |
| `aegis init-realm <REALM>` | Initialize a Kerberos realm |
| `aegis init-role <role> <host>` | Create a role and assign to host |

### Utility Commands

| Command | Description |
|---------|-------------|
| `aegis status` | Show what needs building |
| `aegis list [host]` | List secrets for host(s) |
| `aegis verify <host>` | Verify secrets are valid |

## Architecture

This tool manages the `aegis-secrets` repository:

```
aegis-secrets/
├── src/                    # Source configuration
│   ├── hosts/*.toml        # Host configs
│   ├── users/*.toml        # User configs
│   ├── roles/*.toml        # Role configs
│   └── kerberos/realms/    # Kerberos realm data
├── keys/                   # Encrypted keys
│   ├── admin.pub           # Admin public key
│   └── users/*.age         # User private keys
└── build/                  # Generated output
    ├── hosts/<host>/       # Per-host secrets
    └── roles/<role>/       # Per-role secrets
```

## See Also

- [aegis](../aegis) - NixOS modules for secret decryption
- [aegis-tools-user](../aegis-tools-user) - User CLI for managing personal secrets
- [aegis-secrets](../aegis-secrets) - Example secrets repository
