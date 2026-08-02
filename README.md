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
aegis import-ssh-host-keys lambda --key /secure/lambda.ed25519.key --key /secure/lambda.ecdsa.key
aegis import-nexus-key lambda --file /secure/lambda.nexus.hmac
aegis realm import SEA.FUDO.ORG --realm-key /secure/realm.key --principals-dir /secure/principals/ --domain sea.fudo.org

# Add a user with access to specific hosts
aegis add-user alice --hosts=host1,host2

# Build all secrets (SSH keys, Nexus keys, keytabs, user secrets)
aegis build

# Build specific types
aegis build-role-keys
aegis build-ssh-host-keys
aegis build-nexus-keys
aegis build-keytabs
aegis build-user-secrets

# Report drift between src/ and deploy/ (changes nothing, exits 1 on errors)
aegis check

# Repair recipient drift without touching key material
aegis reencrypt --host myhost

# Kerberos realms
aegis realm init EXAMPLE.ORG --domain example.org
aegis realm list
aegis realm show EXAMPLE.ORG
aegis realm add-principal EXAMPLE.ORG postgres/db.example.org --host db
aegis realm trust EXAMPLE.ORG OTHER.ORG
aegis realm export EXAMPLE.ORG

# Create a role (e.g., KDC)
aegis init-role kdc
aegis add-host-to-role kdc kdchost

# Declare where a decrypted secret belongs
aegis set-placement myhost keytab --target /etc/krb5.keytab --mode 0600

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
| `aegis build` | Run full build (role keys, SSH keys, Nexus keys, keytabs, user secrets) |
| `aegis build-role-keys` | Give each role member its copy of the role key |
| `aegis build-ssh-host-keys` | Generate SSH host keys |
| `aegis build-nexus-keys` | Generate Nexus DDNS authentication keys |
| `aegis build-keytabs` | Generate Kerberos keytabs and the KDC principal bundle |
| `aegis build-user-secrets` | Process user secrets from user repos |

Generators create only what is missing. `--rotate` (formerly `--force`) on the
SSH and Nexus builders mints **new key material**, breaking `known_hosts`,
SSHFP records and DDNS registrations; it prompts before doing so. To re-encrypt
existing secrets for a changed recipient set, use `aegis reencrypt`.

### Consistency Commands

| Command | Description |
|---------|-------------|
| `aegis check` | Report drift between `src/` and the deploy output; exits 1 on errors |
| `aegis reencrypt` | Re-encrypt existing secrets for the current recipient set, and refresh manifests from `src/` placement |

### Admin Key Commands

Every secret is encrypted for the admin set as well as its real audience, so
those keys are the recovery path for the whole system. Keeping a second key
offline turns loss of the everyday key into a non-event.

| Command | Description |
|---------|-------------|
| `aegis admin init` | Generate this machine's admin key if absent, and register it |
| `aegis admin list-keys` | Show the keys this repo encrypts for |
| `aegis admin add-key --name <n>` | Register another admin key |
| `aegis admin remove-key --name <n>` | Unregister a key (refuses to remove the last one) |
| `aegis admin migrate` | Convert a legacy `keys/admin.pub` to `keys/admin/` |

### Realm Commands

| Command | Description |
|---------|-------------|
| `aegis realm init <REALM>` | Create a realm (master key, initial principals, `realm.toml`) |
| `aegis realm import <REALM>` | Import an existing realm and its principals |
| `aegis realm list` | Realms with their domains, trusts and member hosts |
| `aegis realm show <REALM>` | Principals grouped by kind |
| `aegis realm set <REALM>` | Update domains, KDC role, etypes, lifetimes |
| `aegis realm add-principal` | Add a principal (random key or password) |
| `aegis realm remove-principal` | Remove a principal |
| `aegis realm trust <A> <B>` | Establish cross-realm trust (bidirectional by default) |
| `aegis realm untrust <A> <B>` | Remove cross-realm trust |
| `aegis realm export <REALM>` | Write the KDC principal bundle |

A host reaches a realm through the roles already in the repo:

```
host --(domain-<domain> role)--> domain --(realm.toml domains)--> realm
```

so a host gets a keytab once its `domain-*` role lists it *and* some realm
declares that domain. `aegis check` reports either half being missing.

### Import Commands

| Command | Description |
|---------|-------------|
| `aegis import-ssh-host-keys <host>` | Import SSH private keys (derives public keys) |
| `aegis import-nexus-key <host>` | Import Nexus DDNS authentication key |
| `aegis realm import <REALM>` | Import Kerberos realm with principals |
| `aegis import-secret <host> <name>` | Import generic secret with metadata |

### Configuration Commands

| Command | Description |
|---------|-------------|
| `aegis init-host <hostname>` | Add a new host to configuration |
| `aegis add-user <username>` | Add a user and generate their keypair |
| `aegis add-secret <host> <name> <file>` | Add a custom secret for a host |
| `aegis init-role <role>` | Create a role keypair with no members |
| `aegis add-host-to-role <role> <host>` | Give a host the role's key |
| `aegis set-placement <host> <kind>` | Declare where a decrypted secret belongs |

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
├── src/                    # Source of truth: what exists, and where it lands
│   ├── hosts/*.toml        # Host configs, including [placement] metadata
│   ├── users/*.toml        # User configs
│   ├── roles/*.toml        # Role configs
│   └── kerberos/realms/    # Realm data: realm.toml, realm key, principals
├── keys/                   # Encrypted keys
│   ├── admin/*.pub         # Admin recipient set
│   ├── roles/*.age         # Role private keys
│   └── users/*.age         # User private keys
└── deploy/                 # Generated, host-targeted output
    ├── hosts/<host>/       # Per-host secrets + derived secrets.toml
    ├── roles/<role>.pub    # Role public keys
    └── kdc/                # Per-realm KDC principal bundles
```

`deploy/` was previously called `build/`; a repo that still has `build/` and no
`deploy/` keeps using it. Note that despite the name, it holds the **only**
copy of SSH host keys, Nexus keys and DNSSEC private keys — deleting it and
rebuilding mints new identities rather than restoring the old ones.

Deployment metadata (target path, owner, mode) lives in `src/hosts/<host>.toml`
under `[placement]`, so `deploy/hosts/<host>/secrets.toml` is a derived
artifact. Change it with `aegis set-placement`, then `aegis reencrypt`.

## See Also

- [aegis](../aegis) - NixOS modules for secret decryption
- [aegis-tools-user](../aegis-tools-user) - User CLI for managing personal secrets
- [aegis-secrets](../aegis-secrets) - Example secrets repository
