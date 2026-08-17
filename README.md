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
aegis --help                # the groups
aegis host --help           # what a group can do
aegis host add --help       # what one command can do
```

Commands are grouped by what they act on. The top level is small on purpose:

| Group | Holds |
|-------|-------|
| `aegis build` | every generator; bare `aegis build` runs all of them |
| `aegis status` / `check` / `verify` / `reencrypt` | inspection and repair |
| `aegis host` / `user` / `role` / `secret` | what the repo declares |
| `aegis ssh` / `nexus` / `dnssec` / `realm` / `admin` | one kind of key material each |

Every pre-grouping command name (`aegis init-host`, `aegis build-keytabs`, …)
still works and prints where it moved to, so existing scripts keep running.
Those aliases go away when beta does.

### Quick Start

A new host, end to end. Nothing is generated for a host until it has a master
key, because there would be no one to encrypt it for:

```bash
aegis host add rama --domain sea.fudo.org      # declare it
aegis host set-key rama --public-key age1...   # so it can decrypt
aegis build                                    # generate what it is missing
aegis check                                    # confirm nothing is adrift
aegis verify rama                              # confirm the host can read it
```

Bringing in material that already exists, instead of generating it:

```bash
aegis ssh import rama --key /secure/rama.ed25519.key
aegis nexus import rama --file /secure/rama.nexus.hmac

# A service secret you were handed: encrypt it, and say where it lands.
aegis secret import grafana-token --host rama \
    --file /secure/grafana.token \
    --target /run/grafana/token --user grafana --mode 0400

# The same, but tied to the SERVICE rather than to rama: encrypted once, to
# the role, so 'aegis role add-host grafana <host>' is all it takes to move
# or extend it later.
aegis secret import grafana-token --role grafana \
    --file /secure/grafana.token \
    --target /run/grafana/token --user grafana --mode 0400

# One you want invented rather than handed over.
aegis secret new ingest-token --host rama --host lambda \
    --target /run/aurelius/token --user aurelius
```

Two rules worth knowing before you need them:

```bash
# Changing WHO can read a secret never regenerates it.
aegis admin add-key --name backup --public-key age1...
aegis reencrypt                     # until this, the new key reads nothing

# Changing WHAT the secret is does, and breaks everything holding the old one.
aegis build ssh-keys --rotate       # new SSH identity; breaks known_hosts
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
aegis host add myhost --services=host,ssh

# Import existing secrets
aegis secret import db-password --host lambda \
    --file /secure/db.password --target /run/myservice/db-password
aegis ssh import lambda --key /secure/lambda.ed25519.key --key /secure/lambda.ecdsa.key
aegis nexus import lambda --file /secure/lambda.nexus.hmac
aegis realm import SEA.FUDO.ORG --realm-key /secure/realm.key --principals-dir /secure/principals/ --domain sea.fudo.org

# Add a user with access to specific hosts
aegis user add alice --hosts=host1,host2

# Build all secrets (SSH keys, Nexus keys, keytabs, user secrets)
aegis build

# Build one kind
aegis build role-keys
aegis build role-secrets
aegis build ssh-keys
aegis build nexus-keys
aegis build keytabs
aegis build user-secrets

# Report drift between src/ and deploy/ (changes nothing, exits 1 on errors)
aegis check

# Repair recipient drift without touching key material
aegis reencrypt --host myhost

# Rewrite regardless of what a file looks like (after replacing a key)
aegis reencrypt --host myhost --force

# Kerberos realms
aegis realm init EXAMPLE.ORG --domain example.org
aegis realm list
aegis realm show EXAMPLE.ORG
aegis realm add-principal EXAMPLE.ORG postgres/db.example.org --host db
aegis realm rekey-principal EXAMPLE.ORG postgres/db.example.org
aegis realm trust EXAMPLE.ORG OTHER.ORG
aegis realm export EXAMPLE.ORG

# Create a role (e.g., KDC), and give it a secret that follows the service
aegis role init kdc
aegis role add-host kdc kdchost
aegis secret import service-token --role kdc \
    --file /secure/service.token --target /run/kdc/token

# Declare where a decrypted secret belongs
aegis host set-placement myhost keytab --target /etc/krb5.keytab --mode 0600

# List secrets for a host
aegis secret list myhost

# Verify secrets are properly formatted
aegis verify myhost
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `AEGIS_SYSTEM` | Path to aegis-secrets repository |
| `AEGIS_SCRIPTS` | Path to Kerberos scripts (set automatically by Nix) |
| `AEGIS_ADMIN_KEY` | Path to this machine's admin private key (default `~/.config/aegis/key.txt`) |

## Commands Reference

### Build Commands

| Command | Description |
|---------|-------------|
| `aegis build` | Run every step below, in order (same as `aegis build all`) |
| `aegis build role-keys` | Give each role member its copy of the role key |
| `aegis build role-secrets` | Point each role member's manifest at the role's secrets |
| `aegis build ssh-keys` | Generate SSH host keys |
| `aegis build nexus-keys` | Generate Nexus DDNS authentication keys |
| `aegis build keytabs` | Generate Kerberos keytabs and the KDC principal bundle |
| `aegis build user-secrets` | Process user secrets from user repos |
| `aegis build bundles` | Package secrets into host bundles |

Generators create only what is missing. `--rotate` (formerly `--force`) on the
SSH and Nexus builders mints **new key material**, breaking `known_hosts`,
SSHFP records and DDNS registrations; it prompts before doing so. To re-encrypt
existing secrets for a changed recipient set, use `aegis reencrypt`.

### Consistency Commands

| Command | Description |
|---------|-------------|
| `aegis check` | Report drift between `src/` and the deploy output; exits 1 on errors |
| `aegis reencrypt` | Re-encrypt **every** secret in the repo for the current recipient set, and refresh manifests from `src/` placement |

`reencrypt` covers the whole repository, not just per-host output: role
private keys, user private keys, realm master keys and every Kerberos
principal are encrypted for the admin set and nobody else, and they are
exactly what a lost admin key makes unrecoverable. Filter with `--host` or
`--category` (`admin-only`, `host`, `role`, `user`, `kdc`, `dnssec`); preview
with `--dry-run`.

#### Replacing a key needs `--force`

By default a file is skipped once it carries the expected *number* of
recipients, so a re-run is cheap and the git diff stays legible. age exposes
only the count, never which keys — so a key that was **added** is detected,
while a key that **replaced** another is not. Changing a host's master key
leaves every one of its files looking correct while the host can no longer
decrypt any of them:

```bash
aegis host set-key myhost --public-key age1...     # the new key
aegis reencrypt --host myhost                      # "already carries the expected recipients"
aegis reencrypt --host myhost --force              # actually rewrites them
```

`--force` rewrites everything the filters select, whatever it currently
carries. Pair it with `--host` to keep the blast radius to the host whose key
changed; without a filter it rewrites the whole repository. It never touches
key material — unlike the builders' `--rotate` (which was itself once called
`--force`), it only changes who can read the secrets that already exist.

`aegis host set-key` points you here when it replaces an existing key.

Files whose intended audience cannot be determined — anything under
`deploy/` that no current policy describes — are reported and left untouched.
age does not expose the recipients of an existing file, so rewriting one means
picking a new set blind, and a wrong guess silently destroys access.

### Admin Key Commands

Every secret is encrypted for the admin set as well as its real audience, so
those keys are the recovery path for the whole system. Keeping a second key
offline turns loss of the everyday key into a non-event.

Adding a key is two steps, and the second one matters:

```bash
aegis admin add-key --name backup --public-key age1...   # register it
aegis reencrypt                                          # make it usable
```

Registering alone changes nothing about existing files — the new key can
decrypt none of them until `reencrypt` has run. `add-key` reports how many
files are still out of its reach.

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
| `aegis realm rekey-principal` | Rotate a key, retaining the old one for a grace period |
| `aegis realm trust <A> <B>` | Establish cross-realm trust (bidirectional by default) |
| `aegis realm untrust <A> <B>` | Remove cross-realm trust |
| `aegis realm export <REALM>` | Write the KDC principal bundle |
| `aegis realm delete <REALM>` | Delete a realm, its master key and every principal |

### Rotating a principal

A Kerberos keytab can hold several kvnos for the same principal, so rotation
does not have to be a hard cutover:

```bash
aegis realm rekey-principal REALM host/rama.sea.fudo.org   # rotate, keep the old key
aegis build keytabs --force --realm REALM                  # keytabs carry both kvnos
# ...deploy the affected hosts...
aegis realm rekey-principal REALM host/rama.sea.fudo.org --prune
```

The pre-rotation key is retained under `principals/previous/` and
`aegis build keytabs` appends it to the emitted keytab, so services keep
authenticating with the key they already have until they receive the new one.
`aegis check` reports principals mid-rotation, so an unfinished one does not go
unnoticed — the old key stays valid until you prune it.

A host reaches a realm through the roles already in the repo:

```
host --(domain-<domain> role)--> domain --(realm.toml domains)--> realm
```

so a host gets a keytab once its `domain-*` role lists it *and* some realm
declares that domain. `aegis check` reports either half being missing.

### Import Commands

Importing brings key material that already exists under Aegis management;
generating it is the `aegis build` family above.

| Command | Description |
|---------|-------------|
| `aegis ssh import <host>` | Import SSH private keys (derives public keys) |
| `aegis nexus import <host>` | Import Nexus DDNS authentication key |
| `aegis dnssec import <domain>` | Import an existing DNSSEC KSK |
| `aegis realm import <REALM>` | Import Kerberos realm with principals |
| `aegis secret import <name>` | Import a generic secret for hosts and/or roles |

### Host, User and Secret Commands

| Command | Description |
|---------|-------------|
| `aegis host add <hostname>` | Add a new host to configuration |
| `aegis host set-key <host>` | Set the host's age public key |
| `aegis host set-status <host> <status>` | Record whether Aegis manages the host |
| `aegis host set-placement <host> <kind>` | Declare where a decrypted secret belongs |
| `aegis host list` | Declared hosts, their status, key and deployed file count |
| `aegis host delete <host>` | Delete a host and everything deployed to it |
| `aegis user add <username>` | Add a user and generate their keypair |
| `aegis user list` | Users and the hosts they reach |
| `aegis user delete <username>` | Delete a user and every host's copy of their key |
| `aegis secret new <name>` | Generate a random secret for hosts and/or roles |
| `aegis secret add <host> <name> <file>` | Encrypt a file for a host (no placement) |
| `aegis secret list [host]` | List secrets for host(s) |
| `aegis secret delete <name>` | Delete a secret's ciphertext and manifest entries |
| `aegis ssh list [host]` | SSH host keys declared, and which reach sshd |
| `aegis ssh delete <host>` | Delete a host's SSH keys (its identity) |
| `aegis nexus list` | Hosts holding a Nexus HMAC key |
| `aegis nexus delete <host>` | Delete a host's Nexus key |
| `aegis dnssec list` | Domains with a KSK, and who signs with it |
| `aegis dnssec delete <domain>` | Delete a domain's KSK |

### Role Commands

| Command | Description |
|---------|-------------|
| `aegis role init <role>` | Create a role keypair with no members |
| `aegis role add-host <role> <host>` | Give a host the role's key and its secrets |
| `aegis role remove-host <role> <host>` | Revoke a host's copy of the role key |
| `aegis role set-placement <role> secret:<name>` | Declare where a role secret belongs |
| `aegis role list` | Roles, their members and the secrets they carry |
| `aegis role delete <role>` | Delete a role, its key and its shared secrets |

#### Deleting

Every category has `list` and `delete` alongside its create verb. Deletion
refuses rather than cascading: it prints what would go, what still points at
the thing, and stops.

```bash
aegis role delete legacy-app --dry-run   # the plan, and nothing else
aegis role delete legacy-app             # refuses if a manifest still uses it
aegis role delete legacy-app --force     # delete anyway, clean up after
```

A secrets repository is a graph — a role is held by hosts, a host holds role
keys, a Nebula network signs for both — so cleaning up every edge
automatically would let one mistyped name remove a great deal, with the blast
radius visible only afterwards. Naming the references instead lets you decide
which end is the mistake.

`aegis host delete` is usually the wrong verb: a machine that is gone should be
`aegis host set-status <host> retired`, which keeps the record of what it held
so you know what to rotate. Deleting removes that record too, and refuses while
the host is active with secrets on it.

Domain membership is role membership: a host in `domain-fudo.org` is a host in
that domain. See [DOMAIN-ROLES.md](DOMAIN-ROLES.md) for the concept and the
on-disk layout.

#### Secrets that belong to a service, not a machine

A secret targeted at a **host** is encrypted to that host's master key and
stored under it. If the service moves, the secret does not follow.

A secret targeted at a **role** is encrypted once, to the role, and stored at
`deploy/roles/<role>/secrets/<name>.age`. Every member host's manifest points
at that one file and decrypts it in phase 2, using the role key it unwrapped
in phase 1. Adding a host to the role is then the whole of "give this host the
secret" — nothing is re-encrypted, and the plaintext is never needed again:

```bash
# Once, when the service is first declared
aegis role init authentik
aegis secret import ldap-bind-password --role authentik \
    --file /secure/authentik-ldap.password \
    --target /run/authentik/ldap-password \
    --user authentik --group authentik

# Whenever the service moves or scales
aegis role add-host authentik newhost      # gains the key AND the secrets
aegis role remove-host authentik oldhost   # loses both

# 'aegis secret new --role' does the same for a freshly generated secret
aegis secret new authentik-session-key --role authentik \
    --target /run/authentik/session-key
```

Revoking is not rotating: a host that has held a role key has seen everything
the role protected. `aegis role remove-host` says so. To actually rotate,
re-import with `--force` and restart whatever holds the old value.

### Utility Commands

| Command | Description |
|---------|-------------|
| `aegis status` | Show what needs building |
| `aegis verify <host>` | Verify secrets are valid |
| `aegis nexus keygen <file>` | Write a standalone Nexus HMAC key |

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
    ├── roles/<role>/secrets/  # Secrets encrypted to the role, one copy each
    └── kdc/                # Per-realm KDC principal bundles
```

`deploy/` was previously called `build/`; a repo that still has `build/` and no
`deploy/` keeps using it. Note that despite the name, it holds the **only**
copy of SSH host keys, Nexus keys and DNSSEC private keys — deleting it and
rebuilding mints new identities rather than restoring the old ones.

Deployment metadata (target path, owner, mode) lives in `src/hosts/<host>.toml`
under `[placement]`, so `deploy/hosts/<host>/secrets.toml` is a derived
artifact. Change it with `aegis host set-placement`, then `aegis reencrypt`.

A role secret's placement lives in `src/roles/<role>.toml` instead, for the
same reason it is encrypted to the role: there is one destination, and a host
joining the role later has to inherit it without anybody restating it. Change
it with `aegis role set-placement`.

## See Also

- [aegis](../aegis) - NixOS modules for secret decryption
- [aegis-tools-user](../aegis-tools-user) - User CLI for managing personal secrets
- [aegis-secrets](../aegis-secrets) - Example secrets repository
