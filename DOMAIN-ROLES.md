# Domain Roles for Aegis

> **Status note.** The *concept* below — domain roles, two-phase decryption,
> encrypting shared secrets once for a role rather than N times for N hosts —
> is exactly how Aegis works, and the `domain-<domain>` roles in aegis-secrets
> implement it.
>
> The *storage layout* in the "Directory Structure", "Creating a Domain Role"
> and "Managing Domain Membership" sections describes a single shared
> `role-key.age` encrypted for every member host. That is not the layout in
> use. Aegis stores a **per-host copy** of each role key at
> `deploy/hosts/<host>/roles/<role>.age`, which is what the NixOS module reads
> in phase 1, and records membership in `src/roles/<role>.toml`.
>
> Manage membership with the commands in the Role Commands section of the
> README, which operate on that layout:
>
> ```bash
> aegis init-role <role>                     # create the keypair
> aegis add-host-to-role <role> <host>       # grant a host the key
> aegis remove-host-from-role <role> <host>  # revoke the copy
> aegis build-role-keys                      # reconcile every member
> aegis check                                # report members missing a key
> ```
>
> Two shared-key artifacts predate this and are still in the repo:
> `deploy/domains/<domain>/role-key.age` and three orphaned
> `deploy/roles/dns-<domain>.age`. `aegis check` reports them; they need a
> decision rather than a default (see `docs/REVIEW.md` in aegis-secrets).

Domain roles enable efficient secret sharing across multiple hosts using two-phase decryption, making it easy to add or remove hosts from a domain without re-encrypting all domain secrets.

## Concept

**Problem:** If you have 20 domain-wide secrets (like OIDC client secrets, LDAP passwords, etc.) and want to add a new host to the domain, you'd need to re-encrypt all 20 secrets with the new host's key.

**Solution:** Use a domain role key. The domain role key is encrypted for all hosts in the domain, and domain secrets are encrypted with the role key. To add a new host, you only re-encrypt the single role key file.

## Architecture

### Without Domain Roles (Direct Encryption)

```
Secret → Encrypted for [host1, host2, host3, ..., admin]
```

**To add host4:** Re-encrypt ALL secrets with new recipients.

### With Domain Roles (Two-Phase)

```
Phase 1: Role Key → Encrypted for [host1, host2, host3, ..., admin]
Phase 2: Secrets → Encrypted for [role-key, admin]
```

**To add host4:** Re-encrypt ONLY the role key.

## Directory Structure

```
aegis-secrets/build/
├── domains/
│   └── fudo.org/
│       ├── role-key.age              # Domain role key (Phase 1)
│       └── dns/                      # Other domain infrastructure
├── secrets/
│   └── fudo.org/
│       ├── authentik-ldap.token.age  # Domain secret (Phase 2)
│       ├── mastodon-oidc.secret.age  # Domain secret (Phase 2)
│       └── ...
└── hosts/
    └── germany/
        └── secrets.toml              # References domain role key
```

## Creating a Domain Role

### Automatic (During Migration)

The migration script automatically creates domain role keys:

```bash
# Migrate from fudo-secrets with domain roles
cd /path/to/migrate-to-aegis
nix run .
```

This creates:
- `build/domains/fudo.org/role-key.age`
- `build/domains/sea.fudo.org/role-key.age`
- `build/domains/informis.land/role-key.age`

And encrypts all domain secrets with the respective role keys.

### Manual (For New Domains)

```bash
# 1. Generate a role keypair
age-keygen > /tmp/domain-fudo.org.key

# 2. Extract the public key
ROLE_PUBKEY=$(grep 'public key:' /tmp/domain-fudo.org.key | cut -d: -f2 | tr -d ' ')

# 3. Get all host public keys in the domain
ADMIN_PUBKEY=$(cat aegis-secrets/keys/admin.pub)
HOST1_PUBKEY=$(grep age_pubkey aegis-secrets/src/hosts/host1.toml | cut -d'"' -f2)
HOST2_PUBKEY=$(grep age_pubkey aegis-secrets/src/hosts/host2.toml | cut -d'"' -f2)
# ... etc

# 4. Encrypt the role private key for all domain hosts
age --encrypt --armor \
    --recipient "$HOST1_PUBKEY" \
    --recipient "$HOST2_PUBKEY" \
    --recipient "$ADMIN_PUBKEY" \
    --output aegis-secrets/build/domains/fudo.org/role-key.age \
    < /tmp/domain-fudo.org.key

# 5. Encrypt domain secrets with the role public key
age --encrypt --armor \
    --recipient "$ROLE_PUBKEY" \
    --recipient "$ADMIN_PUBKEY" \
    --output aegis-secrets/build/secrets/fudo.org/my-secret.age \
    < my-secret.txt

# 6. Clean up
rm /tmp/domain-fudo.org.key
```

## Host Configuration

Each host in the domain needs a manifest that references the domain role key:

```toml
# aegis-secrets/build/hosts/germany/secrets.toml

# Phase 1: Decrypt domain role key with host master key
[[secrets]]
source = "../../domains/fudo.org/role-key.age"
target = "/run/aegis/roles/domain-fudo.org.key"
mode = "0400"
phase = 1
identity = "/state/master-key/key"  # Host's master key

# Phase 2: Decrypt domain secrets with role key
[[secrets]]
source = "../../secrets/fudo.org/authentik-ldap.token.age"
target = "/run/aegis/authentik/ldap-token"
mode = "0400"
phase = 2
identity = "/run/aegis/roles/domain-fudo.org.key"  # Role key from Phase 1

[[secrets]]
source = "../../secrets/fudo.org/mastodon-oidc.secret.age"
target = "/run/aegis/mastodon/oidc-secret"
mode = "0400"
phase = 2
identity = "/run/aegis/roles/domain-fudo.org.key"

# ... more domain secrets
```

## Managing Domain Membership

### Add a Host to a Domain

Use the `add-host-to-role` command:

```bash
aegis add-host-to-role domain-fudo.org newhost
```

This:
1. Decrypts the current domain role key (requires admin key)
2. Gets the new host's public key from `src/hosts/newhost.toml`
3. Re-encrypts the role key for all existing hosts + new host + admin
4. Updates `build/domains/fudo.org/role-key.age`

**All domain secrets remain untouched!** Only the single role key file is re-encrypted.

### Remove a Host from a Domain

Use the `remove-host-from-role` command:

```bash
aegis remove-host-from-role domain-fudo.org oldhost \
    --hosts=host1,host2,host3,remaining,hosts
```

**Important:** You must specify all hosts that should remain in the domain. This is a safety feature to prevent accidentally removing all hosts.

This:
1. Decrypts the current domain role key
2. Gets public keys for all remaining hosts
3. Re-encrypts the role key WITHOUT the removed host
4. Updates `build/domains/fudo.org/role-key.age`

The removed host can no longer decrypt the role key, and therefore can no longer decrypt any domain secrets.

### Verify Domain Members

Unfortunately, `age` doesn't expose recipient information, so there's no built-in way to list which hosts can decrypt a role key. You need to track this separately.

**Best Practice:** Keep a comment in your secrets repository noting which hosts are in each domain:

```toml
# aegis-secrets/src/domains/fudo.org.toml
realm = "FUDO.ORG"
dns_zones = ["fudo.org", "fudo.ca", "fudo.im", ...]

# Hosts with access to domain-fudo.org role:
# - aedile
# - arx  
# - france
# - germany
# - legatus
# - paris
# - praetor
```

## Workflow Examples

### Example 1: Adding a New Application Service

You have a new application that needs OIDC credentials. Since it's domain-wide:

```bash
# 1. Create the secret (no host needed!)
echo "secret-client-secret-value" > /tmp/newapp-oidc.secret

# 2. Get the domain role public key
ROLE_KEY_FILE="aegis-secrets/build/domains/fudo.org/role-key.age"
age --decrypt --identity ~/.config/aegis/key.txt "$ROLE_KEY_FILE" > /tmp/role.key
ROLE_PUBKEY=$(age-keygen -y /tmp/role.key)

# 3. Encrypt with role key
ADMIN_PUBKEY=$(cat aegis-secrets/keys/admin.pub)
age --encrypt --armor \
    --recipient "$ROLE_PUBKEY" \
    --recipient "$ADMIN_PUBKEY" \
    --output aegis-secrets/build/secrets/fudo.org/newapp-oidc.secret.age \
    < /tmp/newapp-oidc.secret

# 4. Add to ANY host's manifest (all domain hosts can access it)
cat >> aegis-secrets/build/hosts/germany/secrets.toml <<EOF

[[secrets]]
source = "../../secrets/fudo.org/newapp-oidc.secret.age"
target = "/run/aegis/newapp/oidc-secret"
mode = "0400"
phase = 2
identity = "/run/aegis/roles/domain-fudo.org.key"
EOF

# 5. Clean up temp files
rm /tmp/newapp-oidc.secret /tmp/role.key
```

### Example 2: Provisioning a New Domain Host

```bash
# 1. Create host config (if not exists)
aegis sync-hosts  # Or manually create src/hosts/newhost.toml

# 2. Add to domain role
aegis add-host-to-role domain-fudo.org newhost

# 3. Create host manifest with domain role reference
cat > aegis-secrets/build/hosts/newhost/secrets.toml <<EOF
# Domain role key (Phase 1)
[[secrets]]
source = "../../domains/fudo.org/role-key.age"
target = "/run/aegis/roles/domain-fudo.org.key"
mode = "0400"
phase = 1

# Domain secrets (Phase 2) - same as other hosts!
[[secrets]]
source = "../../secrets/fudo.org/authentik-ldap.token.age"
target = "/run/aegis/authentik/ldap-token"
mode = "0400"
phase = 2
identity = "/run/aegis/roles/domain-fudo.org.key"
EOF

# 4. Deploy
# (copy master key to /state/master-key/key on newhost)
# (deploy NixOS config with aegis.autoSecrets enabled)
```

### Example 3: Decommissioning a Host

```bash
# 1. Get list of remaining hosts
REMAINING="host1,host2,host3"  # All except the one being removed

# 2. Remove from domain
aegis remove-host-from-role domain-fudo.org oldhost --hosts="$REMAINING"

# 3. Remove host config
rm aegis-secrets/src/hosts/oldhost.toml
rm -rf aegis-secrets/build/hosts/oldhost/

# 4. Commit
cd aegis-secrets
git add -A
git commit -m "Decommission oldhost"
```

## Comparison with Other Approaches

### Approach 1: Direct Multi-Recipient Encryption

```bash
# Encrypt for all hosts
age --encrypt -r host1 -r host2 -r host3 -r admin -o secret.age < secret.txt
```

**Pros:**
- Simple, one-phase decryption
- No intermediate keys

**Cons:**
- Must re-encrypt ALL secrets when adding/removing hosts
- For 20 secrets, that's 20 files to re-encrypt

### Approach 2: Domain Role Keys (Two-Phase)

```bash
# Encrypt role key for hosts
age --encrypt -r host1 -r host2 -r host3 -r admin -o role-key.age < role.key
# Encrypt secrets with role key
age --encrypt -r $(age-keygen -y role.key) -r admin -o secret.age < secret.txt
```

**Pros:**
- Only re-encrypt 1 file (role key) when adding/removing hosts
- All domain secrets stay the same
- Better for large domains with many secrets

**Cons:**
- Two-phase decryption (slightly more complex)
- Requires systemd dependency ordering (Phase 1 before Phase 2)

### When to Use Each

**Use Direct Encryption when:**
- Small number of secrets (< 5)
- Hosts rarely change
- Simplicity is preferred

**Use Domain Roles when:**
- Many domain-wide secrets (> 10)
- Hosts are added/removed frequently
- Multiple domains with different membership

## Troubleshooting

### "Role key not found"

```
Error: Role key not found: build/domains/fudo.org/role-key.age
```

Create the role key first (see "Creating a Domain Role" above).

### "Host config not found"

```
Error: Host config not found: src/hosts/newhost.toml
Run 'aegis sync-hosts' or create the host config first.
```

Solution:
```bash
aegis sync-hosts
# Or create manually:
cat > src/hosts/newhost.toml <<EOF
services = ["host"]
age_pubkey = "age1..."
EOF
```

### Phase 2 Secrets Not Decrypting

Check systemd service dependencies:

```bash
systemctl status aegis-phase1.target
systemctl status aegis-phase2.target
```

Phase 2 secrets require Phase 1 to complete first. If Phase 1 fails, Phase 2 won't run.

### Can't Decrypt Role Key

Ensure your admin key is set up:

```bash
ls -la ~/.config/aegis/key.txt
# Should exist and be your age private key
```

## Security Considerations

### Role Key Protection

The domain role key is the "master key" for all domain secrets. It's encrypted for:
- All hosts in the domain (each can decrypt with their master key)
- Admin (for management operations)

**If compromised:** An attacker with the role key can decrypt all domain secrets.

**Mitigation:**
- Host master keys stored on disk (e.g., `/state/master-key/key`)
- Role key decrypted to tmpfs (`/run/aegis/roles/`)
- Never persisted to disk unencrypted

### Admin Key Security

The admin key can decrypt:
- All role keys
- All secrets (directly or via role keys)

**Best practices:**
- Keep admin key on secure, air-gapped system
- Use hardware security key (YubiKey) for admin operations
- Audit admin key usage

### Least Privilege

Not all hosts need all domain secrets. Use manifest files to limit what each host decrypts:

```toml
# germany only needs these domain secrets
[[secrets]]
source = "../../secrets/fudo.org/mastodon-oidc.secret.age"
# ...

# france doesn't need mastodon secrets, only grafana
[[secrets]]
source = "../../secrets/fudo.org/grafana-oidc.secret.age"
# ...
```

Even though both hosts can decrypt all domain secrets (they have the role key), they only decrypt what they need.

## See Also

- [aegis-tools-system README](README.md) - General usage
- [aegis PLAN.md](../aegis/PLAN.md) - Overall Aegis architecture
- [Two-Phase Decryption](../aegis/README.md#two-phase-decryption) - How Phase 1/2 works
