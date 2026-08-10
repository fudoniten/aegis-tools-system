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
> The *secrets* a role protects are shared, exactly as described below: one
> copy each, at `deploy/roles/<role>/secrets/<name>.age`, encrypted to the
> role. Every member's manifest names that file and decrypts it in phase 2.
>
> The hand-rolled `age` invocations in "Manual (For New Domains)" and the
> hand-written manifest stanzas in "Host Configuration" are no longer
> necessary — those sections are kept as an explanation of the mechanism.
> The commands that do it are in the Role Commands section of the README:
>
> ```bash
> aegis role init <role>                     # create the keypair
> aegis role add-host <role> <host>          # grant a host the key and secrets
> aegis role remove-host <role> <host>       # revoke both
> aegis secret import <name> --role <role>   # a secret the role owns
> aegis secret new <name> --role <role>      # ...or a freshly generated one
> aegis build role-keys                      # reconcile every member's key
> aegis build role-secrets                   # reconcile every member's manifest
> aegis check                                # report what is out of step
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
aegis-secrets/
├── src/roles/
│   └── domain-fudo.org.toml            # Members, and where each secret lands
├── keys/roles/
│   └── domain-fudo.org.age             # Role private key, admin-encrypted
└── deploy/
    ├── roles/
    │   ├── domain-fudo.org.pub         # Role public key: what secrets encrypt to
    │   └── domain-fudo.org/secrets/
    │       ├── authentik-ldap.token.age  # Domain secret (Phase 2), ONE copy
    │       └── mastodon-oidc.secret.age  # Domain secret (Phase 2), ONE copy
    └── hosts/germany/
        ├── roles/domain-fudo.org.age   # This host's copy of the role key (Phase 1)
        └── secrets.toml                # Names the role, and every role secret
```

The role *key* is per host — one file per member, so a member can be added or
dropped without touching anyone else's. The role's *secrets* are not: there is
one of each, encrypted to the role, and every member's manifest points at it.

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
# 1. Generate the role keypair. The private key is stored encrypted for the
#    admin set; the public key is what domain secrets encrypt to.
aegis role init domain-fudo.org

# 2. Give each domain host its own copy of the role key
aegis role add-host domain-fudo.org host1
aegis role add-host domain-fudo.org host2

# 3. Encrypt a domain secret to the role -- once, not once per host
aegis secret import my-secret --role domain-fudo.org \
    --file /secure/my-secret --target /run/aegis/my-secret
```

The plaintext never reaches the repo, and no temporary key file is left for
step 6 to clean up. The `age` invocations this replaces are in "Approach 2"
below, if you want to see what it is doing.

## Host Configuration

The manifest is generated, not written: `aegis role add-host` and
`aegis build role-secrets` produce it. It looks like this, and the module
derives the phase and the identity from the `role` field rather than being
told them:

```toml
# aegis-secrets/deploy/hosts/germany/secrets.toml

# Phase 1: the role key, decrypted with this host's master key.
roles = ["domain-fudo.org"]

# Phase 2: domain secrets, decrypted with the role key from phase 1. The
# source climbs out of the host directory because there is only one copy.
[secrets.authentik-ldap-token]
source = "../../roles/domain-fudo.org/secrets/authentik-ldap-token.age"
target = "/run/aegis/authentik/ldap-token"
mode = "0400"
role = "domain-fudo.org"

[secrets.mastodon-oidc-secret]
source = "../../roles/domain-fudo.org/secrets/mastodon-oidc-secret.age"
target = "/run/aegis/mastodon/oidc-secret"
mode = "0400"
role = "domain-fudo.org"
```

## Managing Domain Membership

### Add a Host to a Domain

```bash
aegis role add-host domain-fudo.org newhost
```

This:
1. Decrypts the domain role key (requires the admin key)
2. Gets the new host's public key from `src/hosts/newhost.toml`
3. Re-encrypts the role key *for that host alone*, at
   `deploy/hosts/newhost/roles/domain-fudo.org.age`
4. Records the membership in `src/roles/domain-fudo.org.toml`
5. Adds every one of the role's secrets to `newhost`'s manifest

**All domain secrets remain untouched** — nothing is re-encrypted, and the
plaintext is not needed. That is the whole point: the only thing that changes
when a service moves is who holds the role key.

### Remove a Host from a Domain

```bash
aegis role remove-host domain-fudo.org oldhost
```

This deletes `deploy/hosts/oldhost/roles/domain-fudo.org.age` and drops the
role's secrets from that host's manifest, so the next deploy stops writing
them. Membership is recorded in `src/roles/domain-fudo.org.toml`, so there is
no need to restate who remains.

The removed host can no longer decrypt the role key, and therefore no longer
decrypts any domain secret. Note that this is revocation, not rotation: it
has already read them.

### Verify Domain Members

`age` doesn't expose recipient information, so the ciphertext cannot answer
this — but membership is declared, not inferred. It lives in
`src/roles/domain-fudo.org.toml`, and:

```bash
aegis status        # members and secrets, per role
aegis check         # members whose key or manifest is out of step
```

## Workflow Examples

### Example 1: Adding a New Application Service

You have a new application that needs OIDC credentials. Since it's domain-wide,
target the role rather than any host — one command does all of the above:

```bash
aegis secret import newapp-oidc.secret --role domain-fudo.org \
    --file /secure/newapp-oidc.secret \
    --target /run/aegis/newapp/oidc-secret --mode 0400
```

That encrypts it once to the role and the admin set, and adds an entry to
every current member's manifest. Hosts that join the role later pick it up
from `aegis role add-host`, with no re-encryption and no second look at the
plaintext.

### Example 2: Provisioning a New Domain Host

```bash
# 1. Declare the host and its master key
aegis host add newhost
aegis host set-key newhost --public-key age1...

# 2. Add to the domain role. This writes newhost's copy of the role key AND
#    puts every one of the role's secrets into its manifest.
aegis role add-host domain-fudo.org newhost

# 3. Deploy
# (copy master key to /state/master-key/key on newhost)
# (deploy NixOS config with aegis.autoSecrets enabled)
```

### Example 3: Decommissioning a Host

```bash
# 1. Remove from the domain. This deletes its copy of the role key and drops
#    the role's secrets from its manifest.
aegis role remove-host domain-fudo.org oldhost

# 2. Rotate what it could read. Revoking access is not rotation: oldhost has
#    already seen everything the role protected.
aegis secret import <name> --role domain-fudo.org --file ... --force

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

A role secret cannot decrypt before its role key exists, so start there:

```bash
systemctl status aegis-role-domain-fudo.org.service   # phase 1: the role key
systemctl status aegis-secret-<name>.service          # phase 2: the secret
ls -l /run/aegis/roles/                               # what phase 1 produced
```

The phase-2 unit `Requires=` the role's phase-1 unit directly, not just
`aegis-phase1.target` — the target is reached by weak `wantedBy` dependencies
and would otherwise activate even when the role key failed to decrypt.

If the secret is not there at all, the host's manifest may not name it:

```bash
aegis check                  # reports members whose manifest is out of step
aegis build role-secrets     # regenerate the manifests, then redeploy
```

### Can't Decrypt Role Key

Ensure your admin key is set up:

```bash
ls -la ~/.config/aegis/key.txt
# Should exist and be your age private key
```

## Security Considerations

### Role Key Protection

The domain role key is the "master key" for all domain secrets. A copy exists
per member host, each encrypted for:
- That host's master key (so it can use the role)
- The admin set (so the copy can be regenerated)

**If compromised:** An attacker with the role key can decrypt all domain
secrets. Removing a host from the role deletes its copy, but does not undo
what it has already read — revocation is not rotation.

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

Role membership is all-or-nothing: a member holds the role key, so it *can*
decrypt every secret the role holds, whether or not its manifest names them.
Narrower roles are the way to narrow access — one per service rather than one
per domain — not a narrower manifest.

## See Also

- [aegis-tools-system README](README.md) - General usage
- [aegis PLAN.md](../aegis/PLAN.md) - Overall Aegis architecture
- [Two-Phase Decryption](../aegis/README.md#two-phase-decryption) - How Phase 1/2 works
