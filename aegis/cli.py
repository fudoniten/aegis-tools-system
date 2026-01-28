"""Aegis CLI - System administration tools for secrets management."""

import os
import sys
from pathlib import Path
from typing import Optional

import typer
import yaml

from . import crypto, ssh, entities, config

app = typer.Typer(
    name="aegis",
    help="Aegis System Administration Tools for secrets management.",
    no_args_is_help=True,
)


def _is_aegis_repo(path: Path) -> bool:
    """Check if a path looks like an aegis secrets repo."""
    return (
        (path / "src").exists() or 
        (path / "flake.nix").exists() and 
        ((path / "keys").exists() or (path / "build").exists())
    )


def get_secrets_repo(secrets_path: Optional[Path]) -> config.SecretsRepo:
    """Get the secrets repo, with default path handling.
    
    Resolution order:
    1. Explicit --secrets-path argument
    2. AEGIS_SYSTEM environment variable
    3. Current directory (if it looks like a secrets repo)
    4. Common relative paths (./aegis-secrets, ../aegis-secrets)
    """
    if secrets_path is not None:
        if not secrets_path.exists():
            typer.echo(f"Error: Specified path does not exist: {secrets_path}", err=True)
            raise typer.Exit(1)
        return config.SecretsRepo(secrets_path)
    
    # Check AEGIS_SYSTEM environment variable
    env_path = os.environ.get("AEGIS_SYSTEM")
    if env_path:
        path = Path(env_path)
        if path.exists() and _is_aegis_repo(path):
            return config.SecretsRepo(path)
        typer.echo(f"Error: AEGIS_SYSTEM points to invalid repo: {env_path}", err=True)
        raise typer.Exit(1)
    
    # Try to find it relative to current directory
    candidates = [
        Path.cwd(),  # Maybe we're in the secrets repo
        Path.cwd() / "aegis-secrets",
        Path.cwd().parent / "aegis-secrets",
    ]
    for candidate in candidates:
        if candidate.exists() and _is_aegis_repo(candidate):
            return config.SecretsRepo(candidate)
    
    typer.echo("Error: Could not find aegis-secrets repo", err=True)
    typer.echo("", err=True)
    typer.echo("Options:", err=True)
    typer.echo("  1. Run from within an aegis-secrets repo", err=True)
    typer.echo("  2. Set AEGIS_SYSTEM environment variable", err=True)
    typer.echo("  3. Use --secrets-path to specify location", err=True)
    raise typer.Exit(1)


def get_entities_path(entities_path: Optional[Path]) -> Path:
    """Get the entities path, with default handling.
    
    Resolution order:
    1. Explicit --entities-path argument
    2. AEGIS_ENTITIES environment variable (set by dev shell)
    3. Common relative paths
    """
    if entities_path is not None:
        return entities_path
    
    # Check AEGIS_ENTITIES environment variable (set by nix develop)
    env_path = os.environ.get("AEGIS_ENTITIES")
    if env_path:
        path = Path(env_path)
        if path.exists():
            return path
    
    # Try to find it in common locations
    candidates = [
        Path.cwd() / "nix-entities",
        Path.cwd().parent / "nix-entities",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    
    typer.echo("Error: Could not find nix-entities repo", err=True)
    typer.echo("", err=True)
    typer.echo("Options:", err=True)
    typer.echo("  1. Use 'nix develop' in aegis-secrets (sets AEGIS_ENTITIES)", err=True)
    typer.echo("  2. Use --entities-path to specify location", err=True)
    raise typer.Exit(1)


def get_host_master_pubkey(
    hostname: str,
    repo: config.SecretsRepo,
    entities_path: Optional[Path] = None,
) -> str:
    """Get the master public key for a host.
    
    Resolution order:
    1. Host config in aegis-secrets (src/hosts/<hostname>.toml)
    2. nix-entities
    
    The master key is an SSH public key used to encrypt secrets FOR the host.
    The host has the corresponding private key to decrypt.
    
    Returns:
        SSH public key string (e.g., "ssh-ed25519 AAAA...")
        
    Raises:
        typer.Exit if no master key found
    """
    # First, check host config in repo
    host_config = repo.get_host_config(hostname)
    if host_config and host_config.master_pubkey:
        return host_config.master_pubkey
    
    # Fall back to nix-entities
    if entities_path is None:
        try:
            entities_path = get_entities_path(None)
        except SystemExit:
            typer.echo(f"Error: No master key for {hostname}", err=True)
            typer.echo(f"Set it with: aegis set-master-key {hostname} --public-key 'ssh-ed25519 ...'", err=True)
            raise typer.Exit(1)
    
    try:
        host = entities.get_host(hostname, entities_path)
        if host.master_key and host.master_key.public_key:
            return host.master_key.public_key
    except Exception as e:
        typer.echo(f"Warning: Could not get host from entities: {e}", err=True)
    
    typer.echo(f"Error: No master key configured for {hostname}", err=True)
    typer.echo(f"Either:", err=True)
    typer.echo(f"  1. Set it with: aegis set-master-key {hostname} --public-key 'ssh-ed25519 ...'", err=True)
    typer.echo(f"  2. Configure it in nix-entities", err=True)
    raise typer.Exit(1)


# =============================================================================
# Build Commands
# =============================================================================

@app.command()
def build(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to aegis-secrets repo"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e", help="Path to nix-entities repo"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Show what would be done"),
    sync: bool = typer.Option(True, "--sync/--no-sync", help="Sync hosts from entities before building"),
    pull: bool = typer.Option(False, "--pull", "-p", help="Git pull entities repo before syncing"),
):
    """Run full build: sync hosts from entities, generate missing secrets.
    
    By default, this will:
    1. Sync hosts from nix-entities (creates configs for new hosts)
    2. Generate SSH host keys for OpenSSH
    3. Generate Nexus DDNS keys
    4. Generate Kerberos keytabs
    5. Build user secrets
    
    Use --no-sync to skip the entities sync step.
    Use --pull to git pull the entities repo first.
    """
    repo = get_secrets_repo(secrets_path)
    ent_path = get_entities_path(entities_path)
    
    typer.echo("Running full build...")
    
    if dry_run:
        if sync:
            typer.echo("  [dry-run] Would run: sync-hosts")
        typer.echo("  [dry-run] Would run: build-ssh-host-keys")
        typer.echo("  [dry-run] Would run: build-nexus-keys")
        typer.echo("  [dry-run] Would run: build-keytabs")
        typer.echo("  [dry-run] Would run: build-user-secrets")
        return
    
    # Sync hosts from entities
    if sync:
        typer.echo("\n--- Syncing Hosts from Entities ---")
        sync_hosts(secrets_path=secrets_path, entities_path=entities_path, pull=pull, dry_run=False, filter_domain=None)
    
    # Run each build step
    typer.echo("\n--- Building SSH Host Keys ---")
    build_ssh_host_keys(secrets_path=secrets_path, entities_path=entities_path, dry_run=False)
    
    typer.echo("\n--- Building Nexus Keys ---")
    build_nexus_keys(secrets_path=secrets_path, entities_path=entities_path, dry_run=False, algorithm="HmacSHA512")
    
    typer.echo("\n--- Building Keytabs ---")
    build_keytabs(secrets_path=secrets_path, entities_path=entities_path, dry_run=False)
    
    typer.echo("\n--- Building User Secrets ---")
    build_user_secrets(secrets_path=secrets_path, entities_path=entities_path, dry_run=False, user=None)
    
    typer.secho("\nBuild complete!", fg=typer.colors.GREEN)


@app.command("build-ssh-host-keys")
def build_ssh_host_keys(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    force: bool = typer.Option(False, "--force", "-f", help="Regenerate even if keys exist"),
):
    """Generate SSH host keys for OpenSSH servers.
    
    This generates the keys that OpenSSH will use to identify the server
    (ssh_host_ed25519_key, ssh_host_ecdsa_key, etc.).
    
    These are NOT master keys! Master keys are used to encrypt these host keys.
    
    Keys are encrypted with the host's master key + admin key and stored
    in build/hosts/<hostname>/ssh-host-keys.age.
    
    Also generates SSHFP DNS records for trust establishment.
    """
    repo = get_secrets_repo(secrets_path)
    
    hosts = repo.list_hosts()
    if not hosts:
        typer.echo("No hosts configured. Use 'aegis init-host' first.")
        return
    
    admin_pubkey = crypto.get_admin_public_key()
    
    for hostname in hosts:
        output_path = repo.host_build_path(hostname) / "ssh-host-keys.age"
        
        if output_path.exists() and not force:
            typer.echo(f"  {hostname}: SSH host keys exist (use --force to regenerate)")
            continue
        
        if dry_run:
            typer.echo(f"  [dry-run] Would generate SSH host keys for {hostname}")
            continue
        
        typer.echo(f"  Generating SSH host keys for {hostname}...")
        
        # Get master public key (from config or entities)
        try:
            master_pubkey = get_host_master_pubkey(hostname, repo, entities_path)
        except SystemExit:
            typer.echo(f"    Skipping {hostname} (no master key)", err=True)
            continue
        
        # Generate keys
        keys = ssh.generate_host_keys(hostname)
        
        # Convert to YAML
        keys_yaml = yaml.dump(keys.to_dict(), default_flow_style=False)
        
        # Get recipients
        host_age_key = crypto.ssh_pubkey_to_age(master_pubkey)
        recipients = [host_age_key, admin_pubkey]
        
        # Encrypt and write
        output_path.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(keys_yaml, recipients, output_path)
        
        typer.echo(f"    Wrote {output_path}")
        
        # Generate SSHFP records
        public_keys = [
            keys.host_ed25519.public_key,
            keys.host_ecdsa.public_key,
        ]
        sshfp_records = ssh.generate_sshfp_records(public_keys, hostname)
        typer.echo(f"    SSHFP records:")
        for record in sshfp_records:
            typer.echo(f"      {record}")


@app.command("build-nexus-keys")
def build_nexus_keys(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    force: bool = typer.Option(False, "--force", "-f", help="Regenerate even if keys exist"),
    algorithm: str = typer.Option("HmacSHA512", "--algorithm", "-a", help="HMAC algorithm"),
):
    """Generate Nexus DDNS authentication keys for hosts.
    
    Creates HMAC keys for each host to authenticate with Nexus DDNS servers.
    Keys are encrypted with both the admin and host keys.
    
    Each host gets a unique key stored in build/hosts/<hostname>/nexus-key.age.
    Nexus server hosts will automatically receive a collection of all client
    keys via the NixOS configuration.
    """
    from . import nexus
    
    repo = get_secrets_repo(secrets_path)
    ent_path = get_entities_path(entities_path)
    
    hosts = repo.list_hosts()
    if not hosts:
        typer.echo("No hosts configured. Use 'aegis init-host' first.")
        return
    
    admin_pubkey = crypto.get_admin_public_key()
    
    for hostname in hosts:
        output_path = repo.host_build_path(hostname) / "nexus-key.age"
        
        if output_path.exists() and not force:
            typer.echo(f"  {hostname}: Nexus key exists (use --force to regenerate)")
            continue
        
        if dry_run:
            typer.echo(f"  [dry-run] Would generate Nexus key for {hostname}")
            continue
        
        typer.echo(f"  Generating Nexus key for {hostname}...")
        
        # Get master public key (from config or entities)
        try:
            master_pubkey = get_host_master_pubkey(hostname, repo, entities_path)
        except SystemExit:
            typer.echo(f"    Skipping {hostname} (no master key)", err=True)
            continue
        
        # Generate key in a temp file
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_key_path = Path(tmpdir) / "nexus.key"
            nexus.generate_key(
                output_path=tmp_key_path,
                algorithm=algorithm,
                verbose=False,
            )
            
            # Read the generated key
            key_content = tmp_key_path.read_text()
        
        # Get recipients
        host_age_key = crypto.ssh_pubkey_to_age(master_pubkey)
        recipients = [host_age_key, admin_pubkey]
        
        # Encrypt and write
        output_path.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(key_content, recipients, output_path)
        
        typer.echo(f"    Wrote {output_path}")
        
        # Show the algorithm
        algo, _ = key_content.strip().split(":", 1)
        typer.echo(f"    Algorithm: {algo}")


@app.command("build-keytabs")
def build_keytabs(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    force: bool = typer.Option(False, "--force", "-f", help="Regenerate even if keytabs exist"),
):
    """Generate Kerberos keytabs for hosts and KDC database."""
    from . import kerberos as krb
    import tempfile
    import shutil
    
    repo = get_secrets_repo(secrets_path)
    ent_path = get_entities_path(entities_path)
    
    # Get admin key for encryption
    admin_pubkey = crypto.get_admin_public_key()
    
    # Find all realms we need to process
    kerberos_src = repo.src_path / "kerberos" / "realms"
    if not kerberos_src.exists():
        typer.echo("No Kerberos realms configured in src/kerberos/realms/")
        typer.echo("Use 'aegis init-realm' to create a realm first.")
        return
    
    # Get hosts grouped by realm
    hosts_by_realm: dict[str, list[str]] = {}
    for hostname in repo.list_hosts():
        try:
            host = entities.get_host(hostname, ent_path)
            if host.domain:
                domain = entities.get_domain(host.domain, ent_path)
                if domain.gssapi_realm:
                    realm = domain.gssapi_realm
                    if realm not in hosts_by_realm:
                        hosts_by_realm[realm] = []
                    hosts_by_realm[realm].append(hostname)
        except Exception as e:
            typer.echo(f"  Warning: Could not get realm for {hostname}: {e}", err=True)
    
    if not hosts_by_realm:
        typer.echo("No hosts with Kerberos realms found.")
        return
    
    # Get KDC role info for encryption
    kdc_role = repo.get_role_config("kdc")
    kdc_role_pubkey = None
    if kdc_role:
        kdc_pub_path = repo.role_build_path("kdc") / "kdc.pub"
        if kdc_pub_path.exists():
            kdc_role_pubkey = kdc_pub_path.read_text().strip()
    
    # Process each realm
    for realm, hostnames in hosts_by_realm.items():
        typer.echo(f"\nProcessing realm: {realm}")
        
        realm_src = kerberos_src / realm
        if not realm_src.exists():
            typer.echo(f"  Realm directory not found: {realm_src}")
            typer.echo(f"  Use 'aegis init-realm {realm}' to initialize.")
            continue
        
        # Check for encrypted realm key
        realm_key_enc = realm_src / "realm.key.age"
        if not realm_key_enc.exists():
            typer.echo(f"  Realm key not found: {realm_key_enc}")
            continue
        
        if dry_run:
            typer.echo(f"  [dry-run] Would process {len(hostnames)} hosts")
            for hostname in hostnames:
                typer.echo(f"    - {hostname}")
            continue
        
        # Create temp directory for decrypted realm data
        with tempfile.TemporaryDirectory(prefix="aegis-krb-") as tmpdir:
            tmpdir = Path(tmpdir)
            realm_tmp = tmpdir / realm
            realm_tmp.mkdir()
            principals_tmp = realm_tmp / "principals"
            principals_tmp.mkdir()
            
            # Decrypt realm key
            typer.echo(f"  Decrypting realm key...")
            realm_key_plain = realm_tmp / "realm.key"
            realm_key_content = crypto.decrypt_age(realm_key_enc)
            realm_key_plain.write_text(realm_key_content)
            
            # Decrypt existing principals
            principals_enc = realm_src / "principals"
            if principals_enc.exists():
                for princ_file in principals_enc.glob("*.age"):
                    princ_name = princ_file.stem  # Remove .age
                    typer.echo(f"  Decrypting principal: {princ_name}")
                    princ_content = crypto.decrypt_age(princ_file)
                    (principals_tmp / f"{princ_name}.key").write_text(princ_content)
            
            # Instantiate the realm database
            typer.echo(f"  Instantiating realm database...")
            try:
                kdc_conf = krb.instantiate_realm(realm, realm_tmp)
            except Exception as e:
                typer.echo(f"  Error instantiating realm: {e}", err=True)
                continue
            
            # Track which principals we've added
            new_principals: list[Path] = []
            
            # Process each host
            for hostname in hostnames:
                typer.echo(f"  Processing host: {hostname}")
                
                # Get master public key
                try:
                    master_pubkey = get_host_master_pubkey(hostname, repo, entities_path)
                except SystemExit:
                    typer.echo(f"    Skipping {hostname} (no master key)", err=True)
                    continue
                
                # Get host info for domain and services
                try:
                    host = entities.get_host(hostname, ent_path)
                except Exception as e:
                    typer.echo(f"    Error getting host info: {e}", err=True)
                    continue
                
                host_fqdn = f"{hostname}.{host.domain}"
                services = host.kerberos_services
                
                # Check if we need to add principals for this host
                needs_principals = False
                for svc in services:
                    princ_file = principals_tmp / f"{svc}_{host_fqdn}.key"
                    if not princ_file.exists():
                        needs_principals = True
                        break
                
                if needs_principals:
                    typer.echo(f"    Adding principals: {', '.join(services)}")
                    try:
                        added = krb.add_host_to_realm(
                            host_fqdn,
                            krb.RealmConfig(realm, realm_key_plain, principals_tmp),
                            kdc_conf,
                            services=services,
                        )
                        new_principals.extend(added)
                    except Exception as e:
                        typer.echo(f"    Error adding principals: {e}", err=True)
                        continue
                
                # Check if keytab already exists
                keytab_output = repo.host_build_path(hostname) / "keytab.age"
                if keytab_output.exists() and not force:
                    typer.echo(f"    Keytab exists (use --force to regenerate)")
                    continue
                
                # Extract keytab
                typer.echo(f"    Extracting keytab...")
                keytab_tmp = tmpdir / f"{hostname}.keytab"
                try:
                    krb.extract_host_keytab(
                        host_fqdn,
                        kdc_conf,
                        keytab_tmp,
                        services=services,
                    )
                except Exception as e:
                    typer.echo(f"    Error extracting keytab: {e}", err=True)
                    continue
                
                # Encrypt keytab for host + KDC role + admin
                host_age_key = crypto.ssh_pubkey_to_age(master_pubkey)
                recipients = [host_age_key, admin_pubkey]
                if kdc_role_pubkey:
                    recipients.append(kdc_role_pubkey)
                
                keytab_content = keytab_tmp.read_bytes()
                keytab_output.parent.mkdir(parents=True, exist_ok=True)
                
                # Encode keytab as base64 for age (binary handling)
                import base64
                keytab_b64 = base64.b64encode(keytab_content).decode("ascii")
                crypto.encrypt_age(keytab_b64, recipients, keytab_output)
                
                typer.echo(f"    Wrote: {keytab_output}")
            
            # Encrypt any new principals back to the repo
            if new_principals:
                typer.echo(f"\n  Saving {len(new_principals)} new principals...")
                principals_enc.mkdir(parents=True, exist_ok=True)
                
                for princ_file in new_principals:
                    if princ_file.exists():
                        princ_name = princ_file.stem  # e.g., "host_server.example.com"
                        princ_content = princ_file.read_text()
                        princ_out = principals_enc / f"{princ_name}.age"
                        
                        # Encrypt for admin only (principals are sensitive)
                        crypto.encrypt_age(princ_content, [admin_pubkey], princ_out)
                        typer.echo(f"    Saved: {princ_out.name}")
            
            # Generate consolidated KDC principals file
            typer.echo(f"\n  Generating KDC principals file...")
            all_principals = ""
            for princ_file in sorted(principals_tmp.glob("*.key")):
                all_principals += princ_file.read_text()
            
            if all_principals and kdc_role_pubkey:
                kdc_principals_out = repo.build_path / "kdc" / f"{realm}-principals.age"
                kdc_principals_out.parent.mkdir(parents=True, exist_ok=True)
                crypto.encrypt_age(all_principals, [kdc_role_pubkey, admin_pubkey], kdc_principals_out)
                typer.echo(f"  Wrote KDC principals: {kdc_principals_out}")
            elif not kdc_role_pubkey:
                typer.echo(f"  Warning: No KDC role configured, skipping KDC principals file")
    
    typer.secho("\nKeytab build complete!", fg=typer.colors.GREEN)


@app.command("build-user-secrets")
def build_user_secrets(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    user: Optional[str] = typer.Option(None, "--user", "-u", help="Process only this user"),
):
    """Collect and re-encrypt user secrets from user repos.
    
    User secrets are stored with privacy-preserving hashed filenames.
    A manifest file (manifest.age) is created for each user on each host,
    encrypted for both the host and the user, mapping hashed names to
    actual secret names and metadata.
    """
    import tempfile
    from . import manifest as mf
    
    repo = get_secrets_repo(secrets_path)
    ent_path = get_entities_path(entities_path)
    
    admin_pubkey = crypto.get_admin_public_key()
    
    # Get list of users to process
    if user:
        users = [user]
    else:
        users = repo.list_users()
    
    if not users:
        typer.echo("No users configured. Use 'aegis add-user' first.")
        return
    
    for username in users:
        typer.echo(f"\nProcessing user: {username}")
        
        user_config = repo.get_user_config(username)
        if not user_config:
            typer.echo(f"  Warning: No config found for {username}", err=True)
            continue
        
        if not user_config.hosts:
            typer.echo(f"  No hosts configured for {username}, skipping")
            continue
        
        # Get user's public key for manifest encryption
        user_pubkey = user_config.public_key
        if not user_pubkey:
            # Try to read from file
            user_pubkey_path = repo.user_pubkey_path(username)
            if user_pubkey_path.exists():
                user_pubkey = user_pubkey_path.read_text().strip()
        
        if not user_pubkey:
            typer.echo(f"  Warning: No public key found for {username}", err=True)
            typer.echo(f"  Manifest will only be encrypted for hosts (not user)", err=True)
        
        # Find the user's private key (for decrypting their repo)
        user_key_path = repo.user_key_path(username)
        if not user_key_path.exists():
            typer.echo(f"  Warning: No private key found at {user_key_path}", err=True)
            continue
        
        # Find the user's repo
        # First check flake inputs, then fall back to repo_url
        user_repo_path = _find_user_repo(repo, username, user_config)
        if not user_repo_path:
            typer.echo(f"  Warning: Could not find repo for {username}", err=True)
            typer.echo(f"  Set repo_url in user config or add as flake input")
            continue
        
        typer.echo(f"  Repo: {user_repo_path}")
        
        if dry_run:
            typer.echo(f"  [dry-run] Would process secrets for hosts: {', '.join(user_config.hosts)}")
            continue
        
        # Decrypt user's private key
        typer.echo(f"  Decrypting user key...")
        try:
            user_private_key = crypto.decrypt_age(user_key_path)
        except Exception as e:
            typer.echo(f"  Error decrypting user key: {e}", err=True)
            continue
        
        # Get host public keys for re-encryption
        host_keys: dict[str, str] = {}
        for hostname in user_config.hosts:
            try:
                master_pubkey = get_host_master_pubkey(hostname, repo, entities_path)
                host_age_key = crypto.ssh_pubkey_to_age(master_pubkey)
                host_keys[hostname] = host_age_key
            except SystemExit:
                typer.echo(f"  Warning: No master key for {hostname}, skipping", err=True)
            except Exception as e:
                typer.echo(f"  Warning: Could not get host {hostname}: {e}", err=True)
        
        if not host_keys:
            typer.echo(f"  No valid hosts found, skipping")
            continue
        
        # Create a manifest for each host (or load existing)
        host_manifests: dict[str, mf.Manifest] = {}
        for hostname in host_keys:
            manifest_path = repo.host_build_path(hostname) / "users" / username / "manifest.age"
            if manifest_path.exists():
                try:
                    host_manifests[hostname] = mf.load_manifest(
                        manifest_path,
                        lambda p: crypto.decrypt_age(p),
                    )
                except Exception:
                    # Can't decrypt existing manifest, start fresh
                    host_manifests[hostname] = mf.Manifest.empty()
            else:
                host_manifests[hostname] = mf.Manifest.empty()
        
        # Process environment variables
        env_dir = user_repo_path / "env"
        if env_dir.exists():
            env_secrets = _process_user_secrets_dir_with_manifest(
                env_dir, username, user_private_key, host_keys, 
                admin_pubkey, repo, "env", host_manifests,
            )
            typer.echo(f"  Processed {env_secrets} env vars")
        
        # Process files
        files_dir = user_repo_path / "files"
        if files_dir.exists():
            file_secrets = _process_user_secrets_dir_with_manifest(
                files_dir, username, user_private_key, host_keys,
                admin_pubkey, repo, "file", host_manifests,
            )
            typer.echo(f"  Processed {file_secrets} files")
        
        # Save manifests for each host (encrypted for host + user + admin)
        typer.echo(f"  Saving manifests...")
        for hostname, manifest in host_manifests.items():
            manifest_path = repo.host_build_path(hostname) / "users" / username / "manifest.age"
            manifest_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Recipients: host, user (if available), admin
            recipients = [host_keys[hostname], admin_pubkey]
            if user_pubkey:
                recipients.append(user_pubkey)
            
            mf.save_manifest(manifest, manifest_path, crypto.encrypt_age, recipients)
            typer.echo(f"    {hostname}: {len(manifest.secrets)} secrets")
    
    typer.secho("\nUser secrets build complete!", fg=typer.colors.GREEN)


def _find_user_repo(repo: config.SecretsRepo, username: str, user_config: config.UserConfig) -> Optional[Path]:
    """Find the path to a user's secrets repo.
    
    Checks:
    1. Flake input path (if running from flake context)
    2. Sibling directory (aegis-secrets-<username>)
    3. repo_url in config (would need to clone)
    """
    # Check for sibling directory
    sibling = repo.path.parent / f"aegis-secrets-{username}"
    if sibling.exists():
        return sibling
    
    # Check for flake input (set via environment)
    import os
    flake_input = os.environ.get(f"AEGIS_USER_REPO_{username.upper()}")
    if flake_input:
        flake_path = Path(flake_input)
        if flake_path.exists():
            return flake_path
    
    # Check inputs directory (common flake structure)
    inputs_dir = repo.path / "inputs" / f"aegis-secrets-{username}"
    if inputs_dir.exists():
        return inputs_dir
    
    return None


def _process_user_secrets_dir_with_manifest(
    source_dir: Path,
    username: str,
    user_private_key: str,
    host_keys: dict[str, str],
    admin_pubkey: str,
    repo: config.SecretsRepo,
    secret_type: str,  # "env" or "file"
    host_manifests: dict,  # hostname -> Manifest
) -> int:
    """Process a directory of user secrets with privacy-preserving hashed filenames.
    
    Decrypts each .age file, updates the manifest with a hashed filename,
    and re-encrypts for each host using that hashed name.
    
    Returns number of secrets processed.
    """
    import tempfile
    from . import manifest as mf
    
    count = 0
    
    for secret_file in source_dir.glob("*.age"):
        secret_name = secret_file.stem  # Remove .age extension
        
        # Decrypt with user's key
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".key", delete=False) as f:
                f.write(user_private_key)
                temp_key = Path(f.name)
            
            try:
                secret_content = crypto.decrypt_age(secret_file, identity_path=temp_key)
            finally:
                temp_key.unlink()
                
        except Exception as e:
            typer.echo(f"    Warning: Could not decrypt {secret_name}: {e}", err=True)
            continue
        
        # Re-encrypt for each host using hashed filename
        for hostname, host_key in host_keys.items():
            manifest = host_manifests[hostname]
            
            # Get or create hashed filename for this secret
            hashed_name = manifest.add_or_update(
                name=secret_name,
                secret_type=secret_type,
            )
            
            output_dir = repo.host_build_path(hostname) / "users" / username / "secrets"
            output_file = output_dir / f"{hashed_name}.age"
            
            output_dir.mkdir(parents=True, exist_ok=True)
            crypto.encrypt_age(secret_content, [host_key, admin_pubkey], output_file)
        
        count += 1
    
    return count


@app.command("build-bundles")
def build_bundles(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
):
    """Package all secrets into host bundles."""
    typer.echo("build-bundles: Not yet implemented")
    # TODO: Create final host bundle structure


# =============================================================================
# Import Commands
# =============================================================================

@app.command("import-ssh-host-keys")
def import_ssh_host_keys(
    hostname: str = typer.Argument(..., help="Hostname to import keys for"),
    key_files: list[Path] = typer.Option([], "--key", help="Path to SSH private key file (type auto-detected, can specify multiple)"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
):
    """Import SSH host keys for OpenSSH server (NOT the master key).
    
    This imports the SSH keys that OpenSSH will use to identify the server
    to clients (ssh_host_ed25519_key, ssh_host_ecdsa_key, etc.).
    
    These are NOT the master key! The master key is used to ENCRYPT these
    SSH host keys. The master key public should be set via 'set-master-key'
    or come from nix-entities.
    
    This command:
    - Auto-detects key type (ed25519, ecdsa, rsa)
    - Derives public keys automatically
    - Encrypts with the host's master key + admin key
    - Stores in build/hosts/<hostname>/ssh-host-keys.age
    
    Example:
        aegis import-ssh-host-keys lambda \\
            --key /secure/lambda.ed25519.key \\
            --key /secure/lambda.ecdsa.key
    """
    from . import ssh_utils
    
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    # Check if at least one key provided
    if not key_files:
        typer.echo("Error: At least one private key must be provided (use --key)", err=True)
        raise typer.Exit(1)
    
    typer.echo(f"Importing SSH host keys for {hostname}...")
    typer.echo(f"  (These are OpenSSH server keys, NOT the master key)")
    
    # Get master public key (from config or entities)
    master_pubkey = get_host_master_pubkey(hostname, repo, entities_path)
    
    # Ensure host config exists (create if missing)
    host_config = repo.get_host_config(hostname)
    if not host_config:
        typer.echo(f"  Host config not found, creating...")
        # Try to get services from entities if available
        services = ["host", "ssh"]
        try:
            ent_path = get_entities_path(entities_path)
            host = entities.get_host(hostname, ent_path)
            services = host.kerberos_services
        except Exception:
            pass
        host_config = config.HostConfig(
            hostname=hostname,
            services=services,
        )
        repo.set_host_config(host_config)
        typer.echo(f"  Created {repo.src_path / 'hosts' / f'{hostname}.toml'}")
    
    # Read and validate private keys, derive public keys
    try:
        keypairs = ssh_utils.read_ssh_keypairs(
            hostname=hostname,
            key_files=key_files,
        )
    except (FileNotFoundError, ValueError) as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    
    if not keypairs:
        typer.echo("Error: No valid keypairs found", err=True)
        raise typer.Exit(1)
    
    typer.echo(f"  Detected {len(keypairs)} keypair(s):")
    for kp in keypairs:
        typer.echo(f"    - {kp.key_type}")
        typer.echo(f"      Public key: {kp.public_key[:60]}...")
    
    # Convert to YAML format
    keys_dict = {}
    for kp in keypairs:
        key_prefix = f"host_{kp.key_type}"
        keys_dict[key_prefix] = {
            "public_key": kp.public_key,
            "private_key": kp.private_key,
        }
    
    keys_yaml = yaml.dump(keys_dict, default_flow_style=False)
    
    # Get recipients (host master key + admin key)
    host_age_key = crypto.ssh_pubkey_to_age(master_pubkey)
    admin_pubkey = crypto.get_admin_public_key()
    recipients = [host_age_key, admin_pubkey]
    
    # Encrypt and write
    output_path = repo.host_build_path(hostname) / "ssh-host-keys.age"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(keys_yaml, recipients, output_path)
    
    typer.secho(f"\nSSH host keys imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Output: {output_path}")
    typer.echo(f"  Encrypted for: {hostname} (master key) + admin")
    typer.echo(f"  These keys are for OpenSSH server identity.")


@app.command("import-nexus-key")
def import_nexus_key(
    hostname: str = typer.Argument(..., help="Hostname to import key for"),
    key_file: Path = typer.Option(..., "--file", help="Path to nexus HMAC key file"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
):
    """Import a Nexus DDNS authentication key for a host.
    
    Imports an existing Nexus HMAC key. The key should be in the format:
    HmacSHA512:base64encodedkey
    
    Example:
        aegis import-nexus-key lambda --file /secure/lambda.nexus.hmac
    """
    from . import nexus
    
    repo = get_secrets_repo(secrets_path)
    ent_path = get_entities_path(entities_path)
    repo.ensure_structure()
    
    if not key_file.exists():
        typer.echo(f"Error: Key file not found: {key_file}", err=True)
        raise typer.Exit(1)
    
    typer.echo(f"Importing Nexus key for {hostname}...")
    
    # Get master public key
    master_pubkey = get_host_master_pubkey(hostname, repo, entities_path)
    
    # Ensure host config exists
    host_config = repo.get_host_config(hostname)
    if not host_config:
        typer.echo(f"  Host config not found, creating...")
        # Try to get services from entities if available
        services = ["host", "ssh"]
        try:
            ent_path = get_entities_path(entities_path)
            host = entities.get_host(hostname, ent_path)
            services = host.kerberos_services
        except Exception:
            pass
        host_config = config.HostConfig(
            hostname=hostname,
            services=services,
        )
        repo.set_host_config(host_config)
        typer.echo(f"  Created {repo.src_path / 'hosts' / f'{hostname}.toml'}")
    
    # Read and validate key
    key_content = key_file.read_text().strip()
    
    try:
        algo, encoded_key = nexus.read_key(key_file)
        typer.echo(f"  Algorithm: {algo}")
        typer.echo(f"  Key length: {len(encoded_key)} characters (base64)")
    except ValueError as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(1)
    
    # Get recipients
    host_age_key = crypto.ssh_pubkey_to_age(master_pubkey)
    admin_pubkey = crypto.get_admin_public_key()
    recipients = [host_age_key, admin_pubkey]
    
    # Encrypt and write
    output_path = repo.host_build_path(hostname) / "nexus-key.age"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(key_content, recipients, output_path)
    
    typer.secho(f"\nNexus key imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Output: {output_path}")
    typer.echo(f"  Encrypted for: {hostname} (host) + admin")


@app.command("import-kerberos-realm")
def import_kerberos_realm(
    realm: str = typer.Argument(..., help="Realm name (e.g., SEA.FUDO.ORG)"),
    realm_key: Path = typer.Option(..., "--realm-key", help="Path to realm master key file"),
    principals_dir: Path = typer.Option(..., "--principals-dir", help="Path to directory containing principal key files"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Import a Kerberos realm with its master key and principal keys.
    
    This imports an existing Kerberos realm structure:
    - realm.key: The realm master key
    - principals/: Directory containing principal key files (e.g., krbtgt_REALM.key, host_fqdn.key)
    
    All keys will be encrypted with the admin key and stored in
    src/kerberos/realms/<REALM>/ for use by aegis build-keytabs.
    
    Example:
        aegis import-kerberos-realm SEA.FUDO.ORG \\
            --realm-key /secure/realms/SEA.FUDO.ORG/realm.key \\
            --principals-dir /secure/realms/SEA.FUDO.ORG/principals/
    """
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    if not realm_key.exists():
        typer.echo(f"Error: Realm key not found: {realm_key}", err=True)
        raise typer.Exit(1)
    
    if not principals_dir.exists() or not principals_dir.is_dir():
        typer.echo(f"Error: Principals directory not found: {principals_dir}", err=True)
        raise typer.Exit(1)
    
    typer.echo(f"Importing Kerberos realm: {realm}")
    
    # Create realm directory
    realm_dir = repo.src_path / "kerberos" / "realms" / realm
    realm_dir.mkdir(parents=True, exist_ok=True)
    principals_out_dir = realm_dir / "principals"
    principals_out_dir.mkdir(exist_ok=True)
    
    admin_pubkey = crypto.get_admin_public_key()
    
    # Import realm master key
    typer.echo(f"  Importing realm master key...")
    realm_key_content = realm_key.read_text()
    realm_key_out = realm_dir / "realm.key.age"
    crypto.encrypt_age(realm_key_content, [admin_pubkey], realm_key_out)
    typer.echo(f"    Wrote {realm_key_out}")
    
    # Import principal keys
    principal_files = list(principals_dir.glob("*.key"))
    if not principal_files:
        typer.echo("  Warning: No principal key files found (*.key)", err=True)
    
    typer.echo(f"  Importing {len(principal_files)} principal(s)...")
    for principal_file in principal_files:
        principal_name = principal_file.stem
        principal_content = principal_file.read_text()
        
        output_file = principals_out_dir / f"{principal_name}.age"
        crypto.encrypt_age(principal_content, [admin_pubkey], output_file)
        typer.echo(f"    - {principal_name}")
    
    typer.secho(f"\nKerberos realm imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Location: {realm_dir}")
    typer.echo(f"  Realm master key: {realm_key_out.name}")
    typer.echo(f"  Principals: {len(principal_files)}")
    typer.echo(f"\nNext: Run 'aegis build-keytabs' to generate host keytabs")


@app.command("import-secret")
def import_secret(
    hostname: str = typer.Argument(..., help="Hostname this secret belongs to"),
    secret_name: str = typer.Argument(..., help="Name of the secret"),
    file: Path = typer.Option(..., "--file", help="Path to secret file"),
    target: str = typer.Option(..., "--target", help="Target path on host (e.g., /run/service/config)"),
    user: str = typer.Option("root", "--user", help="Owner user on target host"),
    group: str = typer.Option("root", "--group", help="Owner group on target host"),
    mode: str = typer.Option("0400", "--mode", help="File permissions (e.g., 0600)"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
):
    """Import a generic secret for a host.
    
    This is for service-specific or custom secrets that don't fit the standard
    categories (SSH, Nexus, Kerberos). The secret will be encrypted and metadata
    about target path, ownership, and permissions will be stored in the host config.
    
    Example:
        aegis import-secret lambda my-service-token \\
            --file /secure/lambda-service.token \\
            --target /run/myservice/token \\
            --user myservice --group myservice --mode 0600
    """
    repo = get_secrets_repo(secrets_path)
    ent_path = get_entities_path(entities_path)
    repo.ensure_structure()
    
    if not file.exists():
        typer.echo(f"Error: Secret file not found: {file}", err=True)
        raise typer.Exit(1)
    
    typer.echo(f"Importing secret '{secret_name}' for {hostname}...")
    
    # Get master public key
    master_pubkey = get_host_master_pubkey(hostname, repo, entities_path)
    
    # Ensure host config exists
    host_config = repo.get_host_config(hostname)
    if not host_config:
        typer.echo(f"  Host config not found, creating...")
        # Try to get services from entities if available
        services = ["host", "ssh"]
        try:
            ent_path = get_entities_path(entities_path)
            host = entities.get_host(hostname, ent_path)
            services = host.kerberos_services
        except Exception:
            pass
        host_config = config.HostConfig(
            hostname=hostname,
            services=services,
        )
    
    # Add secret metadata to host config
    host_config.extra_secrets[secret_name] = {
        "target": target,
        "user": user,
        "group": group,
        "mode": mode,
    }
    repo.set_host_config(host_config)
    
    # Read secret content
    secret_content = file.read_text()
    
    # Get recipients
    host_age_key = crypto.ssh_pubkey_to_age(master_pubkey)
    admin_pubkey = crypto.get_admin_public_key()
    recipients = [host_age_key, admin_pubkey]
    
    # Encrypt and write
    output_path = repo.host_build_path(hostname) / f"{secret_name}.age"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(secret_content, recipients, output_path)
    
    typer.secho(f"\nSecret imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Output: {output_path}")
    typer.echo(f"  Target: {target}")
    typer.echo(f"  Owner: {user}:{group}")
    typer.echo(f"  Mode: {mode}")
    typer.echo(f"  Metadata stored in: {repo.src_path / 'hosts' / f'{hostname}.toml'}")


# =============================================================================
# Configuration Commands
# =============================================================================

@app.command("sync-hosts")
def sync_hosts(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
    pull: bool = typer.Option(False, "--pull", "-p", help="Git pull entities repo before syncing"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Show what would be done"),
    filter_domain: Optional[str] = typer.Option(None, "--domain", "-d", help="Only sync hosts in this domain"),
):
    """Sync hosts from nix-entities to aegis-secrets.
    
    This command discovers all hosts in nix-entities that have master keys
    configured and creates corresponding host configs in aegis-secrets.
    
    For each host found:
    - Creates src/hosts/<hostname>.toml if it doesn't exist
    - Sets master_pubkey from entities
    - Sets kerberos services from entities
    
    This is idempotent - running it multiple times is safe. It will:
    - Skip hosts that already have configs
    - Update master keys if they've changed (with --force)
    
    Typically run as part of the build process or when new hosts are added.
    
    Example:
        aegis sync-hosts --pull
        aegis sync-hosts --domain sea.fudo.org
    """
    repo = get_secrets_repo(secrets_path)
    ent_path = get_entities_path(entities_path)
    repo.ensure_structure()
    
    # Optionally pull the entities repo
    if pull:
        typer.echo(f"Pulling entities repo at {ent_path}...")
        try:
            import subprocess
            result = subprocess.run(
                ["git", "pull"],
                cwd=ent_path,
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                typer.echo(f"  {result.stdout.strip()}")
            else:
                typer.echo(f"  Warning: git pull failed: {result.stderr}", err=True)
        except Exception as e:
            typer.echo(f"  Warning: Could not pull: {e}", err=True)
    
    typer.echo(f"Syncing hosts from {ent_path}...")
    
    # Get all hosts from entities
    try:
        all_hosts = entities.get_all_hosts(ent_path)
    except Exception as e:
        typer.echo(f"Error: Could not list hosts from entities: {e}", err=True)
        raise typer.Exit(1)
    
    typer.echo(f"  Found {len(all_hosts)} hosts in entities")
    
    created = 0
    skipped = 0
    no_master_key = 0
    filtered_out = 0
    
    for hostname in sorted(all_hosts):
        try:
            host = entities.get_host(hostname, ent_path)
        except Exception as e:
            typer.echo(f"  {hostname}: Error getting host info: {e}", err=True)
            continue
        
        # Filter by domain if specified
        if filter_domain and host.domain != filter_domain:
            filtered_out += 1
            continue
        
        # Skip hosts without master keys
        if not host.master_key or not host.master_key.public_key:
            if dry_run:
                typer.echo(f"  {hostname}: No master key configured, skipping")
            no_master_key += 1
            continue
        
        # Check if config already exists
        existing = repo.get_host_config(hostname)
        if existing:
            # Check if master key needs updating
            if existing.master_pubkey != host.master_key.public_key:
                if dry_run:
                    typer.echo(f"  {hostname}: Master key changed (would update)")
                else:
                    existing.master_pubkey = host.master_key.public_key
                    existing.services = host.kerberos_services
                    repo.set_host_config(existing)
                    typer.echo(f"  {hostname}: Updated master key")
                    created += 1
            else:
                skipped += 1
            continue
        
        # Create new host config
        if dry_run:
            typer.echo(f"  {hostname}: Would create config (domain={host.domain})")
            created += 1
            continue
        
        host_config = config.HostConfig(
            hostname=hostname,
            master_pubkey=host.master_key.public_key,
            services=host.kerberos_services,
        )
        repo.set_host_config(host_config)
        typer.echo(f"  {hostname}: Created config (domain={host.domain})")
        created += 1
    
    typer.echo("")
    if dry_run:
        typer.secho("[DRY-RUN] Summary:", fg=typer.colors.YELLOW)
    else:
        typer.secho("Summary:", fg=typer.colors.GREEN)
    typer.echo(f"  Created/updated: {created}")
    typer.echo(f"  Already configured: {skipped}")
    typer.echo(f"  No master key: {no_master_key}")
    if filter_domain:
        typer.echo(f"  Filtered out (wrong domain): {filtered_out}")


@app.command("init-host")
def init_host(
    hostname: str = typer.Argument(..., help="Hostname to initialize"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    services: str = typer.Option("host,ssh", "--services", help="Comma-separated Kerberos services"),
):
    """Add a host to the secrets configuration.
    
    This initializes a host in the aegis-secrets repository. When you run
    'aegis build', the following will be generated for this host:
    - SSH host keys (ed25519, ecdsa, rsa)
    - Nexus DDNS authentication key
    - Kerberos keytabs (if configured)
    """
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    existing = repo.get_host_config(hostname)
    if existing:
        typer.echo(f"Host {hostname} already configured")
        raise typer.Exit(1)
    
    service_list = [s.strip() for s in services.split(",")]
    
    host_config = config.HostConfig(
        hostname=hostname,
        services=service_list,
    )
    repo.set_host_config(host_config)
    
    typer.secho(f"Initialized host: {hostname}", fg=typer.colors.GREEN)
    typer.echo(f"  Services: {', '.join(service_list)}")
    typer.echo(f"  Config: {repo.src_path / 'hosts' / f'{hostname}.toml'}")
    typer.echo("")
    typer.echo("Next:")
    typer.echo("  1. Set master key: aegis set-master-key {hostname} --public-key 'ssh-ed25519 ...'")
    typer.echo("  2. Build secrets:  aegis build")


@app.command("set-master-key")
def set_master_key(
    hostname: str = typer.Argument(..., help="Hostname to set master key for"),
    public_key: str = typer.Option(..., "--public-key", "-k", help="SSH public key (e.g., 'ssh-ed25519 AAAA...')"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Set the master public key for a host.
    
    The master key is used to ENCRYPT secrets for this host. The host must have
    the corresponding private key to decrypt secrets at boot time.
    
    This is NOT an SSH host key for OpenSSH! This is the key Aegis uses to
    encrypt secrets that only this host can decrypt.
    
    The public key should be in SSH format: "ssh-ed25519 AAAA... comment"
    
    Typical setup:
    1. Host has master private key at /state/master-key/key (persistent storage)
    2. You extract the public key: ssh-keygen -y -f /state/master-key/key
    3. You set it here: aegis set-master-key lambda --public-key "ssh-ed25519 AAAA..."
    
    Example:
        aegis set-master-key lambda --public-key "ssh-ed25519 AAAAC3Nza... lambda-master"
    """
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    # Validate the public key format
    public_key = public_key.strip()
    if not public_key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
        typer.echo("Error: Public key must be in SSH format", err=True)
        typer.echo("  Expected: ssh-ed25519 AAAA... or ssh-rsa AAAA... or ecdsa-sha2-...", err=True)
        raise typer.Exit(1)
    
    # Test that we can convert it to age format
    try:
        age_key = crypto.ssh_pubkey_to_age(public_key)
    except Exception as e:
        typer.echo(f"Error: Could not convert SSH key to age format: {e}", err=True)
        typer.echo("  Make sure the key is a valid SSH public key", err=True)
        raise typer.Exit(1)
    
    # Get or create host config
    host_config = repo.get_host_config(hostname)
    if not host_config:
        typer.echo(f"Creating new host config for {hostname}...")
        host_config = config.HostConfig(
            hostname=hostname,
            master_pubkey=public_key,
        )
    else:
        host_config.master_pubkey = public_key
    
    repo.set_host_config(host_config)
    
    typer.secho(f"Master key set for {hostname}", fg=typer.colors.GREEN)
    typer.echo(f"  SSH public key: {public_key[:50]}...")
    typer.echo(f"  Age public key: {age_key}")
    typer.echo(f"  Config: {repo.src_path / 'hosts' / f'{hostname}.toml'}")
    typer.echo("")
    typer.echo("Now you can encrypt secrets for this host with 'aegis build'")


@app.command("add-user")
def add_user(
    username: str = typer.Argument(..., help="Username"),
    hosts: str = typer.Option(..., "--hosts", "-h", help="Comma-separated list of hosts user can access"),
    repo_url: Optional[str] = typer.Option(None, "--repo-url", help="URL of user's secrets repo"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Add a user and generate their keypair."""
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    existing = repo.get_user_config(username)
    if existing:
        typer.echo(f"User {username} already configured")
        raise typer.Exit(1)
    
    host_list = [h.strip() for h in hosts.split(",")]
    
    # Generate keypair for user
    typer.echo(f"Generating keypair for {username}...")
    keypair = crypto.generate_age_keypair()
    
    # Encrypt private key for admin
    admin_pubkey = crypto.get_admin_public_key()
    user_key_path = repo.user_key_path(username)
    user_key_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(keypair.private_key, [admin_pubkey], user_key_path)
    
    # Save public key (for manifest encryption)
    user_pubkey_path = repo.user_pubkey_path(username)
    user_pubkey_path.write_text(keypair.public_key + "\n")
    
    # Save user config (including public key for convenience)
    user_config = config.UserConfig(
        username=username,
        hosts=host_list,
        repo_url=repo_url,
        public_key=keypair.public_key,
    )
    repo.set_user_config(user_config)
    
    typer.secho(f"Added user: {username}", fg=typer.colors.GREEN)
    typer.echo(f"  Hosts: {', '.join(host_list)}")
    typer.echo(f"  Private key: {user_key_path}")
    typer.echo(f"  Public key: {user_pubkey_path}")
    typer.echo("")
    typer.secho("Give this public key to the user:", fg=typer.colors.YELLOW)
    typer.echo(keypair.public_key)


@app.command("add-secret")
def add_secret(
    hostname: str = typer.Argument(..., help="Target hostname"),
    name: str = typer.Argument(..., help="Secret name"),
    file: Path = typer.Argument(..., help="File containing the secret"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
):
    """Add a user-provided secret for a host."""
    repo = get_secrets_repo(secrets_path)
    if not file.exists():
        typer.echo(f"Error: File not found: {file}", err=True)
        raise typer.Exit(1)
    
    # Get master public key
    master_pubkey = get_host_master_pubkey(hostname, repo, entities_path)
    
    # Read secret
    content = file.read_text()
    
    # Encrypt
    admin_pubkey = crypto.get_admin_public_key()
    host_age_key = crypto.ssh_pubkey_to_age(master_pubkey)
    
    output_path = repo.host_build_path(hostname) / f"{name}.age"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    crypto.encrypt_age(content, [host_age_key, admin_pubkey], output_path)
    
    typer.secho(f"Added secret: {name} for {hostname}", fg=typer.colors.GREEN)
    typer.echo(f"  Wrote: {output_path}")


# =============================================================================
# Role Commands
# =============================================================================

@app.command("init-realm")
def init_realm(
    realm: str = typer.Argument(..., help="Realm name (e.g., FUDO.ORG)"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Initialize a new Kerberos realm."""
    from . import kerberos as krb
    import tempfile
    
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    realm_dir = repo.src_path / "kerberos" / "realms" / realm
    if realm_dir.exists():
        typer.echo(f"Realm {realm} already exists at {realm_dir}")
        raise typer.Exit(1)
    
    typer.echo(f"Initializing Kerberos realm: {realm}")
    
    admin_pubkey = crypto.get_admin_public_key()
    
    with tempfile.TemporaryDirectory(prefix="aegis-realm-init-") as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Initialize realm in temp directory
        typer.echo("  Generating realm master key and initial database...")
        realm_config = krb.initialize_realm(realm, tmpdir, verbose=True)
        
        # Create encrypted realm directory
        realm_dir.mkdir(parents=True, exist_ok=True)
        principals_dir = realm_dir / "principals"
        principals_dir.mkdir()
        
        # Encrypt realm key
        typer.echo("  Encrypting realm key...")
        realm_key_content = realm_config.key_path.read_text()
        crypto.encrypt_age(realm_key_content, [admin_pubkey], realm_dir / "realm.key.age")
        
        # Encrypt any initial principals (usually just krbtgt)
        for princ_file in realm_config.principals_path.glob("*.key"):
            princ_name = princ_file.stem
            typer.echo(f"  Encrypting principal: {princ_name}")
            princ_content = princ_file.read_text()
            crypto.encrypt_age(princ_content, [admin_pubkey], principals_dir / f"{princ_name}.age")
    
    typer.secho(f"\nRealm {realm} initialized!", fg=typer.colors.GREEN)
    typer.echo(f"  Location: {realm_dir}")
    typer.echo(f"\nNext steps:")
    typer.echo(f"  1. Run 'aegis init-role kdc <hostname>' to set up the KDC role")
    typer.echo(f"  2. Run 'aegis build-keytabs' to generate host keytabs")


@app.command("init-role")
def init_role(
    role: str = typer.Argument(..., help="Role name (e.g., kdc, dns)"),
    hostname: str = typer.Argument(..., help="Host that will have this role"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
):
    """Create a role and assign it to a host."""
    repo = get_secrets_repo(secrets_path)
    ent_path = get_entities_path(entities_path)
    repo.ensure_structure()
    
    existing = repo.get_role_config(role)
    if existing:
        typer.echo(f"Role {role} already exists (assigned to {existing.host})")
        raise typer.Exit(1)
    
    # Get master public key
    master_pubkey = get_host_master_pubkey(hostname, repo, entities_path)
    
    # Generate role keypair
    typer.echo(f"Generating keypair for role {role}...")
    keypair = crypto.generate_age_keypair()
    
    # Encrypt role private key for the host and admin
    admin_pubkey = crypto.get_admin_public_key()
    host_age_key = crypto.ssh_pubkey_to_age(master_pubkey)
    
    role_key_path = repo.role_build_path(role) / f"{role}.age"
    role_key_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(keypair.private_key, [host_age_key, admin_pubkey], role_key_path)
    
    # Save public key
    role_pub_path = repo.role_build_path(role) / f"{role}.pub"
    role_pub_path.write_text(keypair.public_key)
    
    # Save role config
    role_config = config.RoleConfig(name=role, host=hostname)
    repo.set_role_config(role_config)
    
    typer.secho(f"Created role: {role}", fg=typer.colors.GREEN)
    typer.echo(f"  Assigned to: {hostname}")
    typer.echo(f"  Public key: {keypair.public_key}")


# =============================================================================
# Nexus DDNS Commands
# =============================================================================

@app.command("nexus-keygen")
def nexus_keygen(
    output: Path = typer.Argument(..., help="Output file path for the key"),
    algorithm: str = typer.Option("HmacSHA512", "--algorithm", "-a", help="HMAC algorithm (e.g., HmacSHA256, HmacSHA512)"),
    seed: Optional[str] = typer.Option(None, "--seed", "-s", help="Seed for key generation (for reproducibility)"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print verbose output"),
):
    """Generate a Nexus DDNS authentication key.
    
    Creates an HMAC key for authenticating Nexus DDNS clients to servers.
    The key is written in the format: ALGORITHM:BASE64_ENCODED_KEY
    
    Example:
        aegis nexus-keygen server.key
        aegis nexus-keygen client.key --algorithm HmacSHA256
    """
    from . import nexus
    
    typer.echo(f"Generating Nexus key with algorithm: {algorithm}")
    
    try:
        key_path = nexus.generate_key(
            output_path=output,
            algorithm=algorithm,
            seed=seed,
            verbose=verbose,
        )
        
        typer.secho(f"\nKey generated successfully!", fg=typer.colors.GREEN)
        typer.echo(f"  Location: {key_path}")
        
        # Show the algorithm
        algo, _ = nexus.read_key(key_path)
        typer.echo(f"  Algorithm: {algo}")
        
    except Exception as e:
        typer.echo(f"Error generating key: {e}", err=True)
        raise typer.Exit(1)


# =============================================================================
# Utility Commands
# =============================================================================

@app.command("status")
def status(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Show what needs building."""
    repo = get_secrets_repo(secrets_path)
    
    typer.echo("Aegis Secrets Status")
    typer.echo("=" * 40)
    
    hosts = repo.list_hosts()
    users = repo.list_users()
    roles = repo.list_roles()
    
    typer.echo(f"\nConfigured hosts: {len(hosts)}")
    for hostname in hosts:
        build_path = repo.host_build_path(hostname)
        ssh_exists = (build_path / "ssh-keys.age").exists()
        status_icon = "[green]✓[/green]" if ssh_exists else "[yellow]○[/yellow]"
        typer.echo(f"  {hostname}: SSH={'yes' if ssh_exists else 'no'}")
    
    typer.echo(f"\nConfigured users: {len(users)}")
    for username in users:
        user_config = repo.get_user_config(username)
        if user_config:
            typer.echo(f"  {username}: hosts={','.join(user_config.hosts)}")
    
    typer.echo(f"\nConfigured roles: {len(roles)}")
    for role in roles:
        role_config = repo.get_role_config(role)
        if role_config:
            typer.echo(f"  {role}: host={role_config.host}")


@app.command("list")
def list_secrets(
    hostname: Optional[str] = typer.Argument(None, help="Hostname (optional, list all if omitted)"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """List secrets for a host or all hosts."""
    repo = get_secrets_repo(secrets_path)
    
    if hostname:
        hosts = [hostname]
    else:
        hosts = repo.list_hosts()
    
    for host in hosts:
        typer.echo(f"\n{host}:")
        build_path = repo.host_build_path(host)
        
        if not build_path.exists():
            typer.echo("  (no build output)")
            continue
        
        for secret_file in sorted(build_path.glob("*.age")):
            size = secret_file.stat().st_size
            typer.echo(f"  {secret_file.name} ({size} bytes)")


@app.command("verify")
def verify(
    hostname: str = typer.Argument(..., help="Hostname to verify"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
):
    """Verify a host can decrypt its secrets."""
    repo = get_secrets_repo(secrets_path)
    ent_path = get_entities_path(entities_path)
    
    # This would require having the host's private key, which we don't
    # In practice, verification happens at deployment time
    typer.echo(f"Verification for {hostname}:")
    typer.echo("  Note: Full verification requires the host's private key")
    typer.echo("  Checking that secrets exist and are properly formatted...")
    
    build_path = repo.host_build_path(hostname)
    if not build_path.exists():
        typer.echo("  No build output found")
        raise typer.Exit(1)
    
    for secret_file in build_path.glob("*.age"):
        # Just check it's valid age format (starts with age header)
        content = secret_file.read_text()
        if content.startswith("-----BEGIN AGE ENCRYPTED FILE-----"):
            typer.echo(f"  {secret_file.name}: OK (valid age format)")
        else:
            typer.echo(f"  {secret_file.name}: WARNING (unexpected format)")


def main():
    app()


if __name__ == "__main__":
    main()
