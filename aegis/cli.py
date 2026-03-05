"""Aegis CLI - System administration tools for secrets management."""

import os
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer

from . import crypto, ssh, config

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



def get_host_age_pubkey(
    hostname: str,
    repo: config.SecretsRepo,
) -> str:
    """Get the age public key for a host from its config in aegis-secrets.

    Returns:
        age public key string (e.g., "age1...")

    Raises:
        typer.Exit if no key found
    """
    host_config = repo.get_host_config(hostname)
    if host_config and host_config.age_pubkey:
        return host_config.age_pubkey

    typer.echo(f"Error: No age key configured for {hostname}", err=True)
    typer.echo(f"Set it with: aegis set-master-key {hostname} --public-key 'age1...'", err=True)
    raise typer.Exit(1)


# =============================================================================
# Build Commands
# =============================================================================

@app.command()
def build(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to aegis-secrets repo"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Show what would be done"),
):
    """Run full build: generate missing secrets for all configured hosts.

    This will:
    1. Generate SSH host keys for OpenSSH
    2. Generate Nexus DDNS keys
    3. Generate Kerberos keytabs
    4. Build user secrets
    """
    repo = get_secrets_repo(secrets_path)

    typer.echo("Running full build...")

    if dry_run:
        typer.echo("  [dry-run] Would run: build-ssh-host-keys")
        typer.echo("  [dry-run] Would run: build-nexus-keys")
        typer.echo("  [dry-run] Would run: build-keytabs")
        typer.echo("  [dry-run] Would run: build-user-secrets")
        return

    # Run each build step
    typer.echo("\n--- Building SSH Host Keys ---")
    build_ssh_host_keys(secrets_path=secrets_path, dry_run=False)

    typer.echo("\n--- Building Nexus Keys ---")
    build_nexus_keys(secrets_path=secrets_path, dry_run=False, algorithm="HmacSHA512")

    typer.echo("\n--- Building Keytabs ---")
    build_keytabs(secrets_path=secrets_path, dry_run=False)

    typer.echo("\n--- Building User Secrets ---")
    build_user_secrets(secrets_path=secrets_path, dry_run=False, user=None)

    typer.secho("\nBuild complete!", fg=typer.colors.GREEN)


@app.command("build-ssh-host-keys")
def build_ssh_host_keys(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    force: Annotated[bool, typer.Option("--force", "-f", help="Regenerate even if keys exist")] = False,
    target_dir: Annotated[str, typer.Option("--target-dir", help="Target directory for SSH keys")] = "/run/aegis/ssh",
    user: Annotated[str, typer.Option("--user", help="Owner user for key files")] = "root",
    group: Annotated[str, typer.Option("--group", help="Owner group for key files")] = "root",
    mode: Annotated[str, typer.Option("--mode", help="Permissions for private key files")] = "0600",
):
    """Generate SSH host keys for OpenSSH servers.
    
    This generates the keys that OpenSSH will use to identify the server
    (ssh_host_ed25519_key, ssh_host_ecdsa_key, etc.).
    
    These are NOT master keys! Master keys are used to encrypt these host keys.
    
    Each private key is encrypted separately as its own age file under
    build/hosts/<hostname>/ssh/.  The corresponding public keys are written
    as plaintext .pub files alongside for use in DNS or known_hosts files.

    Deployment metadata is stored in build/hosts/<hostname>/secrets.toml
    for NixOS to import.

    Also generates SSHFP DNS records for trust establishment.
    """
    from . import host_secrets

    repo = get_secrets_repo(secrets_path)

    hosts = repo.list_hosts()
    if not hosts:
        typer.echo("No hosts configured. Use 'aegis init-host' first.")
        return

    admin_pubkey = crypto.get_admin_public_key()

    for hostname in hosts:
        ssh_dir = repo.host_build_path(hostname) / "ssh"

        if ssh_dir.exists() and any(ssh_dir.glob("*.age")) and not force:
            typer.echo(f"  {hostname}: SSH host keys exist (use --force to regenerate)")
            continue

        if dry_run:
            typer.echo(f"  [dry-run] Would generate SSH host keys for {hostname}")
            continue

        typer.echo(f"  Generating SSH host keys for {hostname}...")

        # Get age public key from host config
        try:
            host_age_key = get_host_age_pubkey(hostname, repo)
        except SystemExit:
            typer.echo(f"    Skipping {hostname} (no age key)", err=True)
            continue

        # Generate keys
        keys = ssh.generate_host_keys(hostname)

        # Encrypt each private key separately; write each public key plaintext
        recipients = [host_age_key, admin_pubkey]
        ssh_dir.mkdir(parents=True, exist_ok=True)

        for stem, keypair in keys.items():
            age_path = ssh_dir / f"{stem}.age"
            pub_path = ssh_dir / f"{stem}.pub"
            crypto.encrypt_age(keypair.private_key, recipients, age_path)
            pub_path.write_text(keypair.public_key + "\n")
            typer.echo(f"    Wrote {age_path.name} + {pub_path.name}")

        # Update manifest with one entry per private key
        manifest = host_secrets.load_host_manifest(repo.build_path, hostname)
        stems = [stem for stem, _ in keys.items()]
        manifest.ssh_host_keys = host_secrets.make_ssh_host_keys_entries(
            stems=stems,
            target_dir=target_dir,
            user=user,
            group=group,
            mode=mode,
        )
        manifest_path = host_secrets.save_host_manifest(repo.build_path, manifest)
        typer.echo(f"    Updated manifest: {manifest_path}")

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
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    force: Annotated[bool, typer.Option("--force", "-f", help="Regenerate even if keys exist")] = False,
    algorithm: Annotated[str, typer.Option("--algorithm", "-a", help="HMAC algorithm")] = "HmacSHA512",
    target: Annotated[str, typer.Option("--target", help="Target path for nexus key")] = "/run/aegis/nexus-key",
    user: Annotated[str, typer.Option("--user", help="Owner user")] = "root",
    group: Annotated[str, typer.Option("--group", help="Owner group")] = "root",
    mode: Annotated[str, typer.Option("--mode", help="Permissions")] = "0400",
):
    """Generate Nexus DDNS authentication keys for hosts.
    
    Creates HMAC keys for each host to authenticate with Nexus DDNS servers.
    Keys are encrypted with both the admin and host keys.
    
    Each host gets a unique key stored in build/hosts/<hostname>/nexus-key.age.
    Deployment metadata is written to secrets.toml for NixOS to import.
    """
    from . import nexus

    repo = get_secrets_repo(secrets_path)

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

        # Get age public key from host config
        try:
            host_age_key = get_host_age_pubkey(hostname, repo)
        except SystemExit:
            typer.echo(f"    Skipping {hostname} (no age key)", err=True)
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
        recipients = [host_age_key, admin_pubkey]
        
        # Encrypt and write
        output_path.parent.mkdir(parents=True, exist_ok=True)
        crypto.encrypt_age(key_content, recipients, output_path)
        
        typer.echo(f"    Wrote {output_path}")
        
        # Update manifest with deployment metadata
        from . import host_secrets
        manifest = host_secrets.load_host_manifest(repo.build_path, hostname)
        manifest.nexus_key = host_secrets.make_nexus_key_entry(
            target=target,
            user=user,
            group=group,
            mode=mode,
        )
        host_secrets.save_host_manifest(repo.build_path, manifest)
        typer.echo(f"    Updated manifest")
        
        # Show the algorithm
        algo, _ = key_content.strip().split(":", 1)
        typer.echo(f"    Algorithm: {algo}")


@app.command("build-keytabs")
def build_keytabs(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    force: Annotated[bool, typer.Option("--force", "-f", help="Regenerate even if keytabs exist")] = False,
    target: Annotated[str, typer.Option("--target", help="Target path for keytab")] = "/run/aegis/keytab",
    user: Annotated[str, typer.Option("--user", help="Owner user for keytab")] = "root",
    group: Annotated[str, typer.Option("--group", help="Owner group for keytab")] = "root",
    mode: Annotated[str, typer.Option("--mode", help="Permissions for keytab")] = "0600",
):
    """Generate Kerberos keytabs for hosts and KDC database.
    
    Deployment metadata is written to secrets.toml for NixOS to import.
    """
    from . import kerberos as krb
    import tempfile
    import shutil

    repo = get_secrets_repo(secrets_path)

    # Get admin key for encryption
    admin_pubkey = crypto.get_admin_public_key()

    # Find all realms we need to process
    kerberos_src = repo.src_path / "kerberos" / "realms"
    if not kerberos_src.exists():
        typer.echo("No Kerberos realms configured in src/kerberos/realms/")
        typer.echo("Use 'aegis init-realm' to create a realm first.")
        return

    # Get hosts grouped by realm (via HostConfig.domain -> DomainConfig.realm)
    hosts_by_realm: dict[str, list[str]] = {}
    for hostname in repo.list_hosts():
        host_config = repo.get_host_config(hostname)
        if host_config and host_config.domain:
            domain_config = repo.get_domain_config(host_config.domain)
            if domain_config and domain_config.realm:
                realm = domain_config.realm
                if realm not in hosts_by_realm:
                    hosts_by_realm[realm] = []
                hosts_by_realm[realm].append(hostname)
    
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
            
            # Decrypt realm key (binary - Kerberos keys are not UTF-8)
            typer.echo(f"  Decrypting realm key...")
            realm_key_plain = realm_tmp / "realm.key"
            realm_key_content = crypto.decrypt_age_binary(realm_key_enc)
            realm_key_plain.write_bytes(realm_key_content)
            
            # Decrypt existing principals (binary)
            principals_enc = realm_src / "principals"
            if principals_enc.exists():
                for princ_file in principals_enc.glob("*.age"):
                    princ_name = princ_file.stem  # Remove .age
                    typer.echo(f"  Decrypting principal: {princ_name}")
                    princ_content = crypto.decrypt_age_binary(princ_file)
                    (principals_tmp / f"{princ_name}.key").write_bytes(princ_content)
            
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
                
                # Get age public key from host config
                try:
                    host_age_key = get_host_age_pubkey(hostname, repo)
                except SystemExit:
                    typer.echo(f"    Skipping {hostname} (no age key)", err=True)
                    continue

                # Get host info from config
                host_config = repo.get_host_config(hostname)
                if not host_config:
                    typer.echo(f"    Error: No config found for {hostname}", err=True)
                    continue

                host_fqdn = f"{hostname}.{host_config.domain}" if host_config.domain else hostname
                services = host_config.services
                
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
                recipients = [host_age_key, admin_pubkey]
                if kdc_role_pubkey:
                    recipients.append(kdc_role_pubkey)
                
                keytab_content = keytab_tmp.read_bytes()
                keytab_output.parent.mkdir(parents=True, exist_ok=True)
                
                # Use encrypt_age_binary for binary keytab data
                crypto.encrypt_age_binary(keytab_content, recipients, keytab_output)
                
                typer.echo(f"    Wrote: {keytab_output}")
                
                # Update manifest with deployment metadata
                from . import host_secrets
                manifest = host_secrets.load_host_manifest(repo.build_path, hostname)
                manifest.keytab = host_secrets.make_keytab_entry(
                    target=target,
                    user=user,
                    group=group,
                    mode=mode,
                )
                host_secrets.save_host_manifest(repo.build_path, manifest)
                typer.echo(f"    Updated manifest")
            
            # Encrypt any new principals back to the repo (binary)
            if new_principals:
                typer.echo(f"\n  Saving {len(new_principals)} new principals...")
                principals_enc.mkdir(parents=True, exist_ok=True)
                
                for princ_file in new_principals:
                    if princ_file.exists():
                        princ_name = princ_file.stem  # e.g., "host_server.example.com"
                        princ_content = princ_file.read_bytes()
                        princ_out = principals_enc / f"{princ_name}.age"
                        
                        # Encrypt for admin only (principals are sensitive)
                        crypto.encrypt_age_binary(princ_content, [admin_pubkey], princ_out)
                        typer.echo(f"    Saved: {princ_out.name}")
            
            # Generate consolidated KDC principals file (binary)
            typer.echo(f"\n  Generating KDC principals file...")
            all_principals = b""
            for princ_file in sorted(principals_tmp.glob("*.key")):
                all_principals += princ_file.read_bytes()
            
            if all_principals and kdc_role_pubkey:
                kdc_principals_out = repo.build_path / "kdc" / f"{realm}-principals.age"
                kdc_principals_out.parent.mkdir(parents=True, exist_ok=True)
                crypto.encrypt_age_binary(all_principals, [kdc_role_pubkey, admin_pubkey], kdc_principals_out)
                typer.echo(f"  Wrote KDC principals: {kdc_principals_out}")
            elif not kdc_role_pubkey:
                typer.echo(f"  Warning: No KDC role configured, skipping KDC principals file")
    
    typer.secho("\nKeytab build complete!", fg=typer.colors.GREEN)


@app.command("build-user-secrets")
def build_user_secrets(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
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
                host_keys[hostname] = get_host_age_pubkey(hostname, repo)
            except SystemExit:
                typer.echo(f"  Warning: No age key for {hostname}, skipping", err=True)
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
    target_dir: str = typer.Option("/run/aegis/ssh", "--target-dir", help="Target directory for SSH keys"),
    user: str = typer.Option("root", "--user", help="Owner user for key files"),
    group: str = typer.Option("root", "--group", help="Owner group for key files"),
    mode: str = typer.Option("0600", "--mode", help="Permissions for private key files"),
):
    """Import SSH host keys for OpenSSH server (NOT the master key).
    
    This imports the SSH keys that OpenSSH will use to identify the server
    to clients (ssh_host_ed25519_key, ssh_host_ecdsa_key, etc.).
    
    These are NOT the master key! The master key is used to ENCRYPT these
    SSH host keys. The master key public should be set via 'set-master-key'.
    
    This command:
    - Auto-detects key type (ed25519, ecdsa, rsa)
    - Derives public keys automatically
    - Encrypts each private key separately as its own age file
    - Writes each public key as a plaintext .pub file alongside
    - Writes deployment metadata to secrets.toml for NixOS

    Example:
        aegis import-ssh-host-keys lambda \\
            --key /secure/lambda.ed25519.key \\
            --key /secure/lambda.ecdsa.key
    """
    from . import ssh_utils, host_secrets

    # Maps detected key_type string → SSH server filename stem
    KEY_TYPE_TO_STEM = {
        "ed25519": "ssh_host_ed25519_key",
        "ecdsa": "ssh_host_ecdsa_key",
        "rsa": "ssh_host_rsa_key",
    }

    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()

    if not key_files:
        typer.echo("Error: At least one private key must be provided (use --key)", err=True)
        raise typer.Exit(1)

    typer.echo(f"Importing SSH host keys for {hostname}...")
    typer.echo(f"  (These are OpenSSH server keys, NOT the master key)")

    # Get age public key from host config
    host_age_key = get_host_age_pubkey(hostname, repo)

    # Ensure host config exists (create if missing)
    host_config = repo.get_host_config(hostname)
    if not host_config:
        typer.echo(f"  Host config not found, creating...")
        host_config = config.HostConfig(hostname=hostname)
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

    # Encrypt each private key separately; write each public key plaintext
    admin_pubkey = crypto.get_admin_public_key()
    recipients = [host_age_key, admin_pubkey]

    ssh_dir = repo.host_build_path(hostname) / "ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)

    stems = []
    for kp in keypairs:
        stem = KEY_TYPE_TO_STEM.get(kp.key_type, f"ssh_host_{kp.key_type}_key")
        age_path = ssh_dir / f"{stem}.age"
        pub_path = ssh_dir / f"{stem}.pub"
        crypto.encrypt_age(kp.private_key, recipients, age_path)
        pub_path.write_text(kp.public_key + "\n")
        stems.append(stem)
        typer.echo(f"    Wrote {age_path.name} + {pub_path.name}")

    # Update manifest with one entry per private key
    manifest = host_secrets.load_host_manifest(repo.build_path, hostname)
    manifest.ssh_host_keys = host_secrets.make_ssh_host_keys_entries(
        stems=stems,
        target_dir=target_dir,
        user=user,
        group=group,
        mode=mode,
    )
    manifest_path = host_secrets.save_host_manifest(repo.build_path, manifest)

    typer.secho(f"\nSSH host keys imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Output dir: {ssh_dir}")
    typer.echo(f"  Manifest: {manifest_path}")
    typer.echo(f"  Target: {target_dir}")
    typer.echo(f"  Encrypted for: {hostname} (master key) + admin")
    typer.echo(f"  These keys are for OpenSSH server identity.")


@app.command("import-nexus-key")
def import_nexus_key(
    hostname: str = typer.Argument(..., help="Hostname to import key for"),
    key_file: Path = typer.Option(..., "--file", help="Path to nexus HMAC key file"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    target: str = typer.Option("/run/aegis/nexus-key", "--target", help="Target path for nexus key"),
    user: str = typer.Option("root", "--user", help="Owner user"),
    group: str = typer.Option("root", "--group", help="Owner group"),
    mode: str = typer.Option("0400", "--mode", help="Permissions"),
):
    """Import a Nexus DDNS authentication key for a host.
    
    Imports an existing Nexus HMAC key. The key should be in the format:
    HmacSHA512:base64encodedkey
    
    Deployment metadata is written to secrets.toml for NixOS to import.
    
    Example:
        aegis import-nexus-key lambda --file /secure/lambda.nexus.hmac
    """
    from . import nexus

    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()

    if not key_file.exists():
        typer.echo(f"Error: Key file not found: {key_file}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Importing Nexus key for {hostname}...")

    # Get age public key from host config
    host_age_key = get_host_age_pubkey(hostname, repo)

    # Ensure host config exists
    host_config = repo.get_host_config(hostname)
    if not host_config:
        typer.echo(f"  Host config not found, creating...")
        host_config = config.HostConfig(hostname=hostname)
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
    admin_pubkey = crypto.get_admin_public_key()
    recipients = [host_age_key, admin_pubkey]
    
    # Encrypt and write
    output_path = repo.host_build_path(hostname) / "nexus-key.age"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(key_content, recipients, output_path)
    
    # Update manifest with deployment metadata
    from . import host_secrets
    manifest = host_secrets.load_host_manifest(repo.build_path, hostname)
    manifest.nexus_key = host_secrets.make_nexus_key_entry(
        target=target,
        user=user,
        group=group,
        mode=mode,
    )
    manifest_path = host_secrets.save_host_manifest(repo.build_path, manifest)
    
    typer.secho(f"\nNexus key imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Output: {output_path}")
    typer.echo(f"  Manifest: {manifest_path}")
    typer.echo(f"  Target: {target}")
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
    
    # Import realm master key (binary - Kerberos keys are not UTF-8)
    typer.echo(f"  Importing realm master key...")
    realm_key_content = realm_key.read_bytes()
    realm_key_out = realm_dir / "realm.key.age"
    crypto.encrypt_age_binary(realm_key_content, [admin_pubkey], realm_key_out)
    typer.echo(f"    Wrote {realm_key_out}")
    
    # Import principal keys (binary)
    principal_files = list(principals_dir.glob("*.key"))
    if not principal_files:
        typer.echo("  Warning: No principal key files found (*.key)", err=True)
    
    typer.echo(f"  Importing {len(principal_files)} principal(s)...")
    for principal_file in principal_files:
        principal_name = principal_file.stem
        principal_content = principal_file.read_bytes()
        
        output_file = principals_out_dir / f"{principal_name}.age"
        crypto.encrypt_age_binary(principal_content, [admin_pubkey], output_file)
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
):
    """Import a generic secret for a host.
    
    This is for service-specific or custom secrets that don't fit the standard
    categories (SSH, Nexus, Kerberos). The secret will be encrypted and metadata
    about target path, ownership, and permissions will be stored in secrets.toml.
    
    Example:
        aegis import-secret lambda my-service-token \\
            --file /secure/lambda-service.token \\
            --target /run/myservice/token \\
            --user myservice --group myservice --mode 0600
    """
    from . import host_secrets

    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()

    if not file.exists():
        typer.echo(f"Error: Secret file not found: {file}", err=True)
        raise typer.Exit(1)

    typer.echo(f"Importing secret '{secret_name}' for {hostname}...")

    # Get age public key from host config
    host_age_key = get_host_age_pubkey(hostname, repo)

    # Ensure host config exists
    host_config = repo.get_host_config(hostname)
    if not host_config:
        typer.echo(f"  Host config not found, creating...")
        host_config = config.HostConfig(hostname=hostname)
        repo.set_host_config(host_config)

    # Read secret content
    secret_content = file.read_text()

    # Get recipients
    admin_pubkey = crypto.get_admin_public_key()
    recipients = [host_age_key, admin_pubkey]
    
    # Encrypt and write to secrets subdirectory
    secrets_dir = repo.host_build_path(hostname) / "secrets"
    secrets_dir.mkdir(parents=True, exist_ok=True)
    output_path = secrets_dir / f"{secret_name}.age"
    crypto.encrypt_age(secret_content, recipients, output_path)
    
    # Update manifest with deployment metadata
    manifest = host_secrets.load_host_manifest(repo.build_path, hostname)
    manifest.secrets[secret_name] = host_secrets.make_secret_entry(
        name=secret_name,
        target=target,
        user=user,
        group=group,
        mode=mode,
    )
    manifest_path = host_secrets.save_host_manifest(repo.build_path, manifest)
    
    typer.secho(f"\nSecret imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Output: {output_path}")
    typer.echo(f"  Manifest: {manifest_path}")
    typer.echo(f"  Target: {target}")
    typer.echo(f"  Owner: {user}:{group}")
    typer.echo(f"  Mode: {mode}")


# =============================================================================
# DNSSEC Commands
# =============================================================================

def _ensure_dns_role(
    repo: config.SecretsRepo,
    domain: str,
    hostname: str,
) -> str:
    """Ensure dns-master-<domain> role exists, create if needed.

    Returns the role's public key.
    """
    role_name = f"dns-master-{domain}"
    existing = repo.get_role_config(role_name)

    if existing:
        # Role exists, get its public key
        role_pub_path = repo.role_build_path(role_name) / f"{role_name}.pub"
        if not role_pub_path.exists():
            typer.echo(f"Error: Role {role_name} exists but public key not found", err=True)
            raise typer.Exit(1)
        return role_pub_path.read_text().strip()

    # Create the role
    typer.echo(f"Creating role: {role_name} (assigned to {hostname})")

    # Get age public key for the host
    host_age_key = get_host_age_pubkey(hostname, repo)

    # Generate role keypair
    keypair = crypto.generate_age_keypair()

    # Encrypt role private key for the host and admin
    admin_pubkey = crypto.get_admin_public_key()

    role_key_path = repo.role_build_path(role_name) / f"{role_name}.age"
    role_key_path.parent.mkdir(parents=True, exist_ok=True)
    crypto.encrypt_age(keypair.private_key, [host_age_key, admin_pubkey], role_key_path)
    
    # Save public key
    role_pub_path = repo.role_build_path(role_name) / f"{role_name}.pub"
    role_pub_path.write_text(keypair.public_key)
    
    # Save role config
    role_config = config.RoleConfig(name=role_name, host=hostname)
    repo.set_role_config(role_config)
    
    return keypair.public_key


@app.command("generate-dnssec-keys")
def generate_dnssec_keys(
    domain: str = typer.Argument(..., help="Domain name (e.g., fudo.org)"),
    hostname: str = typer.Option(..., "--host", "-h", help="DNS master server hostname"),
    algorithm: str = typer.Option("ECDSAP256SHA256", "--algorithm", "-a", help="DNSSEC algorithm"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing keys"),
    target_dir: Optional[str] = typer.Option(None, "--target-dir", help="Target directory for keys (default: /var/lib/dnssec/<domain>)"),
    user: str = typer.Option("root", "--user", help="Owner user for key files"),
    group: str = typer.Option("root", "--group", help="Owner group for key files"),
):
    """Generate DNSSEC Key Signing Key (KSK) for a domain.
    
    Creates a new DNSSEC KSK using ldns-keygen and encrypts it for the
    dns-master-<domain> role (auto-created if needed) and the admin.
    
    Deployment metadata is written to secrets.toml for NixOS to import.
    
    Requires ldns-keygen to be available in PATH.
    
    Example:
        aegis generate-dnssec-keys fudo.org --host polaris
        aegis generate-dnssec-keys fudo.org --host polaris --algorithm ED25519
    """
    from . import dnssec
    import tempfile
    
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    # Check if keys already exist
    existing = repo.get_dnssec_config(domain)
    if existing and not force:
        typer.echo(f"DNSSEC keys already exist for {domain} (keytag: {existing.keytag})")
        typer.echo("Use --force to overwrite.")
        raise typer.Exit(1)
    
    # Validate algorithm
    if algorithm not in dnssec.ALGORITHM_MAP:
        typer.echo(f"Error: Unknown algorithm: {algorithm}", err=True)
        typer.echo(f"Valid options: {', '.join(dnssec.ALGORITHM_MAP.keys())}")
        raise typer.Exit(1)
    
    typer.echo(f"Generating DNSSEC KSK for {domain}...")
    typer.echo(f"  Algorithm: {algorithm} ({dnssec.ALGORITHM_MAP[algorithm]})")
    
    # Ensure role exists and get its public key
    role_pubkey = _ensure_dns_role(repo, domain, hostname)
    admin_pubkey = crypto.get_admin_public_key()
    recipients = [role_pubkey, admin_pubkey]

    # Generate keys in temp directory
    with tempfile.TemporaryDirectory(prefix="aegis-dnssec-") as tmpdir:
        tmpdir = Path(tmpdir)
        
        try:
            key_files = dnssec.generate_ksk(domain, tmpdir, algorithm)
        except FileNotFoundError:
            typer.echo("Error: ldns-keygen not found in PATH", err=True)
            typer.echo("Install with: nix-shell -p ldns.examples")
            raise typer.Exit(1)
        except Exception as e:
            typer.echo(f"Error generating keys: {e}", err=True)
            raise typer.Exit(1)
        
        typer.echo(f"  Generated: {key_files.basename}")
        typer.echo(f"  Key tag: {key_files.keytag}")
        
        # Create output directory
        build_dir = repo.dnssec_build_path(domain)
        build_dir.mkdir(parents=True, exist_ok=True)
        
        # Encrypt and store keys
        typer.echo(f"Encrypting keys for: admin, dns-master-{domain}")
        
        # Public key (.key)
        key_content = key_files.key_file.read_text()
        crypto.encrypt_age(key_content, recipients, build_dir / "ksk.key.age")
        typer.echo(f"  ksk.key.age")
        
        # Private key (.private)
        private_content = key_files.private_file.read_text()
        crypto.encrypt_age(private_content, recipients, build_dir / "ksk.private.age")
        typer.echo(f"  ksk.private.age")
        
        # DS record (.ds)
        if key_files.ds_file.exists():
            ds_content = key_files.ds_file.read_text()
            crypto.encrypt_age(ds_content, recipients, build_dir / "ksk.ds.age")
            typer.echo(f"  ksk.ds.age")
            ds_record = ds_content.strip()
        else:
            ds_record = None
    
    # Save config (legacy - still keep for backward compat)
    dnssec_config = config.DnssecConfig(
        domain=domain,
        algorithm=algorithm,
        algorithm_num=dnssec.ALGORITHM_MAP[algorithm],
        keytag=key_files.keytag,
    )
    repo.set_dnssec_config(dnssec_config)
    
    # Save secrets manifest with deployment metadata
    from . import host_secrets
    dnssec_manifest = host_secrets.make_dnssec_entry(
        domain=domain,
        algorithm=algorithm,
        algorithm_num=dnssec.ALGORITHM_MAP[algorithm],
        keytag=key_files.keytag,
        target_dir=target_dir,
        user=user,
        group=group,
    )
    manifest_path = host_secrets.save_dnssec_manifest(repo.build_path, dnssec_manifest)
    
    typer.secho(f"\nDNSSEC keys generated successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Location: {build_dir}")
    typer.echo(f"  Manifest: {manifest_path}")
    typer.echo(f"  Algorithm: {algorithm} ({dnssec.ALGORITHM_MAP[algorithm]})")
    typer.echo(f"  Key tag: {key_files.keytag}")
    if dnssec_manifest.public_key:
        typer.echo(f"  Target dir: {dnssec_manifest.public_key.target.rsplit('/', 1)[0]}")
    
    if ds_record:
        typer.echo(f"\nDS Record (submit to registrar):")
        typer.echo(f"  {ds_record}")


@app.command("import-dnssec-keys")
def import_dnssec_keys(
    domain: str = typer.Argument(..., help="Domain name (e.g., fudo.org)"),
    keys_dir: Path = typer.Option(..., "--keys-dir", "-k", help="Directory containing DNSSEC key files"),
    hostname: str = typer.Option(..., "--host", "-h", help="DNS master server hostname"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing keys"),
    target_dir: Optional[str] = typer.Option(None, "--target-dir", help="Target directory for keys (default: /var/lib/dnssec/<domain>)"),
    user: str = typer.Option("root", "--user", help="Owner user for key files"),
    group: str = typer.Option("root", "--group", help="Owner group for key files"),
):
    """Import existing DNSSEC Key Signing Key (KSK) for a domain.
    
    Imports DNSSEC key files generated by ldns-keygen:
      - K<domain>.+<alg>+<keytag>.key      (public key)
      - K<domain>.+<alg>+<keytag>.private  (private key)
      - K<domain>.+<alg>+<keytag>.ds       (DS record, optional)
    
    The keys are encrypted for the dns-master-<domain> role (auto-created
    if needed) and the admin.
    
    Deployment metadata is written to secrets.toml for NixOS to import.
    
    Example:
        aegis import-dnssec-keys fudo.org --keys-dir /secrets/dnssec/fudo.org/ --host polaris
    """
    from . import dnssec
    
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    if not keys_dir.exists() or not keys_dir.is_dir():
        typer.echo(f"Error: Keys directory not found: {keys_dir}", err=True)
        raise typer.Exit(1)
    
    # Check if keys already exist
    existing = repo.get_dnssec_config(domain)
    if existing and not force:
        typer.echo(f"DNSSEC keys already exist for {domain} (keytag: {existing.keytag})")
        typer.echo("Use --force to overwrite.")
        raise typer.Exit(1)
    
    # Find key files
    key_files = dnssec.find_dnssec_keys(keys_dir, domain)
    if key_files is None:
        typer.echo(f"Error: No DNSSEC key files found for {domain} in {keys_dir}", err=True)
        typer.echo(f"Looking for files matching: K{domain}.+<alg>+<keytag>.*")
        raise typer.Exit(1)
    
    typer.echo(f"Importing DNSSEC keys for {domain}...")
    typer.echo(f"  Found: {key_files.basename}")
    typer.echo(f"  Algorithm: {key_files.algorithm} ({key_files.algorithm_num})")
    typer.echo(f"  Key tag: {key_files.keytag}")
    
    # Check required files exist
    if not key_files.key_file.exists():
        typer.echo(f"Error: Public key file not found: {key_files.key_file}", err=True)
        raise typer.Exit(1)
    if not key_files.private_file.exists():
        typer.echo(f"Error: Private key file not found: {key_files.private_file}", err=True)
        raise typer.Exit(1)
    
    # Ensure role exists and get its public key
    role_pubkey = _ensure_dns_role(repo, domain, hostname)
    admin_pubkey = crypto.get_admin_public_key()
    recipients = [role_pubkey, admin_pubkey]

    # Create output directory
    build_dir = repo.dnssec_build_path(domain)
    build_dir.mkdir(parents=True, exist_ok=True)
    
    # Encrypt and store keys
    typer.echo(f"Encrypting keys for: admin, dns-master-{domain}")
    
    # Public key (.key)
    key_content = key_files.key_file.read_text()
    crypto.encrypt_age(key_content, recipients, build_dir / "ksk.key.age")
    typer.echo(f"  ksk.key.age")
    
    # Private key (.private)
    private_content = key_files.private_file.read_text()
    crypto.encrypt_age(private_content, recipients, build_dir / "ksk.private.age")
    typer.echo(f"  ksk.private.age")
    
    # DS record (.ds) - optional
    ds_record = None
    if key_files.ds_file.exists():
        ds_content = key_files.ds_file.read_text()
        crypto.encrypt_age(ds_content, recipients, build_dir / "ksk.ds.age")
        typer.echo(f"  ksk.ds.age")
        ds_record = ds_content.strip()
    else:
        typer.echo(f"  (no DS record file found)")
    
    # Save config (legacy - still keep for backward compat)
    dnssec_config = config.DnssecConfig(
        domain=domain,
        algorithm=key_files.algorithm,
        algorithm_num=key_files.algorithm_num,
        keytag=key_files.keytag,
    )
    repo.set_dnssec_config(dnssec_config)
    
    # Save secrets manifest with deployment metadata
    from . import host_secrets
    dnssec_manifest = host_secrets.make_dnssec_entry(
        domain=domain,
        algorithm=key_files.algorithm,
        algorithm_num=key_files.algorithm_num,
        keytag=key_files.keytag,
        target_dir=target_dir,
        user=user,
        group=group,
    )
    manifest_path = host_secrets.save_dnssec_manifest(repo.build_path, dnssec_manifest)
    
    typer.secho(f"\nDNSSEC keys imported successfully!", fg=typer.colors.GREEN)
    typer.echo(f"  Location: {build_dir}")
    typer.echo(f"  Manifest: {manifest_path}")
    typer.echo(f"  Algorithm: {key_files.algorithm} ({key_files.algorithm_num})")
    typer.echo(f"  Key tag: {key_files.keytag}")
    if dnssec_manifest.public_key:
        typer.echo(f"  Target dir: {dnssec_manifest.public_key.target.rsplit('/', 1)[0]}")
    
    if ds_record:
        typer.echo(f"\nDS Record (submit to registrar):")
        typer.echo(f"  {ds_record}")


# =============================================================================
# Configuration Commands
# =============================================================================


@app.command("init-host")
def init_host(
    hostname: str = typer.Argument(..., help="Hostname to initialize"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    domain: Optional[str] = typer.Option(None, "--domain", "-d", help="DNS domain (e.g. sea.fudo.org), used for Kerberos FQDNs"),
    services: str = typer.Option("host,ssh", "--services", help="Comma-separated Kerberos services"),
):
    """Add a host to the secrets configuration.

    This initializes a host in the aegis-secrets repository. When you run
    'aegis build', the following will be generated for this host:
    - SSH host keys (ed25519, ecdsa, rsa)
    - Nexus DDNS authentication key
    - Kerberos keytabs (if domain and realm are configured)
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
        domain=domain,
        services=service_list,
    )
    repo.set_host_config(host_config)

    typer.secho(f"Initialized host: {hostname}", fg=typer.colors.GREEN)
    if domain:
        typer.echo(f"  Domain: {domain}")
    typer.echo(f"  Services: {', '.join(service_list)}")
    typer.echo(f"  Config: {repo.src_path / 'hosts' / f'{hostname}.toml'}")
    typer.echo("")
    typer.echo("Next:")
    typer.echo("  1. Set master key: aegis set-master-key {hostname} --public-key 'age1...'")
    typer.echo("  2. Build secrets:  aegis build")


@app.command("set-master-key")
def set_master_key(
    hostname: str = typer.Argument(..., help="Hostname to set master key for"),
    public_key: str = typer.Option(..., "--public-key", "-k", help="age public key (e.g., 'age1...')"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
):
    """Set the age public key for a host.

    The master key is used to ENCRYPT secrets for this host. The host must have
    the corresponding age private key to decrypt secrets at boot time.

    This is NOT an SSH host key for OpenSSH! This is the age key Aegis uses to
    encrypt secrets that only this host can decrypt.

    The public key should be in age format: "age1..."

    Typical setup:
    1. Host has age private key at /state/master-key/key (persistent storage)
    2. Extract the public key: age-keygen -y /state/master-key/key
    3. Set it here: aegis set-master-key lambda --public-key "age1..."

    Example:
        aegis set-master-key lambda --public-key "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"
    """
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()

    # Validate the public key format
    public_key = public_key.strip()
    if not public_key.startswith("age1"):
        typer.echo("Error: Public key must be in age format", err=True)
        typer.echo("  Expected: age1... (obtain with: age-keygen -y /path/to/key)", err=True)
        raise typer.Exit(1)

    # Get or create host config
    host_config = repo.get_host_config(hostname)
    if not host_config:
        typer.echo(f"Creating new host config for {hostname}...")
        host_config = config.HostConfig(
            hostname=hostname,
            age_pubkey=public_key,
        )
    else:
        host_config.age_pubkey = public_key

    repo.set_host_config(host_config)

    typer.secho(f"Master key set for {hostname}", fg=typer.colors.GREEN)
    typer.echo(f"  Age public key: {public_key}")
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
):
    """Add a user-provided secret for a host."""
    repo = get_secrets_repo(secrets_path)
    if not file.exists():
        typer.echo(f"Error: File not found: {file}", err=True)
        raise typer.Exit(1)

    # Get age public key from host config
    host_age_key = get_host_age_pubkey(hostname, repo)

    # Read secret
    content = file.read_text()

    # Encrypt
    admin_pubkey = crypto.get_admin_public_key()
    
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
):
    """Create a role and assign it to a host."""
    repo = get_secrets_repo(secrets_path)
    repo.ensure_structure()
    
    existing = repo.get_role_config(role)
    if existing:
        typer.echo(f"Role {role} already exists (assigned to {existing.host})")
        raise typer.Exit(1)
    
    # Get age public key from host config
    host_age_key = get_host_age_pubkey(hostname, repo)

    # Generate role keypair
    typer.echo(f"Generating keypair for role {role}...")
    keypair = crypto.generate_age_keypair()

    # Encrypt role private key for the host and admin
    admin_pubkey = crypto.get_admin_public_key()
    
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
):
    """Verify a host can decrypt its secrets."""
    repo = get_secrets_repo(secrets_path)
    
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
