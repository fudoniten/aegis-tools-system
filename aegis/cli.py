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
    """Get the entities path, with default handling."""
    if entities_path is not None:
        return entities_path
    
    # Try to find it
    candidates = [
        Path.cwd() / "nix-entities",
        Path.cwd().parent / "nix-entities",
        Path("/net/projects/niten/nix-entities"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    
    typer.echo("Error: Could not find nix-entities repo", err=True)
    typer.echo("Use --entities-path to specify location", err=True)
    raise typer.Exit(1)


# =============================================================================
# Build Commands
# =============================================================================

@app.command()
def build(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s", help="Path to aegis-secrets repo"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e", help="Path to nix-entities repo"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Show what would be done"),
):
    """Run full build: generate missing secrets and create host bundles."""
    repo = get_secrets_repo(secrets_path)
    ent_path = get_entities_path(entities_path)
    
    typer.echo("Running full build...")
    
    if dry_run:
        typer.echo("  [dry-run] Would run: build-ssh-keys")
        typer.echo("  [dry-run] Would run: build-keytabs")
        typer.echo("  [dry-run] Would run: build-user-secrets")
        typer.echo("  [dry-run] Would run: build-bundles")
        return
    
    # Run each build step
    typer.echo("\n--- Building SSH Keys ---")
    build_ssh_keys(secrets_path=secrets_path, entities_path=entities_path, dry_run=False)
    
    typer.echo("\n--- Building Keytabs ---")
    build_keytabs(secrets_path=secrets_path, entities_path=entities_path, dry_run=False)
    
    typer.echo("\n--- Building User Secrets ---")
    build_user_secrets(secrets_path=secrets_path, entities_path=entities_path, dry_run=False)
    
    # build_bundles(...)  # TODO - may not be needed if structure is already per-host
    
    typer.secho("\nBuild complete!", fg=typer.colors.GREEN)


@app.command("build-ssh-keys")
def build_ssh_keys(
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    entities_path: Optional[Path] = typer.Option(None, "--entities-path", "-e"),
    dry_run: bool = typer.Option(False, "--dry-run", "-n"),
    force: bool = typer.Option(False, "--force", "-f", help="Regenerate even if keys exist"),
):
    """Generate SSH keys for hosts that need them."""
    repo = get_secrets_repo(secrets_path)
    ent_path = get_entities_path(entities_path)
    
    hosts = repo.list_hosts()
    if not hosts:
        typer.echo("No hosts configured. Use 'aegis init-host' first.")
        return
    
    admin_pubkey = crypto.get_admin_public_key()
    
    for hostname in hosts:
        output_path = repo.host_build_path(hostname) / "ssh-keys.age"
        
        if output_path.exists() and not force:
            typer.echo(f"  {hostname}: SSH keys exist (use --force to regenerate)")
            continue
        
        if dry_run:
            typer.echo(f"  [dry-run] Would generate SSH keys for {hostname}")
            continue
        
        typer.echo(f"  Generating SSH keys for {hostname}...")
        
        # Get host info from entities
        try:
            host = entities.get_host(hostname, ent_path)
        except Exception as e:
            typer.echo(f"    Warning: Could not get host info from entities: {e}", err=True)
            typer.echo(f"    Skipping {hostname}", err=True)
            continue
        
        if host.master_key is None:
            typer.echo(f"    Warning: No master key for {hostname}, skipping", err=True)
            continue
        
        # Generate keys
        keys = ssh.generate_host_keys(hostname)
        
        # Convert to YAML
        keys_yaml = yaml.dump(keys.to_dict(), default_flow_style=False)
        
        # Get recipients
        host_age_key = crypto.ssh_pubkey_to_age(host.master_key.public_key)
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
                
                try:
                    host = entities.get_host(hostname, ent_path)
                except Exception as e:
                    typer.echo(f"    Error getting host info: {e}", err=True)
                    continue
                
                if host.master_key is None:
                    typer.echo(f"    No master key, skipping")
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
                host_age_key = crypto.ssh_pubkey_to_age(host.master_key.public_key)
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
    """Collect and re-encrypt user secrets from user repos."""
    import tempfile
    
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
                host = entities.get_host(hostname, ent_path)
                if host.master_key:
                    host_age_key = crypto.ssh_pubkey_to_age(host.master_key.public_key)
                    host_keys[hostname] = host_age_key
                else:
                    typer.echo(f"  Warning: No master key for {hostname}", err=True)
            except Exception as e:
                typer.echo(f"  Warning: Could not get host {hostname}: {e}", err=True)
        
        if not host_keys:
            typer.echo(f"  No valid hosts found, skipping")
            continue
        
        # Process environment variables
        env_dir = user_repo_path / "env"
        if env_dir.exists():
            env_secrets = _process_user_secrets_dir(
                env_dir, username, user_private_key, host_keys, 
                admin_pubkey, repo, "env", dry_run
            )
            typer.echo(f"  Processed {env_secrets} env vars")
        
        # Process files
        files_dir = user_repo_path / "files"
        if files_dir.exists():
            file_secrets = _process_user_secrets_dir(
                files_dir, username, user_private_key, host_keys,
                admin_pubkey, repo, "files", dry_run
            )
            typer.echo(f"  Processed {file_secrets} files")
    
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


def _process_user_secrets_dir(
    source_dir: Path,
    username: str,
    user_private_key: str,
    host_keys: dict[str, str],
    admin_pubkey: str,
    repo: config.SecretsRepo,
    secret_type: str,  # "env" or "files"
    dry_run: bool,
) -> int:
    """Process a directory of user secrets.
    
    Decrypts each .age file and re-encrypts for each host.
    
    Returns number of secrets processed.
    """
    import tempfile
    
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
        
        # Re-encrypt for each host
        for hostname, host_key in host_keys.items():
            output_dir = repo.host_build_path(hostname) / "users" / username / secret_type
            output_file = output_dir / f"{secret_name}.age"
            
            if not dry_run:
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
# Configuration Commands
# =============================================================================

@app.command("init-host")
def init_host(
    hostname: str = typer.Argument(..., help="Hostname to initialize"),
    secrets_path: Optional[Path] = typer.Option(None, "--secrets-path", "-s"),
    services: str = typer.Option("host,ssh", "--services", help="Comma-separated Kerberos services"),
):
    """Add a host to the secrets configuration."""
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
    typer.echo("Next: run 'aegis build' to generate secrets")


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
    
    # Save user config
    user_config = config.UserConfig(
        username=username,
        hosts=host_list,
        repo_url=repo_url,
    )
    repo.set_user_config(user_config)
    
    typer.secho(f"Added user: {username}", fg=typer.colors.GREEN)
    typer.echo(f"  Hosts: {', '.join(host_list)}")
    typer.echo(f"  Private key: {user_key_path}")
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
    ent_path = get_entities_path(entities_path)
    
    if not file.exists():
        typer.echo(f"Error: File not found: {file}", err=True)
        raise typer.Exit(1)
    
    # Get host info
    try:
        host = entities.get_host(hostname, ent_path)
    except Exception as e:
        typer.echo(f"Error getting host info: {e}", err=True)
        raise typer.Exit(1)
    
    if host.master_key is None:
        typer.echo(f"Error: No master key for {hostname}", err=True)
        raise typer.Exit(1)
    
    # Read secret
    content = file.read_text()
    
    # Encrypt
    admin_pubkey = crypto.get_admin_public_key()
    host_age_key = crypto.ssh_pubkey_to_age(host.master_key.public_key)
    
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
    
    # Get host info
    try:
        host = entities.get_host(hostname, ent_path)
    except Exception as e:
        typer.echo(f"Error getting host info: {e}", err=True)
        raise typer.Exit(1)
    
    if host.master_key is None:
        typer.echo(f"Error: No master key for {hostname}", err=True)
        raise typer.Exit(1)
    
    # Generate role keypair
    typer.echo(f"Generating keypair for role {role}...")
    keypair = crypto.generate_age_keypair()
    
    # Encrypt role private key for the host and admin
    admin_pubkey = crypto.get_admin_public_key()
    host_age_key = crypto.ssh_pubkey_to_age(host.master_key.public_key)
    
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
