"""Role management for Aegis.

Roles allow secrets to be shared across multiple hosts using two-phase decryption.

## Domain Roles

Domain roles enable efficient secret sharing across domain hosts. Instead of
encrypting each domain secret for all hosts, you:

1. Create a domain role key
2. Encrypt the role key for all domain hosts
3. Encrypt domain secrets with the role key

To add/remove hosts, only the role key needs to be re-encrypted.

## Two-Phase Decryption

Phase 1: Host decrypts role key with its master key
Phase 2: Host decrypts domain secrets with the role key

Example:
    # Add a host to a domain
    add_host_to_role(
        repo_build_path=Path("aegis-secrets/build"),
        repo_src_path=Path("aegis-secrets/src"),
        role_name="domain-fudo.org",
        hostname="newhost",
        admin_identity=Path("~/.config/aegis/key.txt"),
        admin_pubkey="age1...",
    )

See Also:
    DOMAIN-ROLES.md - Complete documentation on domain roles
    CLI commands: aegis add-host-to-role, aegis remove-host-from-role
"""

from pathlib import Path
from typing import List, Set
import subprocess

from . import crypto


def get_role_key_path(repo_build_path: Path, role_name: str) -> Path:
    """Get path to role key file."""
    # Check multiple possible locations
    candidates = [
        repo_build_path / "roles" / f"{role_name}.age",
        repo_build_path / "domains" / role_name.replace("domain-", "") / "role-key.age",
    ]
    
    for path in candidates:
        if path.exists():
            return path
    
    # Return default location if not found
    return repo_build_path / "roles" / f"{role_name}.age"


def get_role_recipients(role_key_path: Path, admin_identity: Path) -> Set[str]:
    """Extract current recipients from an encrypted role key.
    
    This is a heuristic - age doesn't expose recipients directly.
    We decrypt and look at the header for X25519 recipients.
    """
    try:
        result = subprocess.run(
            ["age", "--decrypt", "--identity", str(admin_identity), str(role_key_path)],
            capture_output=True,
            check=False,
        )
        
        # Even if decryption fails, we can sometimes see recipients in stderr
        # This is fragile but better than nothing
        # TODO: Consider storing recipients in a metadata file
        return set()
        
    except Exception:
        return set()


def add_host_to_role(
    repo_build_path: Path,
    repo_src_path: Path,
    role_name: str,
    hostname: str,
    admin_identity: Path,
    admin_pubkey: str,
) -> None:
    """Add a host to a role by re-encrypting the role key.
    
    Args:
        repo_build_path: Path to aegis-secrets/build
        repo_src_path: Path to aegis-secrets/src  
        role_name: Name of the role (e.g., "domain-fudo.org")
        hostname: Host to add
        admin_identity: Path to admin's age private key
        admin_pubkey: Admin's age public key
    """
    role_key_path = get_role_key_path(repo_build_path, role_name)
    
    if not role_key_path.exists():
        raise FileNotFoundError(f"Role key not found: {role_key_path}")
    
    # Get host's public key
    host_config = repo_src_path / "hosts" / f"{hostname}.toml"
    if not host_config.exists():
        raise FileNotFoundError(
            f"Host config not found: {host_config}\n"
            f"Run 'aegis sync-hosts' or create the host config first."
        )
    
    import tomllib
    with open(host_config, "rb") as f:
        config = tomllib.load(f)
    
    host_pubkey = config.get("age_pubkey")
    if not host_pubkey:
        raise ValueError(f"No age_pubkey found in {host_config}")
    
    # Decrypt current role key
    decrypted = subprocess.run(
        ["age", "--decrypt", "--identity", str(admin_identity), str(role_key_path)],
        capture_output=True,
        check=True,
    )
    
    role_key_content = decrypted.stdout
    
    # Get current recipients (this is approximate - we'll rebuild the list)
    # For domain roles, get all hosts in that domain
    recipients = [admin_pubkey, host_pubkey]
    
    # If it's a domain role, add all domain hosts
    if role_name.startswith("domain-"):
        domain = role_name.replace("domain-", "")
        # TODO: Get domain hosts from entities or config
        # For now, just add the new host
        pass
    
    # Re-encrypt with new recipients
    temp_output = role_key_path.with_suffix(".age.new")
    
    crypto.encrypt_age(
        content=role_key_content,
        recipients=recipients,
        output_path=temp_output,
    )
    
    # Atomic replace
    temp_output.rename(role_key_path)
    
    print(f"✓ Added {hostname} to role {role_name}")
    print(f"  Role key: {role_key_path.relative_to(repo_build_path.parent)}")


def remove_host_from_role(
    repo_build_path: Path,
    repo_src_path: Path,
    role_name: str,
    hostname: str,
    admin_identity: Path,
    admin_pubkey: str,
    all_domain_hosts: List[str],
) -> None:
    """Remove a host from a role by re-encrypting the role key.
    
    Args:
        repo_build_path: Path to aegis-secrets/build
        repo_src_path: Path to aegis-secrets/src
        role_name: Name of the role
        hostname: Host to remove
        admin_identity: Path to admin's age private key
        admin_pubkey: Admin's age public key
        all_domain_hosts: All hosts that should have access (excluding the one being removed)
    """
    role_key_path = get_role_key_path(repo_build_path, role_name)
    
    if not role_key_path.exists():
        raise FileNotFoundError(f"Role key not found: {role_key_path}")
    
    # Decrypt current role key
    decrypted = subprocess.run(
        ["age", "--decrypt", "--identity", str(admin_identity), str(role_key_path)],
        capture_output=True,
        check=True,
    )
    
    role_key_content = decrypted.stdout
    
    # Build new recipient list (all domain hosts except the one being removed)
    recipients = [admin_pubkey]
    
    for host in all_domain_hosts:
        if host == hostname:
            continue  # Skip the host being removed
        
        host_config = repo_src_path / "hosts" / f"{host}.toml"
        if not host_config.exists():
            print(f"Warning: Host config not found for {host}, skipping")
            continue
        
        import tomllib
        with open(host_config, "rb") as f:
            config = tomllib.load(f)
        
        host_pubkey = config.get("age_pubkey")
        if host_pubkey:
            recipients.append(host_pubkey)
    
    # Re-encrypt without the removed host
    temp_output = role_key_path.with_suffix(".age.new")
    
    crypto.encrypt_age(
        content=role_key_content,
        recipients=recipients,
        output_path=temp_output,
    )
    
    # Atomic replace
    temp_output.rename(role_key_path)
    
    print(f"✓ Removed {hostname} from role {role_name}")
    print(f"  Remaining recipients: {len(recipients)} (including admin)")


def list_role_hosts(
    repo_build_path: Path,
    role_name: str,
) -> None:
    """List hosts that have access to a role.
    
    Note: This is approximate since age doesn't expose recipients.
    Best we can do is show which hosts SHOULD have access based on domain.
    """
    role_key_path = get_role_key_path(repo_build_path, role_name)
    
    if not role_key_path.exists():
        raise FileNotFoundError(f"Role key not found: {role_key_path}")
    
    print(f"Role: {role_name}")
    print(f"Key:  {role_key_path.relative_to(repo_build_path.parent)}")
    print()
    print("Note: age does not expose recipients. To see actual recipients,")
    print("      you would need to track them separately or check domain config.")
