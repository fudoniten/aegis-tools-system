"""Kerberos keytab generation using Ruby scripts."""

import os
import subprocess
import tempfile
from pathlib import Path
from dataclasses import dataclass


def get_scripts_path() -> Path:
    """Get path to the Ruby scripts directory."""
    scripts_path = os.environ.get("AEGIS_SCRIPTS")
    if scripts_path:
        return Path(scripts_path)
    
    # Fallback: relative to this file
    return Path(__file__).parent.parent / "scripts"


@dataclass
class RealmConfig:
    """Configuration for a Kerberos realm."""
    name: str
    key_path: Path
    principals_path: Path


def initialize_realm(
    realm: str,
    output_path: Path,
    etypes: list[str] | None = None,
    max_ticket_lifetime: str = "1w",
    max_renewable_lifetime: str = "1m",
    verbose: bool = False,
) -> RealmConfig:
    """Initialize a new Kerberos realm.
    
    Creates the realm master key and initial database structure.
    
    Args:
        realm: Realm name (e.g., "FUDO.ORG")
        output_path: Directory to store realm data
        etypes: Encryption types (default: AES128/256)
        max_ticket_lifetime: Max ticket lifetime
        max_renewable_lifetime: Max renewable lifetime
        verbose: Print verbose output
        
    Returns:
        RealmConfig with paths to created files
    """
    if etypes is None:
        etypes = ["aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha1-96"]
    
    scripts = get_scripts_path()
    script = scripts / "initialize-kerberos-realm.rb"
    
    if not script.exists():
        raise FileNotFoundError(f"Script not found: {script}")
    
    output_path.mkdir(parents=True, exist_ok=True)
    
    cmd = [
        "ruby", str(script),
        "--output", str(output_path),
        "--encryption-types", ",".join(etypes),
        "--max-ticket-lifetime", max_ticket_lifetime,
        "--max-renewable-lifetime", max_renewable_lifetime,
    ]
    
    if verbose:
        cmd.append("--verbose")
    
    cmd.append(realm)
    
    subprocess.run(cmd, check=True)
    
    realm_path = output_path / realm
    return RealmConfig(
        name=realm,
        key_path=realm_path / "realm.key",
        principals_path=realm_path / "principals",
    )


def add_host_to_realm(
    hostname: str,
    realm_config: RealmConfig,
    kdc_conf_path: Path,
    services: list[str] | None = None,
    verbose: bool = False,
) -> list[Path]:
    """Add a host's principals to a realm.
    
    Args:
        hostname: Fully qualified hostname
        realm_config: Realm configuration
        kdc_conf_path: Path to KDC config file (from instantiate_realm)
        services: Services to create principals for (default: host, ssh)
        verbose: Print verbose output
        
    Returns:
        List of paths to created principal key files
    """
    if services is None:
        services = ["host", "ssh"]
    
    scripts = get_scripts_path()
    script = scripts / "add-host-to-kerberos-realm.rb"
    
    if not script.exists():
        raise FileNotFoundError(f"Script not found: {script}")
    
    cmd = [
        "ruby", str(script),
        "--conf", str(kdc_conf_path),
        "--principal-dir", str(realm_config.principals_path),
        "--services", ",".join(services),
    ]
    
    if verbose:
        cmd.append("--verbose")
    
    cmd.append(hostname)
    
    subprocess.run(cmd, check=True)
    
    # Return paths to created principal files
    return [
        realm_config.principals_path / f"{svc}_{hostname}.key"
        for svc in services
    ]


def instantiate_realm(
    realm: str,
    realm_data_path: Path,
    etypes: list[str] | None = None,
    verbose: bool = False,
) -> Path:
    """Reconstruct a KDC database from stored principals.
    
    Creates a temporary database and returns the path to the KDC config file.
    The caller is responsible for cleanup.
    
    Args:
        realm: Realm name
        realm_data_path: Path containing realm.key and principals/
        etypes: Encryption types
        verbose: Print verbose output
        
    Returns:
        Path to the KDC config file (in a temp directory)
    """
    if etypes is None:
        etypes = ["aes128-cts-hmac-sha1-96", "aes256-cts-hmac-sha1-96"]
    
    scripts = get_scripts_path()
    script = scripts / "instantiate-kerberos-realm.rb"
    
    if not script.exists():
        raise FileNotFoundError(f"Script not found: {script}")
    
    cmd = [
        "ruby", str(script),
        "--base", str(realm_data_path.parent),  # Parent contains realm dirs
        "--encryption-types", ",".join(etypes),
    ]
    
    if verbose:
        cmd.append("--verbose")
    
    cmd.append(realm)
    
    # Script prints the kdc.conf path to stdout
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    kdc_conf_path = result.stdout.strip().split("\n")[-1]  # Last line is the path
    
    return Path(kdc_conf_path)


def extract_host_keytab(
    hostname: str,
    kdc_conf_path: Path,
    output_path: Path,
    services: list[str] | None = None,
    all_keys: bool = False,
    verbose: bool = False,
) -> Path:
    """Extract a keytab for a host.
    
    Args:
        hostname: Fully qualified hostname
        kdc_conf_path: Path to KDC config file
        output_path: Where to write the keytab
        services: Services to extract (ignored if all_keys=True)
        all_keys: Extract all keys for the host
        verbose: Print verbose output
        
    Returns:
        Path to the created keytab file
    """
    scripts = get_scripts_path()
    script = scripts / "extract-kerberos-host-keytab.rb"
    
    if not script.exists():
        raise FileNotFoundError(f"Script not found: {script}")
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    cmd = [
        "ruby", str(script),
        "--conf", str(kdc_conf_path),
        "--keytab", str(output_path),
    ]
    
    if all_keys:
        cmd.append("--all")
    elif services:
        cmd.extend(["--services", ",".join(services)])
    else:
        raise ValueError("Either services or all_keys must be specified")
    
    if verbose:
        cmd.append("--verbose")
    
    cmd.append(hostname)
    
    subprocess.run(cmd, check=True)
    
    return output_path


def extract_keytab(
    principals: list[str],
    kdc_conf_path: Path,
    output_path: Path,
    verbose: bool = False,
) -> Path:
    """Extract a keytab for specific principals.
    
    Args:
        principals: List of principal names (e.g., "host/server.example.com")
        kdc_conf_path: Path to KDC config file
        output_path: Where to write the keytab
        verbose: Print verbose output
        
    Returns:
        Path to the created keytab file
    """
    scripts = get_scripts_path()
    script = scripts / "extract-kerberos-keytab.rb"
    
    if not script.exists():
        raise FileNotFoundError(f"Script not found: {script}")
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    cmd = [
        "ruby", str(script),
        "--conf", str(kdc_conf_path),
        "--keytab", str(output_path),
    ]
    
    if verbose:
        cmd.append("--verbose")
    
    cmd.extend(principals)
    
    subprocess.run(cmd, check=True)
    
    return output_path
