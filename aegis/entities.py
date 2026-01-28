"""Query nix-entities for host/domain information."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class MasterKey:
    """Host master key configuration."""
    public_key: str
    key_path: str


@dataclass
class Host:
    """Host information from entities."""
    hostname: str
    domain: str
    site: str
    master_key: MasterKey | None
    arch: str
    nixos_system: bool
    kerberos_services: list[str]
    

@dataclass
class Domain:
    """Domain information from entities."""
    name: str
    gssapi_realm: str | None


def _nix_eval(expr: str, entities_path: Path) -> Any:
    """Evaluate a Nix expression and return JSON result.
    
    Uses flake-based evaluation since nix-entities is a flake.
    """
    # Construct the flake reference
    flake_ref = f"path:{entities_path}#{expr}"
    
    cmd = [
        "nix", "eval", "--json",
        "--extra-experimental-features", "nix-command flakes",
        flake_ref,
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def get_host(hostname: str, entities_path: Path) -> Host:
    """Query entities for host information.
    
    Args:
        hostname: The hostname to look up
        entities_path: Path to nix-entities repo
        
    Returns:
        Host object with all host information
        
    Raises:
        KeyError: If host not found
        subprocess.CalledProcessError: If nix eval fails
    """
    data = _nix_eval(f"entities.hosts.{hostname}", entities_path)
    
    master_key = None
    if data.get("master-key"):
        master_key = MasterKey(
            public_key=data["master-key"]["public-key"],
            key_path=data["master-key"]["key-path"],
        )
    
    return Host(
        hostname=hostname,
        domain=data.get("domain", ""),
        site=data.get("site", ""),
        master_key=master_key,
        arch=data.get("arch", "x86_64-linux"),
        nixos_system=data.get("nixos-system", True),
        kerberos_services=data.get("kerberos-services", ["host", "ssh"]),
    )


def get_domain(domain_name: str, entities_path: Path) -> Domain:
    """Query entities for domain information.
    
    Args:
        domain_name: The domain name to look up
        entities_path: Path to nix-entities repo
        
    Returns:
        Domain object with domain information
    """
    data = _nix_eval(f"entities.domains.\"{domain_name}\"", entities_path)
    
    return Domain(
        name=domain_name,
        gssapi_realm=data.get("gssapi-realm"),
    )


def get_host_fqdn(hostname: str, entities_path: Path) -> str:
    """Get fully qualified domain name for a host."""
    host = get_host(hostname, entities_path)
    return f"{hostname}.{host.domain}"


def get_all_hosts(entities_path: Path) -> list[str]:
    """Get list of all host names."""
    data = _nix_eval("builtins.attrNames entities.hosts", entities_path)
    return data


def get_all_domains(entities_path: Path) -> list[str]:
    """Get list of all domain names."""
    data = _nix_eval("builtins.attrNames entities.domains", entities_path)
    return data
