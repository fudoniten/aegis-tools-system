"""Configuration management for aegis-secrets repo."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib
except ImportError:
    import tomli as tomllib  # type: ignore

import tomli_w  # type: ignore


@dataclass
class HostConfig:
    """Configuration for a host."""
    hostname: str
    services: list[str] = field(default_factory=lambda: ["host", "ssh"])
    filesystem_keys: list[str] = field(default_factory=list)
    extra_secrets: dict[str, str] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, hostname: str, data: dict) -> "HostConfig":
        return cls(
            hostname=hostname,
            services=data.get("services", ["host", "ssh"]),
            filesystem_keys=data.get("filesystem_keys", []),
            extra_secrets=data.get("extra_secrets", {}),
        )
    
    def to_dict(self) -> dict:
        return {
            "services": self.services,
            "filesystem_keys": self.filesystem_keys,
            "extra_secrets": self.extra_secrets,
        }


@dataclass
class UserConfig:
    """Configuration for a user."""
    username: str
    hosts: list[str]
    repo_url: str | None = None
    
    @classmethod
    def from_dict(cls, username: str, data: dict) -> "UserConfig":
        return cls(
            username=username,
            hosts=data.get("hosts", []),
            repo_url=data.get("repo_url"),
        )
    
    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "hosts": self.hosts,
        }
        if self.repo_url:
            d["repo_url"] = self.repo_url
        return d


@dataclass
class RoleConfig:
    """Configuration for a role."""
    name: str
    host: str
    
    @classmethod
    def from_dict(cls, name: str, data: dict) -> "RoleConfig":
        return cls(
            name=name,
            host=data.get("host", ""),
        )
    
    def to_dict(self) -> dict:
        return {
            "host": self.host,
        }


@dataclass
class DomainConfig:
    """Configuration for a domain."""
    name: str
    realm: str | None = None
    
    @classmethod
    def from_dict(cls, name: str, data: dict) -> "DomainConfig":
        return cls(
            name=name,
            realm=data.get("realm"),
        )
    
    def to_dict(self) -> dict:
        d = {}
        if self.realm:
            d["realm"] = self.realm
        return d


class SecretsRepo:
    """Interface to the aegis-secrets repository."""
    
    def __init__(self, path: Path):
        self.path = path
        self.src_path = path / "src"
        self.build_path = path / "build"
        self.keys_path = path / "keys"
    
    def ensure_structure(self) -> None:
        """Create the expected directory structure if missing."""
        (self.src_path / "hosts").mkdir(parents=True, exist_ok=True)
        (self.src_path / "domains").mkdir(parents=True, exist_ok=True)
        (self.src_path / "roles").mkdir(parents=True, exist_ok=True)
        (self.src_path / "users").mkdir(parents=True, exist_ok=True)
        (self.keys_path / "users").mkdir(parents=True, exist_ok=True)
        self.build_path.mkdir(parents=True, exist_ok=True)
    
    # Host configuration
    
    def get_host_config(self, hostname: str) -> HostConfig | None:
        """Read host configuration."""
        config_path = self.src_path / "hosts" / f"{hostname}.toml"
        if not config_path.exists():
            return None
        
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        return HostConfig.from_dict(hostname, data)
    
    def set_host_config(self, config: HostConfig) -> None:
        """Write host configuration."""
        config_path = self.src_path / "hosts" / f"{config.hostname}.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, "wb") as f:
            tomli_w.dump(config.to_dict(), f)
    
    def list_hosts(self) -> list[str]:
        """List all configured hosts."""
        hosts_dir = self.src_path / "hosts"
        if not hosts_dir.exists():
            return []
        return [p.stem for p in hosts_dir.glob("*.toml")]
    
    # User configuration
    
    def get_user_config(self, username: str) -> UserConfig | None:
        """Read user configuration."""
        config_path = self.src_path / "users" / f"{username}.toml"
        if not config_path.exists():
            return None
        
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        return UserConfig.from_dict(username, data)
    
    def set_user_config(self, config: UserConfig) -> None:
        """Write user configuration."""
        config_path = self.src_path / "users" / f"{config.username}.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, "wb") as f:
            tomli_w.dump(config.to_dict(), f)
    
    def list_users(self) -> list[str]:
        """List all configured users."""
        users_dir = self.src_path / "users"
        if not users_dir.exists():
            return []
        return [p.stem for p in users_dir.glob("*.toml")]
    
    # Role configuration
    
    def get_role_config(self, role_name: str) -> RoleConfig | None:
        """Read role configuration."""
        config_path = self.src_path / "roles" / f"{role_name}.toml"
        if not config_path.exists():
            return None
        
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        return RoleConfig.from_dict(role_name, data)
    
    def set_role_config(self, config: RoleConfig) -> None:
        """Write role configuration."""
        config_path = self.src_path / "roles" / f"{config.name}.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, "wb") as f:
            tomli_w.dump(config.to_dict(), f)
    
    def list_roles(self) -> list[str]:
        """List all configured roles."""
        roles_dir = self.src_path / "roles"
        if not roles_dir.exists():
            return []
        return [p.stem for p in roles_dir.glob("*.toml")]
    
    # Domain configuration
    
    def get_domain_config(self, domain_name: str) -> DomainConfig | None:
        """Read domain configuration."""
        # Domain names have dots, use a safe filename
        safe_name = domain_name.replace(".", "_")
        config_path = self.src_path / "domains" / f"{safe_name}.toml"
        if not config_path.exists():
            return None
        
        with open(config_path, "rb") as f:
            data = tomllib.load(f)
        return DomainConfig.from_dict(domain_name, data)
    
    def set_domain_config(self, config: DomainConfig) -> None:
        """Write domain configuration."""
        safe_name = config.name.replace(".", "_")
        config_path = self.src_path / "domains" / f"{safe_name}.toml"
        config_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_path, "wb") as f:
            tomli_w.dump(config.to_dict(), f)
    
    # Build paths
    
    def host_build_path(self, hostname: str) -> Path:
        """Get the build output directory for a host."""
        return self.build_path / "hosts" / hostname
    
    def domain_build_path(self, domain_name: str) -> Path:
        """Get the build output directory for a domain."""
        safe_name = domain_name.replace(".", "_")
        return self.build_path / "domains" / safe_name
    
    def role_build_path(self, role_name: str) -> Path:
        """Get the build output directory for a role."""
        return self.build_path / "roles"
    
    # User keys
    
    def user_key_path(self, username: str) -> Path:
        """Get the path to a user's private key (encrypted)."""
        return self.keys_path / "users" / f"{username}.age"
    
    def admin_key_path(self) -> Path:
        """Get the path to the admin public key."""
        return self.keys_path / "admin.pub"
