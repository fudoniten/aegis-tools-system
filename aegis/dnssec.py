"""DNSSEC key generation and management."""

import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


# Algorithm name to number mapping
ALGORITHM_MAP = {
    "RSAMD5": 1,
    "RSASHA1": 5,
    "RSASHA1-NSEC3-SHA1": 7,
    "RSASHA256": 8,
    "RSASHA512": 10,
    "ECDSAP256SHA256": 13,
    "ECDSAP384SHA384": 14,
    "ED25519": 15,
    "ED448": 16,
}

# Reverse mapping
ALGORITHM_NAMES = {v: k for k, v in ALGORITHM_MAP.items()}

# Default algorithm (widely supported, good security)
DEFAULT_ALGORITHM = "ECDSAP256SHA256"


@dataclass
class DnssecKeyFiles:
    """Paths to DNSSEC key files."""
    domain: str
    algorithm: str
    algorithm_num: int
    keytag: int
    key_file: Path      # Public key (.key)
    private_file: Path  # Private key (.private)
    ds_file: Path       # DS record (.ds)
    
    @property
    def basename(self) -> str:
        """Get the key basename (K<domain>.+<alg>+<keytag>)."""
        return f"K{self.domain}.+{self.algorithm_num:03d}+{self.keytag:05d}"


def parse_dnssec_filename(filename: str) -> tuple[str, int, int] | None:
    """Parse a DNSSEC key filename.
    
    Args:
        filename: Filename like "Kfudo.org.+013+11926.key"
        
    Returns:
        Tuple of (domain, algorithm_num, keytag) or None if not a valid DNSSEC filename
    """
    # Pattern: K<domain>.+<algorithm>+<keytag>.<extension>
    # Domain can contain dots, algorithm is 3 digits, keytag is 5 digits
    pattern = r"^K(.+)\.\+(\d{3})\+(\d{5})\.(key|private|ds)$"
    match = re.match(pattern, filename)
    if not match:
        return None
    
    domain = match.group(1)
    algorithm_num = int(match.group(2))
    keytag = int(match.group(3))
    
    return (domain, algorithm_num, keytag)


def find_dnssec_keys(directory: Path, domain: str) -> DnssecKeyFiles | None:
    """Find DNSSEC key files for a domain in a directory.
    
    Args:
        directory: Directory to search
        domain: Domain name to look for
        
    Returns:
        DnssecKeyFiles if found, None otherwise
    """
    # Look for .key files matching the domain
    for key_file in directory.glob(f"K{domain}.+*.key"):
        parsed = parse_dnssec_filename(key_file.name)
        if parsed is None:
            continue
        
        found_domain, algorithm_num, keytag = parsed
        if found_domain != domain:
            continue
        
        # Found a matching key, look for the other files
        # key_file.stem already removes the .key extension
        basename = key_file.stem
        private_file = directory / f"{basename}.private"
        ds_file = directory / f"{basename}.ds"
        
        if not private_file.exists():
            continue  # Need at least the private key
        
        algorithm = ALGORITHM_NAMES.get(algorithm_num, f"UNKNOWN({algorithm_num})")
        
        return DnssecKeyFiles(
            domain=domain,
            algorithm=algorithm,
            algorithm_num=algorithm_num,
            keytag=keytag,
            key_file=key_file,
            private_file=private_file,
            ds_file=ds_file if ds_file.exists() else ds_file,  # May not exist yet
        )
    
    return None


def generate_ksk(
    domain: str,
    output_dir: Path,
    algorithm: str = DEFAULT_ALGORITHM,
) -> DnssecKeyFiles:
    """Generate a DNSSEC Key Signing Key (KSK).
    
    Requires ldns-keygen to be available in PATH.
    
    Args:
        domain: Domain name (e.g., "fudo.org")
        output_dir: Directory to write key files
        algorithm: Algorithm name (default: ECDSAP256SHA256)
        
    Returns:
        DnssecKeyFiles with paths to generated files
        
    Raises:
        FileNotFoundError: If ldns-keygen is not available
        subprocess.CalledProcessError: If key generation fails
        ValueError: If algorithm is not recognized
    """
    if algorithm not in ALGORITHM_MAP:
        raise ValueError(
            f"Unknown algorithm: {algorithm}. "
            f"Valid options: {', '.join(ALGORITHM_MAP.keys())}"
        )
    
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Run ldns-keygen
    # -a: algorithm
    # -k: KSK (sets flags to 257)
    cmd = ["ldns-keygen", "-a", algorithm, "-k", domain]
    
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=output_dir,
        check=True,
    )
    
    # ldns-keygen prints the basename to stdout
    basename = result.stdout.strip()
    if not basename:
        raise RuntimeError("ldns-keygen did not return a key basename")
    
    # Parse the basename to get algorithm and keytag
    parsed = parse_dnssec_filename(f"{basename}.key")
    if parsed is None:
        raise RuntimeError(f"Could not parse ldns-keygen output: {basename}")
    
    _, algorithm_num, keytag = parsed
    
    return DnssecKeyFiles(
        domain=domain,
        algorithm=algorithm,
        algorithm_num=algorithm_num,
        keytag=keytag,
        key_file=output_dir / f"{basename}.key",
        private_file=output_dir / f"{basename}.private",
        ds_file=output_dir / f"{basename}.ds",
    )


def read_ds_record(ds_file: Path) -> str | None:
    """Read and return the DS record from a .ds file.
    
    Args:
        ds_file: Path to the .ds file
        
    Returns:
        The DS record string, or None if file doesn't exist
    """
    if not ds_file.exists():
        return None
    return ds_file.read_text().strip()
