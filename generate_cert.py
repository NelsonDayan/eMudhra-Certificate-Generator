import argparse
import ipaddress
import re
import shutil
import subprocess
import sys
from pathlib import Path

VALIDATION_LEVELS = ("DV", "OV", "EV")
GENERATIONS = ("G3B", "G3C")

# Temporary folders are created next to this script (the project root)
BASE_DIR = Path(__file__).resolve().parent

# Folder holding the server.cnf / server.ext templates (name as in the project)
TEMPLATE_DIR = BASE_DIR / "Certification Genration Files"
TEMPLATE_FILES = ("server.cnf", "server.ext")

# Issuing CA files, named after the CA's subject, for example:
#   Private Keys/CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL.key
#   Public Certificates/CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL.pem
# The .pem is the CA certificate that signs the server certificate. The
# intermediate certificate appended to it is a separate file, for example:
#   Intermidiate Certificates/CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL.intermidiate
CA_KEY_DIR = BASE_DIR / "Private Keys"
CA_CERT_DIR = BASE_DIR / "Public Certificates"
INTERMEDIATE_DIR = BASE_DIR / "Intermidiate Certificates"
INTERMEDIATE_EXT = ".intermidiate"

# Organisation / country part of the CA name for each generation
GENERATION_ISSUER = {
    "G3B": "O=eMudhra BV,C=NL",
    "G3C": "O=eMudhra Inc,C=US",
}

CERT_VALIDITY_DAYS = "397"

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(\*\.)?([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)


# ---------- argument validation ----------

def ip_type(value: str) -> str:
    """argparse type: accept a valid IPv4/IPv6 address, else reject."""
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid IP address")


def domain_type(value: str) -> str:
    """argparse type: accept a valid domain name (wildcard allowed), else reject."""
    if not DOMAIN_RE.match(value):
        raise argparse.ArgumentTypeError(f"'{value}' is not a valid domain name")
    return value.lower()


def upper_choice(choices):
    """argparse type: case-insensitive match against a fixed set of choices."""
    def convert(value: str) -> str:
        v = value.upper()
        if v not in choices:
            raise argparse.ArgumentTypeError(
                f"invalid choice '{value}' (choose from {', '.join(choices)})"
            )
        return v
    return convert


# ---------- temporary folder handling ----------

def safe_name(value: str) -> str:
    """Make a value safe for use in a folder name on Windows/Linux/macOS.

    '*' (wildcard domains) and ':' (IPv6) are not allowed in Windows paths.
    """
    return value.replace("*", "wildcard").replace(":", "-")


def build_folder_name(domain: str, ip: str, validation_level: str, generation: str) -> str:
    """Return '{domain}-{ip}-{validation level}-{generation}'."""
    return "-".join(
        [safe_name(domain), safe_name(ip), validation_level, generation]
    )


def create_temp_folder(domain: str, ip: str, validation_level: str,
                       generation: str, base_dir: Path = BASE_DIR) -> Path:
    """Create the temporary working folder and return its path.

    Raises FileExistsError if the folder is already there, so a previous
    run's files are never overwritten by accident.
    """
    folder = base_dir / build_folder_name(domain, ip, validation_level, generation)
    folder.mkdir(parents=True, exist_ok=False)
    return folder


def copy_template_files(temp_folder: Path, template_dir: Path = TEMPLATE_DIR) -> list[Path]:
    """Copy server.cnf and server.ext into the temporary folder.

    Returns the paths of the copies. The originals are never modified.
    """
    copies = []
    for name in TEMPLATE_FILES:
        source = template_dir / name
        if not source.is_file():
            raise FileNotFoundError(f"template file not found: {source}")
        copies.append(Path(shutil.copy2(source, temp_folder / name)))
    return copies


def replace_in_file(file_path: Path, replacements: dict[str, str]) -> int:
    """Replace every placeholder key with its value inside file_path.

    Returns the total number of replacements made. Line endings are kept
    exactly as they are in the file.
    """
    with open(file_path, "r", encoding="utf-8", newline="") as f:
        content = f.read()

    total = 0
    for placeholder, value in replacements.items():
        total += content.count(placeholder)
        content = content.replace(placeholder, value)

    with open(file_path, "w", encoding="utf-8", newline="") as f:
        f.write(content)
    return total


# ---------- certificate generation ----------

def ca_name(validation_level: str, generation: str) -> str:
    """Return the CA name used in the file names, e.g.
    'CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL'."""
    return f"CN=EM {validation_level} TLS CA - {generation},{GENERATION_ISSUER[generation]}"


def get_intermediate_path(validation_level: str, generation: str) -> Path:
    """Return the intermediate certificate for the given level / generation."""
    path = INTERMEDIATE_DIR / f"{ca_name(validation_level, generation)}{INTERMEDIATE_EXT}"
    if not path.is_file():
        raise FileNotFoundError(f"intermediate certificate not found: {path}")
    return path


def get_ca_paths(validation_level: str, generation: str) -> tuple[Path, Path]:
    """Return (CA certificate, CA key) for the given validation level / generation.

    The CA name is built like 'CN=EM DV TLS CA - G3B,O=eMudhra BV,C=NL'.
    OV uses the 'OV TLS CA' (not the 'OV CS CA', which is for code signing).
    """
    name = ca_name(validation_level, generation)
    ca_cert = CA_CERT_DIR / f"{name}.pem"
    ca_key = CA_KEY_DIR / f"{name}.key"
    for path in (ca_cert, ca_key):
        if not path.is_file():
            raise FileNotFoundError(f"CA file not found: {path}")
    return ca_cert, ca_key


def run_command(command: list[str], cwd: Path) -> None:
    """Run a command inside cwd, so any files it writes land there.

    Raises subprocess.CalledProcessError (with stderr captured) on failure.
    """
    print(f"$ {' '.join(command)}")
    result = subprocess.run(
        command, cwd=cwd, check=True, capture_output=True, text=True
    )
    if result.stdout.strip():
        print(result.stdout.strip())


def generate_certificate(temp_folder: Path, ca_cert: Path, ca_key: Path) -> None:
    """Create server.key, server.csr and server.crt inside temp_folder."""
    if shutil.which("openssl") is None:
        raise FileNotFoundError("openssl was not found on PATH")

    commands = [
        ["openssl", "genrsa", "-out", "server.key", "2048"],
        ["openssl", "req", "-new", "-key", "server.key",
         "-out", "server.csr", "-config", "server.cnf"],
        ["openssl", "x509", "-req", "-in", "server.csr",
         "-CA", str(ca_cert), "-CAkey", str(ca_key),
         "-CAcreateserial", "-CAserial", "server.srl",
         "-out", "server.crt", "-days", CERT_VALIDITY_DAYS,
         "-sha256", "-extfile", "server.ext"],
    ]
    for command in commands:
        run_command(command, cwd=temp_folder)


def append_intermediate(server_cert: Path, intermediate: Path) -> None:
    """Append the intermediate certificate to server_cert (leaf first, then intermediate)."""
    leaf = server_cert.read_text(encoding="utf-8")
    chain_part = intermediate.read_text(encoding="utf-8")
    if not leaf.endswith("\n"):
        leaf += "\n"
    if not chain_part.endswith("\n"):
        chain_part += "\n"
    server_cert.write_text(leaf + chain_part, encoding="utf-8")


def rename_server_cert(temp_folder: Path, final_name: str) -> Path:
    """Rename server.crt to final_name inside temp_folder and return the new path."""
    return (temp_folder / "server.crt").rename(temp_folder / final_name)


# ---------- entry point ----------

def main():
    parser = argparse.ArgumentParser(description="Generate certificate files.")
    parser.add_argument("ip", type=ip_type, help="IP Address (IPv4 or IPv6)")
    parser.add_argument("domain", type=domain_type, help="Domain Name")
    parser.add_argument(
        "validation_levels",
        type=upper_choice(VALIDATION_LEVELS),
        metavar="{DV,OV,EV}",
        help="Validation Levels (DV,OV,EV)",
    )
    parser.add_argument(
        "generation",
        type=upper_choice(GENERATIONS),
        metavar="{G3B,G3C}",
        help="Issuer Generation / Batch Labels (G3B,G3C)",
    )
    # argparse prints the error and exits with status 2 on any invalid argument
    args = parser.parse_args()

    # Only reached when every argument is valid
    try:
        temp_folder = create_temp_folder(
            args.domain, args.ip, args.validation_levels, args.generation
        )
    except FileExistsError as exc:
        parser.error(f"temporary folder already exists: {exc.filename}")

    print(f"Created temporary folder: {temp_folder}")

    # Copy server.cnf / server.ext into the temporary folder
    try:
        config_files = copy_template_files(temp_folder)
    except OSError as exc:
        parser.error(f"could not copy template files: {exc}")

    # Fill in the placeholders using the values from the arguments
    replacements = {"{DOMAIN_NAME}": args.domain, "{IP_ADDRESS}": args.ip}
    for file_path in config_files:
        try:
            count = replace_in_file(file_path, replacements)
        except (OSError, UnicodeDecodeError) as exc:
            parser.error(f"could not update {file_path.name}: {exc}")
        print(f"Updated {file_path.name} ({count} replacements)")

    # Run the openssl commands; all outputs are written into temp_folder
    try:
        ca_cert, ca_key = get_ca_paths(args.validation_levels, args.generation)
        intermediate = get_intermediate_path(args.validation_levels, args.generation)
        generate_certificate(temp_folder, ca_cert, ca_key)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    except subprocess.CalledProcessError as exc:
        parser.error(
            f"command failed (exit {exc.returncode}): {' '.join(exc.cmd)}\n"
            f"{exc.stderr.strip()}"
        )

    # Append the intermediate to server.crt, then rename it to
    # {domain}-{ip}-{level}-{generation}.crt (same as the folder name)
    try:
        append_intermediate(temp_folder / "server.crt", intermediate)
        final_cert = rename_server_cert(temp_folder, f"{temp_folder.name}.crt")
    except OSError as exc:
        parser.error(f"could not build the certificate chain file: {exc}")

    print(f"Certificate chain: {final_cert}")
    print(f"Done. Output files are in: {temp_folder}")
    return 0


if __name__ == "__main__":
    sys.exit(main())