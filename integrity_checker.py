import os
import argparse
import hashlib
import json
from pathlib import Path

# File to store hashes
HASH_FILE = "hashes.json"

def sha256_hash(filepath):
    """Generate SHA-256 hash for a file."""
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"[ERROR] Could not read {filepath}: {e}")
        return None

def load_hashes():
    """Load stored hashes from JSON file."""
    if os.path.exists(HASH_FILE):
        with open(HASH_FILE, "r") as f:
            return json.load(f)
    return {}

def save_hashes(hashes):
    """Save the hashes to a JSON file."""
    with open(HASH_FILE, "w") as f:
        json.dump(hashes, f, indent=4)

def get_log_files(input_path):
    """Return a list of file paths from a directory or a single file."""
    path = Path(input_path)
    if path.is_dir():
        return [str(f) for f in path.glob("*") if f.is_file()]
    elif path.is_file():
        return [str(path)]
    else:
        raise FileNotFoundError(f"Path does not exist: {input_path}")

def initialize_hashes(files):
    """Create a baseline by hashing all files."""
    hashes = {}
    for file in files:
        hash_val = sha256_hash(file)
        if hash_val:
            hashes[file] = hash_val
            print(f"[+] Baseline set for: {file}")
    save_hashes(hashes)
    print("\n[*] Baseline initialization complete.")

def verify_hashes(files):
    """Compare current hashes with stored hashes."""
    stored_hashes = load_hashes()
    modified = False

    for file in files:
        current_hash = sha256_hash(file)
        if not current_hash:
            continue

        stored_hash = stored_hashes.get(file)
        if stored_hash is None:
            print(f"[?] No baseline for: {file}")
        elif current_hash != stored_hash:
            print(f"[ALERT] File tampered: {file}")
            modified = True
        else:
            print(f"[OK] {file} is intact.")

    if not modified:
        print("\n[*] No discrepancies found.")

def main():
    parser = argparse.ArgumentParser(description="Log File Integrity Checker")
    parser.add_argument("path", help="Path to log file or directory")
    parser.add_argument("--init", action="store_true", help="Initialize or reset baseline hashes")
    args = parser.parse_args()

    try:
        files = get_log_files(args.path)
    except Exception as e:
        print(f"[ERROR] {e}")
        return

    if args.init:
        initialize_hashes(files)
    else:
        verify_hashes(files)

if __name__ == "__main__":
    main()
