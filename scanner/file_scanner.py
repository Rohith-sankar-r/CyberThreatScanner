from .virustotal_scanner import scan_hash_virustotal
import hashlib
import os

def calculate_sha256(file_path):
    """Calculate SHA256 hash of a file"""
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception:
        return None

def load_malicious_hashes():
    """Load malicious hashes from file"""
    with open("malicious_hashes.txt", "r") as f:
        return set(line.strip() for line in f if line.strip())

def scan_file(file_path, malicious_hashes):
    file_hash = calculate_sha256(file_path)
    if not file_hash:
        return "ERROR: Unable to read file or file not found"


    if file_hash in malicious_hashes:
        return "MALICIOUS (Local DB)"

    vt_result = scan_hash_virustotal(file_hash)

    if isinstance(vt_result, dict):
        if vt_result["malicious"] > 0:
            return f"MALICIOUS (VirusTotal: {vt_result})"
        else:
            return "CLEAN (VirusTotal)"
    else:
        return vt_result

def scan_directory(directory_path):
    if not os.path.isdir(directory_path):
        print("❌ Directory not found")
        return

    malicious_hashes = load_malicious_hashes()
    print(f"\n🔍 Scanning directory: {directory_path}\n")

    for root, _, files in os.walk(directory_path):
        for file in files:
            full_path = os.path.join(root, file)
            result = scan_file(full_path, malicious_hashes)

            if result == "MALICIOUS":
                print(f"⚠️ MALICIOUS → {full_path}")
            elif result == "CLEAN":
                print(f"✅ CLEAN → {full_path}")
            else:
                print(f"❌ ERROR → {full_path}")

if __name__ == "__main__":
    choice = input("Scan (1) File or (2) Directory? ")

    if choice == "1":
        path = input("Enter file path: ")
        hashes = load_malicious_hashes()
        result = scan_file(path, hashes)
        print(f"\nResult: {result}")

    elif choice == "2":
        dir_path = input("Enter directory path: ")
        scan_directory(dir_path)

    else:
        print("Invalid choice")
