#!/usr/bin/env python3

import os
import subprocess
import sys
import tempfile
import time

# -----------------------------
# Logging
# -----------------------------
def log(msg, level="INFO"):
    print(f"[{time.strftime('%H:%M:%S')}] [{level}] {msg}")


# -----------------------------
# Banner Output
# -----------------------------
def print_banner(message, success=True):
    GREEN = "\033[92m"
    RED = "\033[91m"
    RESET = "\033[0m"

    color = GREEN if success else RED
    border_char = "=" if success else "!"

    border = border_char * (len(message) + 10)

    print("\n" + color + border)
    print(f"   {message}")
    print(border + RESET + "\n")


# -----------------------------
# Run Command
# -----------------------------
def run_command(cmd):
    try:
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except Exception as e:
        log(f"Command failed: {e}", "ERROR")
        return None


# -----------------------------
# Convert PCAP → 22000
# -----------------------------
def convert_to_hash(pcap):
    hash_file = f"{pcap}.22000"

    result = run_command([
        "hcxpcapngtool",
        "-o", hash_file,
        pcap
    ])

    if result is None:
        return None

    output = (result.stdout + result.stderr).lower()

    if "no hashes written" in output:
        log(f"Skipping (no usable handshake): {pcap}", "WARN")
        return None

    if not os.path.exists(hash_file) or os.path.getsize(hash_file) == 0:
        log(f"Skipping (empty hash file): {pcap}", "WARN")
        return None

    log(f"Valid hash extracted: {hash_file}", "SUCCESS")
    return hash_file


# -----------------------------
# Combine Hashes
# -----------------------------
def combine_hashes(hash_files, combined_file):
    with open(combined_file, "w") as outfile:
        for hf in hash_files:
            with open(hf, "r") as infile:
                outfile.write(infile.read())
    return combined_file


# -----------------------------
# Run Hashcat (interactive)
# -----------------------------
def run_hashcat(hash_file, wordlist):
    potfile = tempfile.NamedTemporaryFile(delete=False).name

    log(f"Running hashcat on {hash_file}", "STEP")
    log("Press 's' for status, 'q' to quit", "INFO")

    try:
        subprocess.run([
            "hashcat",
            "-m", "22000",
            hash_file,
            wordlist,
            "--potfile-path", potfile
        ])

        result = subprocess.run([
            "hashcat",
            "-m", "22000",
            hash_file,
            "--show",
            "--potfile-path", potfile
        ], stdout=subprocess.PIPE, text=True)

        if result.stdout.strip():
            return result.stdout.strip().splitlines()

        return []

    finally:
        if os.path.exists(potfile):
            os.remove(potfile)


# -----------------------------
# Parse Results
# -----------------------------
def parse_hashcat_output(lines):
    results = []

    for line in lines:
        try:
            parts = line.split(":")
            password = parts[-1]
            essid = parts[-2]
            results.append((essid, password))
        except:
            continue

    return results


# -----------------------------
# Main
# -----------------------------
def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <wordlist>")
        sys.exit(1)

    wordlist = sys.argv[1]

    if not os.path.exists(wordlist):
        log(f"Wordlist not found: {wordlist}", "ERROR")
        sys.exit(1)

    pcaps = [f for f in os.listdir(".") if f.endswith(".pcap")]

    if not pcaps:
        log("No pcap files found", "ERROR")
        sys.exit(1)

    log(f"Found {len(pcaps)} pcap files")

    hash_files = []

    # -----------------------------
    # Phase 1: Convert all pcaps
    # -----------------------------
    for i, pcap in enumerate(pcaps, 1):
        log(f"[{i}/{len(pcaps)}] Processing {pcap}")

        try:
            hf = convert_to_hash(pcap)
            if hf:
                hash_files.append(hf)
        except Exception as e:
            log(f"Error processing {pcap}: {e}", "ERROR")

    if not hash_files:
        print_banner("NO VALID HANDSHAKES FOUND", success=False)
        sys.exit(0)

    log(f"Collected {len(hash_files)} valid hash files", "SUCCESS")

    # -----------------------------
    # Phase 2: Combine hashes
    # -----------------------------
    combined_file = "combined.22000"
    combine_hashes(hash_files, combined_file)

    log(f"Combined hashes into {combined_file}", "INFO")

    # Cleanup individual hash files
    for hf in hash_files:
        if os.path.exists(hf):
            os.remove(hf)

    # -----------------------------
    # Phase 3: Crack
    # -----------------------------
    results = run_hashcat(combined_file, wordlist)

    # Cleanup combined file
    if os.path.exists(combined_file):
        os.remove(combined_file)

    # -----------------------------
    # Phase 4: Results
    # -----------------------------
    parsed = parse_hashcat_output(results)

    if parsed:
        print_banner(f"CRACKED {len(parsed)} NETWORK(S)!", success=True)

        for essid, password in parsed:
            log(f"{essid} → {password}", "CRITICAL")

    else:
        print_banner("NO PASSWORDS FOUND", success=False)

    log("Done!")


if __name__ == "__main__":
    main()