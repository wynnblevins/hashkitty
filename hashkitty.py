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
# Run Command (safe wrapper)
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

    # 🔑 Skip junk captures
    if "no hashes written" in output:
        log(f"Skipping (no usable handshake): {pcap}", "WARN")
        return None

    if not os.path.exists(hash_file) or os.path.getsize(hash_file) == 0:
        log(f"Skipping (empty hash file): {pcap}", "WARN")
        return None

    log(f"Valid hash extracted: {hash_file}", "SUCCESS")
    return hash_file


# -----------------------------
# Run Hashcat (interactive)
# -----------------------------
def run_hashcat(hash_file, wordlist):
    potfile = tempfile.NamedTemporaryFile(delete=False).name

    log(f"Running hashcat on {hash_file}", "STEP")
    log("Press 's' for status, 'q' to quit", "INFO")

    try:
        # 🔥 Interactive mode (no stdout capture!)
        subprocess.run([
            "hashcat",
            "-m", "22000",
            hash_file,
            wordlist,
            "--potfile-path", potfile
        ])

        # Check results after run
        result = subprocess.run([
            "hashcat",
            "-m", "22000",
            hash_file,
            "--show",
            "--potfile-path", potfile
        ], stdout=subprocess.PIPE, text=True)

        if result.stdout.strip():
            return result.stdout.strip()

        return None

    finally:
        if os.path.exists(potfile):
            os.remove(potfile)


# -----------------------------
# Parse hashcat output
# -----------------------------
def parse_hashcat_output(line):
    try:
        parts = line.split(":")
        password = parts[-1]
        essid = parts[-2]
        return essid, password
    except:
        return None, None


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

    cracked_count = 0

    for i, pcap in enumerate(pcaps, 1):
        log(f"[{i}/{len(pcaps)}] Processing {pcap}")

        try:
            hash_file = convert_to_hash(pcap)

            if not hash_file:
                continue  # skip invalid pcaps

            result = run_hashcat(hash_file, wordlist)

            if result:
                essid, password = parse_hashcat_output(result)

                if essid and password:
                    print_banner(f"PASSWORD FOUND! {essid} → {password}", success=True)
                    log(f"CRACKED → {essid} : {password}", "CRITICAL")
                    cracked_count += 1
                else:
                    print_banner("PASSWORD FOUND (unable to parse details)", success=True)
                    log(f"Raw result: {result}", "WARN")

            else:
                print_banner("NO PASSWORD FOUND IN WORDLIST", success=False)
                log("No match found", "INFO")

        except Exception as e:
            log(f"Error processing {pcap}: {e}", "ERROR")

        finally:
            # Cleanup
            hash_path = f"{pcap}.22000"
            if os.path.exists(hash_path):
                os.remove(hash_path)

    log(f"Done. Cracked networks: {cracked_count}/{len(pcaps)}")


if __name__ == "__main__":
    main()