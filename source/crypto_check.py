import os
import re
import subprocess

WEAK_ALGOS = {
    'md5': 'MD5 is weak due to collision vulnerabilities. An attacker might generate collisions to forge data or signatures.',
    'sha1': 'SHA1 is vulnerable to collision attacks. Exploitation may allow signature forgery or data tampering.',
    'des': 'DES has a short key length (56 bits) making it susceptible to brute-force attacks.',
    'rc4': 'RC4 has biases in its output stream, leading to vulnerabilities in certain protocols.',
    'md5withrsa': 'Using MD5 with RSA is insecure because MD5 is compromised, potentially allowing forged signatures.',
    'sha1withrsa': 'SHA1withRSA is considered weak due to SHA1 vulnerabilities, risking signature forgery.',
    'xor': 'XOR encryption is insecure if the key is reused or predictable. An attacker can use known-plaintext or frequency analysis to recover the plaintext and potentially the key.',
    'caesar': 'Caesar cipher is a basic substitution cipher that is trivially breakable by brute force (only 25 shifts exist).'
}

# Regex to detect potential key strings (e.g., hexadecimal keys)
KEY_REGEX = re.compile(r'["\']([A-Fa-f0-9]{16,64})["\']')

def analyze_crypto(smali_dir, app_package_prefix=None):
    """
    Recursively scan the smali directory for weak cryptographic algorithms.
    If app_package_prefix is provided, only scan files whose path contains that string.
    """
    print("\n[Crypto Check] Analyzing smali code for weak cryptographic algorithms...")
    found = False
    for root_dir, dirs, files in os.walk(smali_dir):
        for file in files:
            if not file.endswith(".smali"):
                continue
            file_path = os.path.join(root_dir, file)
            # If an app package prefix is provided, only scan files that belong to the app.
            if app_package_prefix and app_package_prefix not in file_path.replace("\\", "/"):
                continue
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
            except Exception as e:
                print(f"Error reading file {file_path}: {e}")
                continue
            for idx, line in enumerate(lines):
                lower_line = line.lower()
                for algo, explanation in WEAK_ALGOS.items():
                    if algo in lower_line:
                        found = True
                        print(f"\n[Weak Crypto Detected] '{algo.upper()}' found in file: {file_path} (line {idx+1})")
                        print(f"   Explanation: {explanation}")
                        keys = KEY_REGEX.findall(line)
                        if keys:
                            print("   Potential key(s) found:")
                            for k in keys:
                                print(f"      {k}")
    if not found:
        print("No weak cryptographic algorithms were detected in the smali code.")

def check_apk_signing(apk_path):
    """
    Uses the 'apksigner' tool to check the APK's signing scheme.
    Reports if only V1 signing is used, which is less secure than V2/V3.
    """
    print("\n[Signature Check] Checking APK signing scheme...")
    try:
        result = subprocess.run(
            ['apksigner', 'verify', '--verbose', apk_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True
        )
        output = result.stdout + result.stderr
        
        # Determine the signature scheme used.
        has_v1 = "Verifies using v1" in output or "V1 scheme:" in output
        has_v2 = "Verifies using v2" in output or "V2 scheme:" in output or "V2 signature:" in output

        if has_v1 and not has_v2:
            print("Warning: APK uses only V1 signing, which is insecure compared to V2/V3.")
        elif has_v2:
            print("APK uses V2 (or later) signing, which is considered secure.")
        else:
            print("Unable to determine the signature scheme from apksigner output.")
    except FileNotFoundError:
        print("Error: apksigner tool not found. Please ensure it is installed and available in your PATH.")
    except Exception as e:
        print(f"Error checking APK signature: {e}")
