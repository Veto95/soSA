# ========================================================
# ================================================
# 🔍 sosa
# Credits: 0xCACT2S | t.me/H3LL_SHELL | github.com/Veto95
# ================================================

import os
import subprocess
import sys
import argparse
import re
import base64
from termcolor import colored

RCE_KEYWORDS = ['system', 'exec', 'sh', '/bin', 'chmod', 'su', 'curl', 'wget', 'eval', 'Runtime', 'loadLibrary', 'popen', 'dlopen', 'dlsym', 'fopen', 'strcpy', 'sprintf']

SENSITIVE_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "OpenAI Key": r"sk-[0-9a-zA-Z]{48}",
    "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
    "JWT": r"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+",
    "Password/Token": r"(pass(word)?|pwd|token|auth)[\"'=:\\s]+[^\"\s]+",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Firebase URL": r"https://[a-z0-9\-]+\.firebaseio\.com",
    "Slack Token": r"xox[baprs]-[0-9A-Za-z\-]+",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Private Key": r"-----BEGIN (RSA|DSA|EC|PGP) PRIVATE KEY-----",
    "Basic Auth": r"Basic [A-Za-z0-9+/=]{20,}",
    "Firebase API Key": r"AIza[0-9A-Za-z\-_]{35}",
    "GitLab Personal Token": r"glpat-[0-9a-zA-Z\-_]{20}",
    "Azure Storage Key": r"[A-Za-z0-9+/]{88}==",
    'firebase'  : r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    'google_captcha' : r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$',
    'google_oauth'   : r'ya29\.[0-9A-Za-z\-_]+',
    'amazon_aws_access_key_id' : r'A[SK]IA[0-9A-Z]{16}',
    'amazon_mws_auth_toke' : r'amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    'amazon_aws_url' : r's3\.amazonaws.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws.com',
    'amazon_aws_url2' : r"(" \
           r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com" \
           r"|s3://[a-zA-Z0-9-\.\_]+" \
           r"|s3-[a-zA-Z0-9-\.\_\/]+" \
           r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+" \
           r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    'facebook_access_token' : r'EAACEdEose0cBA[0-9A-Za-z]+',
    'authorization_basic' : r'basic [a-zA-Z0-9=:_\+\/-]{5,100}',
    'authorization_bearer' : r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}',
    'authorization_api' : r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}',
    'mailgun_api_key' : r'key-[0-9a-zA-Z]{32}',
    'twilio_api_key' : r'SK[0-9a-fA-F]{32}',
    'twilio_account_sid' : r'AC[a-zA-Z0-9_\-]{32}',
    'twilio_app_sid' : r'AP[a-zA-Z0-9_\-]{32}',
    'paypal_braintree_access_token' : r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
    'square_oauth_secret' : r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}',
    'square_access_token' : r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}',
    'stripe_standard_api' : r'sk_live_[0-9a-zA-Z]{24}',
    'stripe_restricted_api' : r'rk_live_[0-9a-zA-Z]{24}',
    'github_access_token' : r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*',
    'rsa_private_key' : r'-----BEGIN RSA PRIVATE KEY-----',
    'ssh_dsa_private_key' : r'-----BEGIN DSA PRIVATE KEY-----',
    'ssh_dc_private_key' : r'-----BEGIN EC PRIVATE KEY-----',
    'pgp_private_block' : r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    'json_web_token' : r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$',
    'slack_token' : r"\"api_token\":\"(xox[a-zA-Z]-[a-zA-Z0-9-]+)\"",
    'SSH_privKey' : r"([-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+)",
    'Heroku API KEY' : r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
    'possible_Creds' : r"(?i)(" \
                    r"password\s*[`=:\"]+\s*[^\s]+|" \
                    r"password is\s*[`=:\"]*\s*[^\s]+|" \
                    r"pwd\s*[`=:\"]*\s*[^\s]+|" \
                    
}

def run_cmd(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"[!] Error running command: {' '.join(command)}\n{e.output}"

def detect_base64_strings(strings):
    base64s = []
    for s in strings:
        if re.fullmatch(r'[A-Za-z0-9+/=]{20,}', s):
            try:
                decoded = base64.b64decode(s).decode('utf-8')
                if any(c.isprintable() for c in decoded):
                    base64s.append((s, decoded))
            except:
                continue
    return base64s

def scan_sensitive_patterns(strings):
    findings = []
    for line in strings:
        for label, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, line):
                findings.append((label, line))
    return findings

def scan_urls(strings):
    return [s for s in strings if re.search(r'https?://[^\s"\']+', s)]

def scan_jni_methods(strings):
    return [s for s in strings if re.search(r'Java_[a-zA-Z0-9_]+', s)]

def analyze_so_file(so_path):
    risk_score = 0
    if not os.path.isfile(so_path):
        print(f"[!] File not found: {so_path}")
        return

    report_file = f"report_{os.path.basename(so_path)}.txt"
    with open(report_file, 'w', encoding='utf-8') as log:

        def log_print(msg, color=None):
            print(colored(msg, color) if color else msg)
            log.write(re.sub(r'\x1b\[[0-9;]*m', '', msg) + '\n')

        log_print(f"[*] Android Native Scanner - Analyzing: {so_path}\n")
        log_print("[+] ELF Header Info:")
        log_print(run_cmd(['readelf', '-h', so_path]))

        log_print("\n[+] Exported Symbols:")
        nm_output = run_cmd(['nm', '-D', so_path])
        log_print(nm_output)

        log_print("\n[+] RCE-Related Symbols:")
        rce_matches = [line for line in nm_output.splitlines() if any(k in line for k in RCE_KEYWORDS)]
        for match in rce_matches:
            log_print(f"[*] {match}", "red")
            risk_score += 5
        if not rce_matches:
            log_print("[-] No suspicious symbols found.")

        log_print("\n[+] Extracting Strings:")
        strings_output = run_cmd(['strings', so_path]).splitlines()

        log_print("\n[+] Sensitive Data Detected:")
        for label, line in scan_sensitive_patterns(strings_output):
            log_print(f"[!] {label}: {line}", "green")
            risk_score += 3 if 'Key' in label or 'Token' in label else 4

        log_print("\n[+] Hardcoded URLs:")
        for url in scan_urls(strings_output):
            log_print(f"[*] URL: {url}", "green")
            risk_score += 2

        log_print("\n[+] Base64-Encoded Strings:")
        for b64, decoded in detect_base64_strings(strings_output):
            log_print(f"[*] Encoded: {b64}\n    → Decoded: {decoded}")

        log_print("\n[+] JNI Methods:")
        for jni in scan_jni_methods(strings_output):
            log_print(f"[*] {jni}")

        log_print(f"\n[+] Final Risk Score: {risk_score}")
        if risk_score >= 10:
            log_print("[!] Risk Level: HIGH ⚠️", "red")
        elif risk_score >= 5:
            log_print("[!] Risk Level: MEDIUM ⚠", "yellow")
        else:
            log_print("[+] Risk Level: LOW ✅", "green")

        log_print("\n[✓] Analysis complete. Powered by 0xCACT2S | Https://t.me/H3LL_SHELL")

def main():
    parser = argparse.ArgumentParser(description="Android Native Scanner - Analyze .so files for RCE, sensitive data, keys, URLs, JNI.")
    parser.add_argument("path", help="Path to .so file or directory containing .so files")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        for root, dirs, files in os.walk(args.path):
            for file in files:
                if file.endswith(".so"):
                    analyze_so_file(os.path.join(root, file))
    else:
        analyze_so_file(args.path)

if __name__ == '__main__':
    main()
