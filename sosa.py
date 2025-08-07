# ========================================================
# 🔍 sosa (.so file analyzer)
# Powered by 0xCACT2S | t.me/H3LL_SHELL | github.com/Veto95
# ========================================================

import os
import re
import sys
import json
import base64
import argparse
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from collections import defaultdict

RCE_KEYWORDS = [
    'system', 'exec', 'sh', '/bin', 'chmod', 'su', 'curl', 'wget', 'eval',
    'Runtime', 'loadLibrary', 'popen', 'dlopen', 'dlsym', 'fopen',
    'strcpy', 'sprintf', 'memcpy', 'gets', 'fgets', 'vsprintf', 'strcat'
]

SENSITIVE_PATTERNS = {
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "OpenAI Key": r"sk-[0-9a-zA-Z]{48}",
    "GitHub Token": r"gh[pousr]_[0-9a-zA-Z]{36,}",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "JWT": r"eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+",
    "AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?['\"][0-9a-zA-Z\/+]{40}['\"]",
    "Firebase URL": r"https://.*\.firebaseio\.com",
    "Private Key": r"-----BEGIN (EC|RSA|DSA)? ?PRIVATE KEY-----",
    "Heroku API Key": r"(?i)heroku[a-z0-9]{32}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Auth Token / Password": r"(pass(word)?|pwd|secret|token|auth|session)[\"'=:\\s]{1,5}[^\"'\s]+",
    "Database URI": r"(postgres|mongodb|mysql|sql)://[^\s\"']+",
    "Generic API Key": r"(?i)(api[_-]?key|access[_-]?token)[\"'=:\\s]{1,5}[0-9a-zA-Z\-_:]{16,}"
}

SUMMARY = defaultdict(list)

def check_dependencies():
    tools = ['readelf', 'nm', 'strings']
    for tool in tools:
        if subprocess.run(['which', tool], capture_output=True).returncode != 0:
            print(colored(f"[!] Error: {tool} not found. Please install it.", "red"))
            sys.exit(1)

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"[!] Error running: {' '.join(cmd)}\n{e}"
    except FileNotFoundError:
        return f"[!] Error: Command {' '.join(cmd)} not found."

def entropy(s):
    if not s:  # Handle empty strings
        return 0.0
    import math
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def scan_strings(strings_out):
    results = {
        'sensitive': [],
        'urls': [],
        'jni': [],
        'base64': []
    }
    for line in strings_out:
        # Sensitive patterns
        for label, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, line):
                results['sensitive'].append((label, line))
        # URLs
        if re.search(r'https?://[^\s"']+', line):
            results['urls'].append(line)
        # JNI methods
        if re.search(r'Java_[a-zA-Z0-9_]+', line):
            results['jni'].append(line)
        # Base64
        if re.fullmatch(r'[A-Za-z0-9+/=]{16,}', line) and len(line) % 4 == 0:
            try:
                decoded = base64.b64decode(line, validate=True).decode('utf-8', errors='ignore')
                if any(c.isprintable() for c in decoded) and entropy(line) > 4.0:
                    results['base64'].append((line, decoded[:80]))
            except:
                continue
    return results

def log_print(msg, color=None, file=None, redact=False):
    clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)
    if redact and file:
        clean_msg = re.sub(r'(?i)(api[_-]?key|access[_-]?token|pass(word)?|secret|token)[\"'=:\\s]{1,5}[^\"'\s]+', '[REDACTED]', clean_msg)
    clean_msg = ''.join(c for c in clean_msg if c.isprintable())
    if file:
        file.write(clean_msg + '\n')
    print(colored(msg, color) if color else msg)

def analyze_so_file(path, verbose=True, write_json=False, redact=False):
    risk_score = 0
    output = {}
    report_file = f"report_{os.path.basename(path)}.txt"
    try:
        with open(report_file, 'w', encoding='utf-8') as log:
            log_print(f"\n📂 Analyzing: {path}", "cyan", log, redact)
            log_print("🔎 ELF Header:", "magenta", log, redact)
            elf_header = run_cmd(['readelf', '-h', path])
            log_print(elf_header, file=log)

            log_print("\n🔧 Exported Symbols:", "magenta", log, redact)
            nm_output = run_cmd(['nm', '-D', path])
            log_print(nm_output, file=log)

            rce_matches = [line for line in nm_output.splitlines() if any(k in line for k in RCE_KEYWORDS)]
            log_print("\n💣 RCE-Related Symbols:", "red", log, redact)
            if rce_matches:
                for rce in rce_matches:
                    log_print(f"[*] {rce}", "red", log, redact)
                    risk_score += 5
                    SUMMARY['RCE'].append((path, rce))
            else:
                log_print("[-] None found.", file=log)

            strings_out = run_cmd(['strings', path]).splitlines()
            scanned = scan_strings(strings_out)

            log_print("\n🕵 Sensitive Patterns:", "yellow", log, redact)
            for label, line in scanned['sensitive']:
                log_print(f"[!] {label}: {line}", "yellow", log, redact)
                risk_score += 3
                SUMMARY[label].append((path, line))

            log_print("\n🌍 URLs:", "blue", log, redact)
            for url in scanned['urls']:
                log_print(f"[+] URL: {url}", "blue", log, redact)
                risk_score += 1
                if re.search(r'(malicious|phishing|exploit)\.com', url, re.I):
                    risk_score += 5
                    log_print(f"[!] Suspicious URL detected: {url}", "red", log, redact)
                SUMMARY['URLs'].append((path, url))

            log_print("\n🔐 Base64 Encoded Strings:", "green", log, redact)
            for b64, decoded in scanned['base64']:
                log_print(f"[+] Encoded: {b64}\n    → {decoded}", "green", log, redact)
                SUMMARY['Base64'].append((path, decoded))

            log_print("\n🧬 JNI Methods:", "cyan", log, redact)
            for jni in scanned['jni']:
                log_print(f"[*] {jni}", "cyan", log, redact)
                SUMMARY['JNI'].append((path, jni))

            log_print(f"\n🧲 Final Risk Score: {risk_score}", "magenta", log, redact)
            if risk_score >= 10:
                log_print("⚠️  Risk: HIGH", "red", log, redact)
            elif risk_score >= 5:
                log_print("⚠️  Risk: MEDIUM", "yellow", log, redact)
            else:
                log_print("✅ Risk: LOW", "green", log, redact)

            output.update({
                "file": path,
                "score": risk_score,
                "rce": rce_matches,
                "urls": scanned['urls'],
                "jni": scanned['jni'],
                "base64": scanned['base64'],
                "secrets": scanned['sensitive']
            })

    except PermissionError:
        log_print(f"[!] Error: Cannot write to {report_file}. Check permissions.", "red")
        return
    except Exception as e:
        log_print(f"[!] Unexpected error writing report: {e}", "red")
        return

    if write_json:
        json_path = f"{path}.json"
        try:
            with open(json_path, 'w', encoding='utf-8') as jf:
                json.dump(output, jf, indent=2)
            log_print(f"[✓] JSON report saved: {json_path}", "green")
        except PermissionError:
            log_print(f"[!] Error: Cannot write to {json_path}. Check permissions.", "red")
        except Exception as e:
            log_print(f"[!] Unexpected error writing JSON: {e}", "red")

def threaded_scan(folder, write_json=False, redact=False):
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith('.so'):
                    path = os.path.join(root, file)
                    futures.append(executor.submit(analyze_so_file, path, True, write_json, redact))
        for future in futures:
            future.result()

def show_summary():
    print(colored("\n================= 🔚 SUMMARY =================", "cyan"))
    for key, entries in SUMMARY.items():
        print(colored(f"\n📁 {key} Findings:", "cyan"))
        for path, detail in entries:
            print(f"  • {path} → {detail}")
    print(colored("==============================================", "cyan"))

def main():
    check_dependencies()
    parser = argparse.ArgumentParser(description="Enhanced Android Native Scanner (.so RCE, Keys, URLs, JNI)")
    parser.add_argument("path", help="Path to .so file or folder")
    parser.add_argument("--json", action="store_true", help="Save detailed JSON report per file")
    parser.add_argument("--redact", action="store_true", help="Redact sensitive data in logs")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        threaded_scan(args.path, args.json, args.redact)
    else:
        analyze_so_file(args.path, write_json=args.json, redact=args.redact)

    show_summary()

if __name__ == '__main__':
    main()
