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

if sys.version_info < (3, 7):
    print(colored("[!] Error: Python 3.7+ required for regex compatibility.", "red"))
    sys.exit(1)

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
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            return f"[!] Error running: {' '.join(cmd)}\n{stderr}"
        return stdout.strip()
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
        if re.search(r'https?://[^ \t\n"\'<>]+', line):
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
        for pattern in SENSITIVE_PATTERNS.values():
            clean_msg = re.sub(pattern, '[REDACTED]', clean_msg)
    clean_msg = ''.join(c for c in clean_msg if c.isprintable())
    if file:
        file.write(clean_msg + '\n')
    print(colored(msg, color) if color else msg)

def analyze_so_file(path, verbose=True, write_json=False, redact=False):
    if not os.path.exists(path):
        log_print(f"[!] Error: File {path} does not exist.", "red")
        return
    if not path.lower().endswith('.so'):
        log_print(f"[!] Error: {path} is not a .so file.", "red")
        return

    risk_score = 0
    output = {}
    report_file = f"report_{os.path.basename(path)}.txt"
    try:
        with open(report_file, 'w', encoding='utf-8') as log:
            def log_verbose(msg, color=None, file=None):
                if verbose:
                    log_print(msg, color, file, redact)

            log_verbose(f"\n📂 Analyzing: {path}", "cyan", log)
            log_verbose("🔎 ELF Header:", "magenta", log)
            elf_header = run_cmd(['readelf', '-h', path])
            if "Error" in elf_header:
                log_verbose(f"[!] Failed to parse ELF header: {elf_header}", "red", log)
                return
            log_verbose(elf_header, file=log)

            log_verbose("\n🔧 Exported Symbols:", "magenta", log)
            nm_output = run_cmd(['nm', '-D', path])
            if "Error" in nm_output:
                log_verbose(f"[!] Failed to parse symbols: {nm_output}", "red", log)
                return
            if not nm_output.strip():
                log_verbose("[!] No symbols found in file.", "yellow", log)
                return
            log_verbose(nm_output, file=log)

            rce_matches = [line for line in nm_output.splitlines() if any(k in line for k in RCE_KEYWORDS)]
            log_verbose("\n💣 RCE-Related Symbols:", "red", log)
            if rce_matches:
                for rce in rce_matches:
                    log_verbose(f"[*] {rce}", "red", log)
                    risk_score += 5
                    SUMMARY['RCE'].append((path, rce))
            else:
                log_verbose("[-] None found.", file=log)

            log_verbose("\n🕵 Sensitive Patterns:", "yellow", log)
            strings_cmd = ['strings', path]
            try:
                process = subprocess.Popen(strings_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                strings_out = [line.strip() for line in process.stdout if line.strip()]
                stderr = process.stderr.read()
                if process.returncode != 0:
                    log_verbose(f"[!] Failed to extract strings: {stderr}", "red", log)
                    return
            except FileNotFoundError:
                log_verbose(f"[!] Error: strings command not found.", "red", log)
                return

            scanned = scan_strings(strings_out)
            for label, line in scanned['sensitive']:
                log_verbose(f"[!] {label}: {line}", "yellow", log)
                risk_score += 3
                SUMMARY[label].append((path, line))

            log_verbose("\n🌍 URLs:", "blue", log)
            for url in scanned['urls']:
                log_verbose(f"[+] URL: {url}", "blue", log)
                risk_score += 1
                if re.search(r'(malicious|phishing|exploit)\.com', url, re.I):
                    risk_score += 5
                    log_verbose(f"[!] Suspicious URL detected: {url}", "red", log)
                SUMMARY['URLs'].append((path, url))

            log_verbose("\n🔐 Base64 Encoded Strings:", "green", log)
            for b64, decoded in scanned['base64']:
                log_verbose(f"[+] Encoded: {b64}\n    → {decoded}", "green", log)
                SUMMARY['Base64'].append((path, decoded))

            log_verbose("\n🧬 JNI Methods:", "cyan", log)
            for jni in scanned['jni']:
                log_verbose(f"[*] {jni}", "cyan", log)
                SUMMARY['JNI'].append((path, jni))

            risk_score = min(risk_score, 100)  # Cap risk score
            log_verbose(f"\n🧲 Final Risk Score: {risk_score}", "magenta", log)
            if risk_score >= 10:
                log_verbose("⚠️  Risk: HIGH", "red", log)
            elif risk_score >= 5:
                log_verbose("⚠️  Risk: MEDIUM", "yellow", log)
            else:
                log_verbose("✅ Risk: LOW", "green", log)

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
    if not os.path.isdir(folder):
        log_print(f"[!] Error: {folder} is not a directory.", "red")
        return
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for root, _, files in os.walk(folder):
            for file in files:
                if file.lower().endswith('.so'):
                    path = os.path.join(root, file)
                    futures.append(executor.submit(analyze_so_file, path, True, write_json, redact))
        for future in futures:
            try:
                future.result()
            except Exception as e:
                log_print(f"[!] Thread error for {path}: {e}", "red")

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
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        threaded_scan(args.path, args.json, args.redact)
    else:
        analyze_so_file(args.path, args.verbose, args.json, args.redact)

    show_summary()

if __name__ == '__main__':
    main()
