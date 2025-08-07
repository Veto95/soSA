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
    "Firebase URL": r"https://.*\\.firebaseio\\.com",
    "Private Key": r"-----BEGIN (EC|RSA|DSA)? ?PRIVATE KEY-----",
    "Heroku API Key": r"(?i)heroku[a-z0-9]{32}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Publishable Key": r"pk_live_[0-9a-zA-Z]{24}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Auth Token / Password": r"(pass(word)?|pwd|secret|token|auth|session)[\"'=:\\s]{1,5}[^\"'\s]+",
    "Database URI": r"(postgres|mongodb|mysql|sql):\/\/[^
\s\"']+",
    "Generic API Key": r"(?i)(api[_-]?key|access[_-]?token)[\"'=:\\s]{1,5}[0-9a-zA-Z\-_:]{16,}"
}

SUMMARY = defaultdict(list)

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        return f"[!] Error running: {' '.join(cmd)}\n{e}"

def entropy(s):
    import math
    prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
    return -sum([p * math.log(p) / math.log(2.0) for p in prob])

def detect_base64_strings(lines):
    base64s = []
    for s in lines:
        if re.fullmatch(r'[A-Za-z0-9+/=]{16,}', s):
            try:
                decoded = base64.b64decode(s).decode('utf-8', errors='ignore')
                if any(c.isprintable() for c in decoded) and entropy(s) > 4.0:
                    base64s.append((s, decoded[:80]))
            except:
                continue
    return base64s

def scan_sensitive_patterns(lines):
    results = []
    for line in lines:
        for label, pattern in SENSITIVE_PATTERNS.items():
            if re.search(pattern, line):
                results.append((label, line))
    return results

def scan_urls(lines):
    return [s for s in lines if re.search(r'https?://[^\s"']+', s)]

def scan_jni_methods(lines):
    return [s for s in lines if re.search(r'Java_[a-zA-Z0-9_]+', s)]

def log_print(msg, color=None, file=None):
    clean_msg = re.sub(r'\x1b\[[0-9;]*m', '', msg)
    if file:
        file.write(clean_msg + '\n')
    print(colored(msg, color) if color else msg)

def analyze_so_file(path, verbose=True, write_json=False):
    risk_score = 0
    output = {}
    report_file = f"report_{os.path.basename(path)}.txt"
    with open(report_file, 'w', encoding='utf-8') as log:
        log_print(f"\n📂 Analyzing: {path}", "cyan", log)
        log_print("🔎 ELF Header:", "magenta", log)
        elf_header = run_cmd(['readelf', '-h', path])
        log_print(elf_header, file=log)

        log_print("\n🔧 Exported Symbols:", "magenta", log)
        nm_output = run_cmd(['nm', '-D', path])
        log_print(nm_output, file=log)

        rce_matches = [line for line in nm_output.splitlines() if any(k in line for k in RCE_KEYWORDS)]
        log_print("\n💣 RCE-Related Symbols:", "red", log)
        if rce_matches:
            for rce in rce_matches:
                log_print(f"[*] {rce}", "red", log)
                risk_score += 5
                SUMMARY['RCE'].append((path, rce))
        else:
            log_print("[-] None found.", log)

        strings_out = run_cmd(['strings', path]).splitlines()

        log_print("\n🕵 Sensitive Patterns:", "yellow", log)
        for label, line in scan_sensitive_patterns(strings_out):
            log_print(f"[!] {label}: {line}", "yellow", log)
            risk_score += 3
            SUMMARY[label].append((path, line))

        log_print("\n🌍 URLs:", "blue", log)
        for url in scan_urls(strings_out):
            log_print(f"[+] URL: {url}", "blue", log)
            risk_score += 1
            SUMMARY['URLs'].append((path, url))

        log_print("\n🔐 Base64 Encoded Strings:", "green", log)
        for b64, decoded in detect_base64_strings(strings_out):
            log_print(f"[+] Encoded: {b64}\n    → {decoded}", "green", log)
            SUMMARY['Base64'].append((path, decoded))

        log_print("\n🧬 JNI Methods:", "cyan", log)
        for jni in scan_jni_methods(strings_out):
            log_print(f"[*] {jni}", "cyan", log)
            SUMMARY['JNI'].append((path, jni))

        log_print(f"\n🧲 Final Risk Score: {risk_score}", "magenta", log)
        if risk_score >= 10:
            log_print("⚠️  Risk: HIGH", "red", log)
        elif risk_score >= 5:
            log_print("⚠️  Risk: MEDIUM", "yellow", log)
        else:
            log_print("✅ Risk: LOW", "green", log)

        output.update({
            "file": path,
            "score": risk_score,
            "rce": rce_matches,
            "urls": scan_urls(strings_out),
            "jni": scan_jni_methods(strings_out),
            "base64": detect_base64_strings(strings_out),
            "secrets": scan_sensitive_patterns(strings_out)
        })

    if write_json:
        json_path = f"{path}.json"
        with open(json_path, 'w') as jf:
            json.dump(output, jf, indent=2)
        print(colored(f"[✓] JSON report saved: {json_path}", "green"))

def threaded_scan(folder):
    threads = []
    for root, _, files in os.walk(folder):
        for file in files:
            if file.endswith('.so'):
                path = os.path.join(root, file)
                t = threading.Thread(target=analyze_so_file, args=(path,))
                threads.append(t)
                t.start()

    for t in threads:
        t.join()

def show_summary():
    print("\n================= 🔚 SUMMARY =================")
    for key, entries in SUMMARY.items():
        print(colored(f"\n📁 {key} Findings:", "cyan"))
        for path, detail in entries:
            print(f"  • {path} → {detail}")
    print("==============================================")

def main():
    parser = argparse.ArgumentParser(description="Enhanced Android Native Scanner (.so RCE, Keys, URLs, JNI)")
    parser.add_argument("path", help="Path to .so file or folder")
    parser.add_argument("--json", action="store_true", help="Save detailed JSON report per file")
    args = parser.parse_args()

    if os.path.isdir(args.path):
        threaded_scan(args.path)
    else:
        analyze_so_file(args.path, write_json=args.json)

    show_summary()

if __name__ == '__main__':
    main()
