# 🛡️ sosa (.so Edition)

Analyze Android native `.so` files for:

- 🔐 Hardcoded tokens, API keys, JWTs, cloud creds
- 🌍 Embedded URLs (Firebase, APIs, endpoints)
- 🧨 Dangerous functions (`system`, `exec`, `popen`, etc.)
- 🧬 JNI method names (e.g., `Java_com_package_Class_method`)
- 🧾 Base64-encoded payloads with entropy check

## 🚀 Usage

```bash
python3 sosa.py libexample.so
python3 sosa.py ./libs/ --json
```

## ✅ Output

- Colored terminal report (risk score, per finding)
- `report_*.txt` per file scanned
- Optional `.json` report (`--json` flag)

## 📦 Features

- Multi-threaded folder scan
- Entropy filter for better base64 detection
- Supports secrets from AWS, GitHub, Slack, OpenAI, Firebase, and more
- Summary overview after all scans

---

Made by [0xCACT2S](https://t.me/H3LL_SHELL)
