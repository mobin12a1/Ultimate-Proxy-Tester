<div align="center">

# ⚡ Ultimate Proxy Tester

**Fast, asynchronous proxy checking from your terminal.**

HTTP · SOCKS4 · SOCKS5 &nbsp; | &nbsp; Python &nbsp; | &nbsp; Windows · macOS · Linux · Termux

**[English Documentation](README%5BEN%5D.md) · [مستندات فارسی](README%5BFA%5D.md)**

</div>

---

## 📖 Documentation

Select your preferred language to read the full guide:

| Language | Full documentation |
| :--- | :--- |
| 🇬🇧 **English** | **[Read the complete English guide →](README%5BEN%5D.md)** |
| 🇮🇷 **فارسی** | **[مشاهدهٔ راهنمای کامل فارسی ←](README%5BFA%5D.md)** |

## 🔎 Overview

**Ultimate Proxy Tester (UPT)** is a Python command-line utility for checking proxy endpoints. It runs a **handshake stage**, optionally follows it with a **connectivity verification stage**, and writes the results to text and JSON files.

Built for handling lists of proxy endpoints with adjustable concurrency—not for discovering or generating proxies.

## ✨ Highlights

- **HTTP and SOCKS modes:** check HTTP proxies or try SOCKS5/SOCKS4 handshakes.
- **Async pipeline:** concurrent handshakes and optional verification.
- **Flexible input:** paste endpoints or load them from a text file.
- **Configurable:** connection/read timeouts, workers and concurrency cap.
- **Useful output:** status, latency, and optional GeoIP information.
- **Cross-platform Python CLI:** terminal interface and command-line arguments.

## 🚀 Quick Start

**Prerequisites:** Python 3.10+ recommended; internet access is required for online verification.

```bash
python -m pip install -r requirements.txt
python UPT.py
```

On platforms where `python` is unavailable, use `python3`.

To scan from a local input file:

```bash
python UPT.py --type http --file proxies.txt
```

The tool writes `result.txt` and `result.json` to the **current working directory**. The file `proxies.txt` must be supplied by you; it is not bundled with the project.

## 📂 Repository Structure

```text
Ultimate-Proxy-Tester/
├── UPT.py                 # Main program
├── README.md              # Overview and language selection
├── README[EN].md          # Complete English documentation
├── README[FA].md          # مستندات کامل فارسی
├── requirements.txt       # HTTP verification dependency
├── requirements-geoip.txt # Optional GeoIP dependency
├── proxies.example.txt    # Input-format examples only
├── SECURITY.md            # Security and privacy guidance
└── .gitignore             # Excludes local inputs/results
```

## ⚠️ Important Notes

- **Handshake success is not the same as verified working access.** Keep verification enabled if you need the second-stage check.
- The HTTP and SOCKS modes must be selected separately; a URL scheme in an input line does not automatically change the mode.
- Some checks use **unencrypted HTTP**. Never assume the whole test path is protected by TLS.
- Only test proxy endpoints that you own or have permission to test. **Do not upload proxy credentials or private results to GitHub.**
- This package has been checked for Python syntax and CLI help output; **live proxy performance has not been verified**.

For full instructions, examples and limitations, use the documentation links above or read [SECURITY.md](SECURITY.md).

---

<div align="center">

Made by **[mobin12a1](https://github.com/mobin12a1)** · Source version: `1.0.0`

*No license file is included. Reuse permissions have not been granted by an open-source license.*

</div>
