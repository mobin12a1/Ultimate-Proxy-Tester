<div align="center">

# 📘 Ultimate Proxy Tester — English Guide

**Complete installation, usage, configuration and troubleshooting documentation**

**[← Home](README.md) · English · [فارسی](README%5BFA%5D.md)**

</div>

---

## Contents

1. [Overview](#1-overview)
2. [Features](#2-features)
3. [Requirements and installation](#3-requirements-and-installation)
4. [Interactive mode](#4-interactive-mode)
5. [Command-line mode](#5-command-line-mode)
6. [Proxy input formats](#6-proxy-input-formats)
7. [How testing works](#7-how-testing-works)
8. [Results and status codes](#8-results-and-status-codes)
9. [Optional GeoIP support](#9-optional-geoip-support)
10. [Troubleshooting](#10-troubleshooting)
11. [Security and limitations](#11-security-and-limitations)
12. [Files and licensing](#12-files-and-licensing)

## 1. Overview

**Ultimate Proxy Tester (UPT)** is a Python CLI application that checks user-supplied proxy endpoints using asynchronous I/O. The program first attempts a protocol handshake and can then verify connectivity to an external IP-check service. It records results during the scan in `result.txt` and `result.json`.

This is a **tester, not a proxy finder**: you supply the endpoints. A successful result is specific to the tested handshake and verification destination; it cannot guarantee access to every website or service.

## 2. Features

| Capability | Behavior in the supplied source |
| :--- | :--- |
| HTTP mode | Performs an HTTP proxy handshake, then optionally sends HTTPS verification requests via `aiohttp` |
| SOCKS mode | Tries SOCKS5 and SOCKS4 handshakes (selected mode applies to the whole batch) |
| Two-stage check | Handshake followed by optional connectivity verification |
| Concurrent execution | Adjustable handshake workers, verification workers and global connection limit |
| Proxy authentication | Parses username/password credentials; behavior depends on the selected protocol |
| Network addressing | Accepts IPv4, domain names and supported IPv6 input formats |
| Optional location data | Country/city lookup using `geoip2` and a separate compatible MMDB file |
| Results | Writes `.txt` and `.json` files incrementally |
| UI | Interactive prompts, progress and optional verbose per-proxy logging |

**Important:** The input parser recognizes `http://`, `https://`, `socks4://`, `socks4a://` and `socks5://` scheme prefixes, but **a scheme prefix does not automatically select the actual scan mode**. The raw HTTP handshake code does not establish TLS to an HTTPS proxy endpoint. Do not interpret scheme parsing as verified support for TLS-encrypted proxy connections.

## 3. Requirements and installation

- Python **3.10 or later recommended**. Actual runtime behavior may depend on your operating system and Python build.
- Network access to the proxies and any external verification service.
- `aiohttp` for the HTTP second-stage verification.
- Optional: `geoip2` plus a compatible GeoLite2 City MMDB file for geography.

Download or clone the project. If publishing it to a GitHub repository, users can download its **Code → Download ZIP** archive and extract it. Open a terminal in the extracted project directory.

**Windows (PowerShell or Command Prompt):**

```powershell
py -m pip install -r requirements.txt
py UPT.py
```

**Linux, macOS or Termux:**

```bash
python3 -m pip install -r requirements.txt
python3 UPT.py
```

If `python3` is not available on Termux, install Python with `pkg install python`. For installations where Python is already named `python`, use that command instead.

> `requirements.txt` contains the `aiohttp` dependency. Optional GeoIP support can be installed separately.

## 4. Interactive mode

Run without specifying an input list:

```bash
python UPT.py
```

The program asks you to:

1. Select **HTTP / HTTPS** or **SOCKS4 / SOCKS5** testing mode.
2. Choose between pasting endpoint addresses and loading a file.
3. If pasting, enter one or more endpoints per line; **press Enter on three empty lines** to finish.
4. Choose connection timeout, read timeout, handshake and verification worker counts, whether to verify, verbose output and maximum concurrent connections.
5. Wait for the scan to finish or interrupt it to save completed results.

Use moderate concurrency on unstable networks. Higher worker settings do not always mean faster or more reliable results.

## 5. Command-line mode

Use `--file` to read a plaintext endpoint list:

```bash
python UPT.py --type http --file proxies.txt
```

Check SOCKS proxies and print per-proxy details:

```bash
python UPT.py --type socks --file proxies.txt --verbose
```

Skip connectivity verification (handshake-only results):

```bash
python UPT.py --type http --file proxies.txt --no-verify
```

Tune resource use:

```bash
python UPT.py --type socks --file proxies.txt --connect-timeout 3 --read-timeout 5 --handshake-workers 50 --verify-workers 20 --max-conn 100
```

List all options:

```bash
python UPT.py --help
```

### CLI options

| Option | Default | Meaning |
| :--- | :--- | :--- |
| `--type` | `http` | `http` or `socks` scan mode |
| `--file` | — | Read proxies from a file |
| `--proxies` | — | Read comma-separated proxies directly from CLI |
| `--connect-timeout` | `2.0` | Connection timeout in seconds |
| `--read-timeout` | `3.0` | Handshake read timeout in seconds |
| `--handshake-workers` | `100` | Number of handshake worker tasks |
| `--verify-workers` | `30` | Number of verification worker tasks |
| `--no-verify` | off | Disable second-stage verification |
| `--verbose` | off | Print detailed per-proxy results |
| `--max-conn` | `500` | Upper bound for concurrent stage operations |

All provided timeout and worker-count values must be positive. **Verification has additional fixed internal timeouts**; `--read-timeout` does not control every verification request.

> **Credential warning:** `--proxies` can expose secrets in shell history or process information. Prefer a protected local input file for authenticated proxies.

## 6. Proxy input formats

The parser accepts the following formats:

```text
host:port
user:pass@host:port
http://host:port
http://user:pass@host:port
socks5://host:port
host:port:user:pass
[2001:db8::1]:1080
```

Examples below use reserved documentation addresses and **are not working proxies**:

```text
192.0.2.10:8080
http://198.51.100.20:3128
socks5://203.0.113.10:1080
```

- Choose the **HTTP** or **SOCKS** mode intentionally; the `--type` flag is not automatic protocol detection.
- Keep HTTP and SOCKS entries in separate batches for predictable results.
- Domain names and bracketed IPv6 literals may be used if accepted by the parser and reachable from your environment.
- Use one endpoint per line, or comma-separate endpoints. Entries are deduplicated by protocol, host, port and credentials.
- Never publish lists that contain real credentials.

## 7. How testing works

```text
Your proxy list
    |
    v
Parse and deduplicate
    |
    v
Stage 1: protocol handshake
    |
    +---- failed  --> not saved as a success result
    |
    v
Stage 2: optional verification
    |
    v
result.txt + result.json
```

### Stage 1 — handshake

The program opens a connection and sends the selected protocol's initial request. A successful handshake is **not necessarily proof of useful proxy forwarding**.

### Stage 2 — verification

When enabled, the program uses an external IP-check endpoint. The HTTP path uses `aiohttp` and HTTPS verification destinations. The SOCKS path uses raw socket requests with an **HTTP** destination. These destinations can change availability or block repeated checks.

**A failed verification may reflect a blocked test destination, not necessarily a universally unusable proxy.** Conversely, success at one destination is not a guarantee for other sites.

### Latency

The program reports measured handshake, verification and total elapsed times. These are **probe timings**, not a benchmark of throughput, anonymity or download speed.

## 8. Results and status codes

The program writes results to your **current working directory**:

| File | Contents |
| :--- | :--- |
| `result.txt` | Human-readable line per recorded proxy result |
| `result.json` | Structured array with protocol type, host, port, timings, status and optional location |

Possible labels include:

- `OK`: successful stage or verification, depending on whether verification is enabled.
- `FAILED`: a proxy passed the handshake but did not pass second-stage verification.
- `AUTH`: a response indicated that authentication is required or failed, where detectable.

Some entries that fail the **first handshake** are not written to the result files. A scan of 100 addresses may therefore produce fewer than 100 recorded results. The tool may overwrite existing `result.txt` and `result.json` on a new run; save a copy first if needed.

## 9. Optional GeoIP support

Install the optional dependency:

```bash
python -m pip install -r requirements-geoip.txt
```

Place a compatible City database named `GeoLite2-City.mmdb` next to `UPT.py`. In interactive mode, if `geoip2` is installed and the database is missing, the script can offer to download a database from a third-party GitHub location.

- GeoIP is approximate, not a reliable indicator of physical server location.
- The database is not bundled with this repository.
- Check the database provider's provenance, update policy and licensing before using or redistributing it.

## 10. Troubleshooting

| Symptom | What to check |
| :--- | :--- |
| `ModuleNotFoundError: aiohttp` | Run `python -m pip install -r requirements.txt` using the same Python interpreter as the script. |
| `HTTP verification requires aiohttp` | Install `aiohttp`, or use `--no-verify` for handshake-only checks. |
| `No valid proxies extracted` | Verify address syntax, allowed ports and `--file` location. |
| All results fail | Verify protocol mode, credentials, destination filtering, timeouts and network access. |
| No GeoIP details | Install `geoip2` and provide the City MMDB database. |
| Nothing appears in the results | Failed handshakes are not written as successful entries; check the live terminal output and input syntax. |
| Output files are missing | Check the terminal's current working directory and file-write permissions. |

To see command-line help:

```bash
python UPT.py --help
```

## 11. Security and limitations

- **Authorization:** test only endpoints you control or have permission to assess.
- **Privacy:** local input files, shell history and result files can expose addresses and credentials.
- **Transport:** some probes use plaintext HTTP. This application is **not** an end-to-end encrypted proxy verifier.
- **Third parties:** IP-check services receive verification requests and can observe the tested proxy's outgoing traffic.
- **Concurrency:** large worker counts can overload your device, network or endpoints. Respect service policies.
- **No anonymity guarantee:** successful status and GeoIP data do not prove anonymity, privacy or unrestricted connectivity.
- **Testing claim:** the code was syntax-checked and its `--help` command was exercised during packaging; a live proxy scan was **not** performed.

Read [SECURITY.md](SECURITY.md) before distributing logs or running large tests.

## 12. Files and licensing

| File | Purpose |
| :--- | :--- |
| `README.md` | GitHub landing page and language navigation |
| `README[EN].md` | This English guide |
| `README[FA].md` | Complete Persian guide |
| `UPT.py` | Program entry point and proxy scanning logic |
| `requirements.txt` | Required dependency for HTTP verification |
| `requirements-geoip.txt` | Optional location dependency |
| `proxies.example.txt` | Non-functional example input formats |
| `.gitignore` | Local input/output/database exclusions |
| `SECURITY.md` | Security and privacy notes |

**License:** no license file has been selected or included. Do not assume permissions granted by an open-source license.

---

<div align="center">

**[← Back to main README](README.md)** · **[خواندن راهنمای فارسی](README%5BFA%5D.md)**

Maintainer: [mobin12a1](https://github.com/mobin12a1) · Source version `1.0.0`

</div>
