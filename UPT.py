#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    Ultimate Proxy Tester v1.0.0                              ║
║                         Enterprise Edition                                   ║
║                                                                              ║
║                Production‑Grade Async Proxy Scanner                          ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  Features:                                                                   ║
║    • Dual‑stage pipeline: handshake + verification                           ║
║    • HTTP/HTTPS and SOCKS4/5 support (No Auto Detect)                       ║
║    • Clean verbose output: [+] proxy  type  OK(code)  ping  | country, city ║
║    • Only essential errors shown (no debug logs)                            ║
║    • Proxy input: press Enter 3 times to finish                             ║
║    • GeoIP location mapping (optional) – works for IPs and domains          ║
║    • IPv6 compatible                                                         ║
║    • Streaming result writer to disk (no duplicate writes)                  ║
║                                                                              ║
║  Compatible with Windows, macOS, Linux, and Termux.                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

import asyncio
import json
import sys
import os
import re
import socket
import random
import time
import tempfile
import shutil
import platform
import base64
import urllib.request
import argparse
import math
import signal
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Tuple, Optional, Any
from urllib.parse import quote, unquote, urlparse


# ============================================================================
#   OPTIONAL UVLOOP
# ============================================================================

try:
    import uvloop  # type: ignore
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except (ImportError, RuntimeError, NotImplementedError):
    pass


# ============================================================================
#   SYSTEM TUNING
# ============================================================================

def setup_ulimit():
    """Increase file descriptor limit on Unix systems."""
    if platform.system() == "Windows":
        return
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = hard if hard != resource.RLIM_INFINITY else 65535
        if target > soft:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


setup_ulimit()


# ============================================================================
#   ENABLE ANSI ON WINDOWS
# ============================================================================

try:
    sys.stdout.reconfigure(errors='backslashreplace')
except (AttributeError, ValueError):
    pass

IS_TTY = sys.stdout.isatty()
USE_CONTROL = IS_TTY and os.environ.get('TERM') != 'dumb'
USE_COLOR = USE_CONTROL and os.environ.get('NO_COLOR') is None
if os.name == 'nt' and USE_COLOR:
    os.system('')  # Enable ANSI escape sequences in Windows consoles


# ============================================================================
#   DEPENDENCY CHECK
# ============================================================================

HAS_AIOHTTP = False
HAS_GEOIP = False

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    aiohttp = None

try:
    import geoip2.database
    HAS_GEOIP = True
except ImportError:
    pass


# ============================================================================
#   GEOIP MANAGER
# ============================================================================

GEOIP_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "GeoLite2-City.mmdb")
GEOIP_DB_URL = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb"


class GeoIPManager:
    """Lazy-loading GeoIP lookup manager."""

    def __init__(self):
        self._reader = None
        self._loaded = False

    def load(self) -> bool:
        """Load the GeoIP database from disk."""
        if self._loaded:
            return True
        if not HAS_GEOIP:
            return False
        if not os.path.exists(GEOIP_DB_PATH):
            return False
        try:
            import geoip2.database
            self._reader = geoip2.database.Reader(GEOIP_DB_PATH)
            self._loaded = True
            return True
        except Exception:
            return False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def get_location(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get location data for a given IP address."""
        if not self._loaded or not self._reader:
            return None
        try:
            response = self._reader.city(ip)
            return {
                "country": response.country.name,
                "country_code": response.country.iso_code,
                "city": response.city.name,
                "region": response.subdivisions.most_specific.name if response.subdivisions else None,
                "latitude": response.location.latitude,
                "longitude": response.location.longitude,
                "timezone": response.location.time_zone,
            }
        except Exception:
            return None


geoip = GeoIPManager()


# ============================================================================
#   TERMINAL & UI (ANSI Colors)
# ============================================================================

RESET = "\033[0m" if USE_COLOR else ""
BOLD = "\033[1m" if USE_COLOR else ""
DIM = "\033[2m" if USE_COLOR else ""
CYAN = "\033[96m" if USE_COLOR else ""
GREEN = "\033[92m" if USE_COLOR else ""
YELLOW = "\033[93m" if USE_COLOR else ""
RED = "\033[91m" if USE_COLOR else ""
WHITE = "\033[97m" if USE_COLOR else ""


def get_terminal_width() -> int:
    return shutil.get_terminal_size(fallback=(72, 24)).columns


def generate_banner(width: int = 72) -> str:
    """Render a compact banner that fits narrow mobile terminals."""
    width = max(10, min(width, 80))
    title = "Ultimate Proxy Tester" if width >= 23 else "UPT"
    subtitle = "HTTP  |  SOCKS4  |  SOCKS5"
    rule = "=" * width
    lines = [f"{CYAN}{rule}{RESET}", f"{BOLD}{title.center(width)}{RESET}"]
    if width >= len(subtitle):
        lines.append(f"{DIM}{subtitle.center(width)}{RESET}")
    lines.append(f"{CYAN}{rule}{RESET}")
    return "\n".join(lines)


# ============================================================================
#   CONFIGURATION & DATA TYPES
# ============================================================================

DEFAULT_CONNECT_TIMEOUT = 2.0
DEFAULT_READ_TIMEOUT = 3.0
VERIFY_TIMEOUT = 5.0
WAIT_CLOSED_TIMEOUT = 0.5
MAX_RESULTS_MEMORY = 50000
DEFAULT_MAX_CONCURRENT = 500

VERIFY_ENDPOINTS = [
    "https://api.ipify.org?format=json",
    "https://icanhazip.com",
    "https://ifconfig.me/ip",
    "https://ipinfo.io/ip",
]


class ProxyType(Enum):
    """Enumeration of proxy types and their authentication status."""
    DEAD = 0
    HTTP_NO_AUTH = 1
    HTTP_AUTH = 2
    SOCKS4_NO_AUTH = 3
    SOCKS4_AUTH = 4
    SOCKS5_NO_AUTH = 5
    SOCKS5_AUTH = 6


@dataclass
class ProxyEntry:
    """Represents a single proxy entry."""
    protocol: Optional[str]
    host: str
    port: int
    username: str
    password: str

    def to_queue_tuple(self):
        return (self.host, self.port, self.username, self.password, self.protocol)


@dataclass
class HandshakeResult:
    """Result of the handshake stage, including resolved IP for GeoIP."""
    entry: ProxyEntry
    proxy_type: ProxyType
    latency_ms: float
    status_code: int
    success: bool
    resolved_ip: Optional[str] = None  # Resolved IP for GeoIP (domain -> IP)


# ============================================================================
#   LOGGER (Async, Non-blocking UI)
# ============================================================================

@dataclass
class LogEvent:
    """Internal log event structure."""
    level: str
    message: str
    proxy: Optional[Dict] = None
    traceback: Optional[str] = None
    verbose_data: Optional[Dict] = None


class Logger:
    """
    Asynchronous logger with non-blocking queue.
    Supports verbose output with clean formatting.
    """

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.queue = asyncio.Queue()
        self._task = None
        self._last_line = ""
        self._processed = 0

    async def start(self):
        self._task = asyncio.create_task(self._consumer())

    async def stop(self):
        await self.queue.put(None)
        if self._task:
            await self._task

    def set_total(self, total: int):
        self._total = total

    async def info(self, msg: str):
        await self.queue.put(LogEvent("INFO", msg))

    async def progress(self, msg: str):
        if USE_CONTROL:
            await self.queue.put(LogEvent("PROGRESS", msg))

    async def result(self, msg: str, proxy: Dict = None):
        await self.queue.put(LogEvent("RESULT", msg, proxy))

    async def verbose_line(
        self,
        ip: str,
        port: int,
        ptype: str,
        status: str,
        code: int,
        handshake_ms: float,
        verify_ms: Optional[float],
        total_ms: float,
        loc: Optional[Dict] = None
    ):
        """Queue a verbose line for display."""
        if not self.verbose:
            return
        data = {
            "ip": ip,
            "port": port,
            "ptype": ptype,
            "status": status,
            "code": code,
            "handshake_ms": handshake_ms,
            "verify_ms": verify_ms,
            "total_ms": total_ms,
            "loc": loc
        }
        await self.queue.put(LogEvent("VERBOSE", "", verbose_data=data))

    async def error(self, msg: str, exc: Optional[Exception] = None):
        tb = traceback.format_exc() if exc else None
        await self.queue.put(LogEvent("ERROR", msg, traceback=tb))

    async def debug(self, msg: str, exc: Optional[Exception] = None):
        pass  # Completely disabled to keep output clean

    async def warning(self, msg: str):
        await self.queue.put(LogEvent("INFO", f"{YELLOW}Warning: {msg}{RESET}"))

    def _print_line(self, line: str):
        if USE_CONTROL and self._last_line:
            sys.stdout.write("\r\033[K")
        sys.stdout.write(line + "\n")
        if USE_CONTROL and self._last_line:
            sys.stdout.write(self._last_line)
        sys.stdout.flush()

    async def _consumer(self):
        """Consume log events and write to stdout."""
        while True:
            event = await self.queue.get()
            if event is None:
                if USE_CONTROL and self._last_line:
                    sys.stdout.write("\r\033[K")
                    sys.stdout.flush()
                break

            if event.level == "VERBOSE" and self.verbose:
                data = event.verbose_data
                ip = data["ip"]
                port = data["port"]
                ptype = data["ptype"]
                status = data["status"]
                code = data["code"]
                total_ms = data["total_ms"]
                loc = data["loc"]

                # Determine prefix: [+] for success, [-] for failure
                if status == "OK":
                    prefix = f"{GREEN}[+]{RESET}"
                elif status == "AUTH":
                    prefix = f"{YELLOW}[!]{RESET}"
                else:
                    prefix = f"{RED}[-]{RESET}"

                # Build status string with code
                if code > 0:
                    status_str = f"{status}({code})"
                else:
                    status_str = f"{status}"

                # Build location string
                loc_str = ""
                if loc and loc.get('country'):
                    loc_str = f" | {loc['country']}"
                    if loc.get('city'):
                        loc_str += f", {loc['city']}"

                if get_terminal_width() < 65:
                    line = f"{prefix} {ip}:{port}\n    {ptype}  {status_str}  {total_ms:.1f}ms{loc_str}"
                else:
                    line = f"{prefix} {ip}:{port}   {ptype:<10}   {status_str}   {total_ms:.1f}ms{loc_str}"
                self._print_line(line)

            elif event.level == "RESULT":
                if not self.verbose:
                    status = event.proxy.get("status") if event.proxy else "UNKNOWN"
                    loc = event.proxy.get("location") if event.proxy else None
                    loc_str = f" | {loc.get('country', 'N/A')} | {loc.get('city', 'N/A')}" if loc else ""

                    if status == "OK":
                        status_display = f"{GREEN}OK{RESET}"
                    elif status == "AUTH":
                        status_display = f"{YELLOW}AUTH{RESET}"
                    elif status == "TIMEOUT":
                        status_display = f"{YELLOW}TIMEOUT{RESET}"
                    else:
                        status_display = f"{RED}FAILED{RESET}"

                    if get_terminal_width() < 65 and event.proxy:
                        proxy = event.proxy
                        line = (f"[{status_display}] {proxy['ip']}:{proxy['port']}\n"
                                f"    {proxy['type']}  {proxy['total_ms']:.1f}ms{loc_str}")
                    else:
                        line = f"[{status_display}] {event.message}{loc_str}"
                    self._print_line(line)

            elif event.level == "ERROR":
                message = f"{RED}ERROR:{RESET} {event.message}"
                if event.traceback and self.verbose:
                    message += f"\n{event.traceback}"
                self._print_line(message)

            elif event.level == "PROGRESS":
                self._last_line = event.message
                sys.stdout.write(f"\r\033[K{event.message}")
                sys.stdout.flush()

            else:
                self._print_line(event.message)


# ============================================================================
#   ROBUST PARSER
# ============================================================================

def parse_proxy_line(line: str) -> Optional[ProxyEntry]:
    """
    Parse a single proxy line from various formats.
    Supported formats:
      - host:port
      - user:pass@host:port
      - protocol://host:port
      - protocol://user:pass@host:port
      - host:port:user:pass
    """
    line = re.sub(r'^[•\-*>\s]+', '', line.strip())
    if not line:
        return None

    protocol = "http"
    if '://' in line:
        protocol, line = line.split('://', 1)
        protocol = protocol.lower()
        if protocol not in ("http", "https", "socks4", "socks4a", "socks5"):
            return None

    username = password = ""
    if '@' in line:
        auth_part, line = line.rsplit('@', 1)
        username, _, password = auth_part.partition(':')
        username, password = unquote(username), unquote(password)

    if line.startswith('['):
        match = re.fullmatch(r'\[([^\]]+)\]:(\d+)(?::([^:]*):([^:]*))?', line)
        if not match or not is_ipv6(match.group(1)):
            return None
        host, port_str, trailing_user, trailing_password = match.groups()
        if trailing_user is not None:
            if username:
                return None
            username, password = trailing_user, trailing_password
    else:
        parts = line.split(':')
        if len(parts) >= 3 and is_ipv6(':'.join(parts[:-1])):
            host, port_str = ':'.join(parts[:-1]), parts[-1]
        elif len(parts) == 4 and parts[1].isdigit() and not username:
            host, port_str, username, password = parts
        elif len(parts) == 4 and parts[3].isdigit() and not username:
            username, password, host, port_str = parts
        elif len(parts) == 3 and parts[1].isdigit() and not username:
            host, port_str, username = parts
        elif len(parts) == 2:
            host, port_str = parts
        else:
            return None

    if not host or not port_str.isdigit():
        return None
    port = int(port_str)
    if not 1 <= port <= 65535:
        return None
    return ProxyEntry(protocol, host, port, username, password)


def parse_input_data(text: str) -> List[ProxyEntry]:
    """Parse raw input text into a list of unique ProxyEntry objects."""
    entries = []
    seen = set()
    for line in text.split('\n'):
        line = line.strip()
        if not line:
            continue
        for part in line.split(','):
            part = part.strip()
            if not part:
                continue
            entry = parse_proxy_line(part)
            if entry:
                key = (entry.protocol, entry.host, entry.port, entry.username, entry.password)
                if key not in seen:
                    seen.add(key)
                    entries.append(entry)
    return entries


# ============================================================================
#   HELPER: IPv4/IPv6 Detection
# ============================================================================

def is_ipv6(host: str) -> bool:
    try:
        socket.inet_pton(socket.AF_INET6, host)
        return True
    except Exception:
        return False


def is_ipv4(host: str) -> bool:
    try:
        socket.inet_aton(host)
        return True
    except Exception:
        return False


# ============================================================================
#   DNS CACHE (Async)
# ============================================================================

_dns_cache: Dict[str, Tuple[str, int]] = {}
_dns_cache_lock = asyncio.Lock()


async def resolve_host(host: str, family_hint: int = socket.AF_UNSPEC) -> Tuple[str, Optional[int]]:
    """
    Async DNS resolution with caching.
    On failure, returns (host, None) to allow caller to handle gracefully.
    """
    cache_key = f"{host}_{family_hint}"

    async with _dns_cache_lock:
        if cache_key in _dns_cache:
            return _dns_cache[cache_key]

    try:
        loop = asyncio.get_running_loop()
        addrs = await loop.getaddrinfo(host, None, family=family_hint, type=socket.SOCK_STREAM)
        for addr in addrs:
            family, _, _, _, sockaddr = addr
            if family in (socket.AF_INET, socket.AF_INET6):
                ip = sockaddr[0]
                async with _dns_cache_lock:
                    _dns_cache[cache_key] = (ip, family)
                return ip, family
        raise socket.gaierror(f"Could not resolve {host}")
    except Exception as e:
        # Do not cache the host as IP; return (host, None) and let caller handle
        async with _dns_cache_lock:
            _dns_cache[cache_key] = (host, None)  # Store marker to avoid retries
        return host, None


# ============================================================================
#   NETWORK HANDSHAKES (Raw Sockets)
# ============================================================================

async def safe_close(writer):
    """Safely close a socket writer with a timeout to prevent resource leaks."""
    if not writer:
        return
    try:
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=WAIT_CLOSED_TIMEOUT)
        except AttributeError:
            pass
    except Exception:
        pass


async def open_connection_with_resolved(
    host: str,
    port: int,
    timeout: float
) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter, Optional[str]]:
    """
    Open a connection and return (reader, writer, resolved_ip).
    Handles both IPv4 and IPv6.
    """
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, happy_eyeballs_delay=0.25),
        timeout=timeout
    )
    peer = writer.get_extra_info("peername")
    resolved_ip = peer[0] if peer else None
    return reader, writer, resolved_ip


async def open_connection(host: str, port: int, timeout: float) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Convenience wrapper that ignores the resolved IP."""
    reader, writer, _ = await open_connection_with_resolved(host, port, timeout)
    return reader, writer


async def _http_handshake(
    entry: ProxyEntry,
    conn_to: float,
    read_to: float,
    logger: Optional[Logger] = None
) -> Tuple[bool, float, int]:
    """Perform a raw HTTP handshake to test the proxy."""
    endpoint = random.choice(["http://httpbin.org/ip", "http://httpbingo.org/ip"])
    reader, writer = None, None
    try:
        reader, writer = await open_connection(entry.host, entry.port, conn_to)

        auth_header = ""
        if entry.username:
            auth_header = (
                f"Proxy-Authorization: Basic "
                f"{base64.b64encode(f'{entry.username}:{entry.password}'.encode()).decode()}\r\n"
            )

        parsed = urlparse(endpoint)
        req = (
            f"GET {endpoint} HTTP/1.1\r\n"
            f"Host: {parsed.netloc}\r\n"
            f"{auth_header}"
            f"User-Agent: UPT/1.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()

        loop = asyncio.get_running_loop()
        start = loop.time()
        writer.write(req)
        await writer.drain()

        first_line = b""
        deadline = loop.time() + read_to
        while loop.time() < deadline:
            try:
                remaining = max(0.001, deadline - loop.time())
                data = await asyncio.wait_for(reader.readline(), timeout=remaining)
                if not data:
                    break
                first_line += data
                if data.endswith(b"\r\n"):
                    break
            except asyncio.TimeoutError:
                break

        end = loop.time()
        if not first_line:
            return False, float('inf'), 0

        parts = first_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
            success = 200 <= status_code < 400 or status_code == 407
            return success, (end - start) * 1000.0, status_code

        return False, float('inf'), 0
    except Exception:
        return False, float('inf'), 0
    finally:
        await safe_close(writer)


async def _socks4_handshake(
    entry: ProxyEntry,
    conn_to: float,
    read_to: float,
    logger: Optional[Logger] = None
) -> Tuple[bool, float, int]:
    """Perform a SOCKS4 handshake (supports SOCKS4a for domain names)."""
    reader, writer = None, None
    try:
        reader, writer = await open_connection(entry.host, entry.port, conn_to)
        loop = asyncio.get_running_loop()
        start = loop.time()

        payload = (
            b'\x04\x01' +
            (80).to_bytes(2, 'big') +
            socket.inet_aton("1.1.1.1") +
            (entry.username.encode() if entry.username else b'') +
            b'\x00'
        )

        writer.write(payload)
        await writer.drain()

        data = await asyncio.wait_for(reader.readexactly(8), timeout=read_to)
        if len(data) >= 2 and data[1] == 0x5a:
            latency = (loop.time() - start) * 1000.0
            return True, latency, 0

        return False, float('inf'), 0
    except Exception:
        return False, float('inf'), 0
    finally:
        await safe_close(writer)


async def _socks5_handshake(
    entry: ProxyEntry,
    conn_to: float,
    read_to: float,
    logger: Optional[Logger] = None
) -> Tuple[bool, float, int]:
    """Perform a SOCKS5 handshake with username/password authentication if provided."""
    target_ip, target_port = (1, 1, 1, 1), 80
    reader, writer = None, None
    try:
        reader, writer = await open_connection(entry.host, entry.port, conn_to)
        loop = asyncio.get_running_loop()
        start = loop.time()

        # Method negotiation
        if entry.username:
            writer.write(b'\x05\x02\x00\x02')
        else:
            writer.write(b'\x05\x01\x00')
        await writer.drain()

        method_data = await asyncio.wait_for(reader.readexactly(2), timeout=read_to)
        if method_data[0] != 0x05:
            return False, float('inf'), 0

        method = method_data[1]
        if entry.username and method == 0x02:
            user_bytes = entry.username.encode()
            password_bytes = entry.password.encode()
            if len(user_bytes) > 255 or len(password_bytes) > 255:
                return False, float('inf'), 0
            auth_packet = (
                b'\x01' +
                bytes([len(user_bytes)]) +
                user_bytes +
                bytes([len(password_bytes)]) +
                password_bytes
            )
            writer.write(auth_packet)
            await writer.drain()
            auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=read_to)
            if auth_resp[1] != 0x00:
                return False, float('inf'), 0
        elif method != 0x00:
            return False, float('inf'), 0

        # Connect request
        writer.write(bytes([0x05, 0x01, 0x00, 0x01, *target_ip, (target_port >> 8) & 0xFF, target_port & 0xFF]))
        await writer.drain()

        header = await asyncio.wait_for(reader.readexactly(4), timeout=read_to)
        if header[0] != 0x05 or header[1] != 0x00 or header[2] != 0x00 or header[3] not in (1, 3, 4):
            return False, float('inf'), 0

        addr_len = 4 if header[3] == 0x01 else 16 if header[3] == 0x04 else (
            await asyncio.wait_for(reader.readexactly(1), timeout=read_to)
        )[0] if header[3] == 0x03 else 0

        if addr_len:
            await asyncio.wait_for(reader.readexactly(addr_len), timeout=read_to)
        await asyncio.wait_for(reader.readexactly(2), timeout=read_to)

        latency = (loop.time() - start) * 1000.0
        return True, latency, 0
    except Exception:
        return False, float('inf'), 0
    finally:
        await safe_close(writer)


# ============================================================================
#   VERIFICATION VIA RAW SOCKETS (for SOCKS)
# ============================================================================

async def _verify_socks_proxy(
    entry: ProxyEntry,
    ptype: ProxyType,
    timeout: float,
    logger: Optional[Logger] = None
) -> Tuple[bool, float, int]:
    """
    Verify a SOCKS proxy by sending an HTTP request through it using raw sockets.
    Uses root path "/" to get a valid 200 OK response from icanhazip.com.
    """
    target_host = "icanhazip.com"
    target_port = 80

    reader, writer = None, None
    try:
        reader, writer = await open_connection(entry.host, entry.port, timeout)
        loop = asyncio.get_running_loop()
        start = loop.time()

        # Perform SOCKS handshake again
        if ptype in (ProxyType.SOCKS4_NO_AUTH, ProxyType.SOCKS4_AUTH):
            target_ip, family = await resolve_host(target_host, family_hint=socket.AF_INET)

            if family == socket.AF_INET:
                payload = (
                    b'\x04\x01' +
                    target_port.to_bytes(2, 'big') +
                    socket.inet_aton(target_ip) +
                    (entry.username.encode() if entry.username else b'') +
                    b'\x00'
                )
            else:
                payload = (
                    b'\x04\x01' +
                    target_port.to_bytes(2, 'big') +
                    b'\x00\x00\x00\x01' +
                    (entry.username.encode() if entry.username else b'') +
                    b'\x00' +
                    target_host.encode() +
                    b'\x00'
                )

            writer.write(payload)
            await writer.drain()
            resp = await asyncio.wait_for(reader.readexactly(8), timeout=timeout)
            if resp[1] != 0x5a:
                return False, float('inf'), 0

        elif ptype in (ProxyType.SOCKS5_NO_AUTH, ProxyType.SOCKS5_AUTH):
            writer.write(b'\x05\x02\x00\x02' if entry.username else b'\x05\x01\x00')
            await writer.drain()
            method_data = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
            if method_data[0] != 0x05:
                return False, float('inf'), 0

            method = method_data[1]
            if entry.username and method == 0x02:
                user_bytes = entry.username.encode()
                password_bytes = entry.password.encode()
                if len(user_bytes) > 255 or len(password_bytes) > 255:
                    return False, float('inf'), 0
                auth_packet = (
                    b'\x01' +
                    bytes([len(user_bytes)]) +
                    user_bytes +
                    bytes([len(password_bytes)]) +
                    password_bytes
                )
                writer.write(auth_packet)
                await writer.drain()
                auth_resp = await asyncio.wait_for(reader.readexactly(2), timeout=timeout)
                if auth_resp[1] != 0x00:
                    return False, float('inf'), 0
            elif method != 0x00:
                return False, float('inf'), 0

            target_bytes = target_host.encode('ascii')
            writer.write(bytes([0x05, 0x01, 0x00, 0x03, len(target_bytes)]) + target_bytes + target_port.to_bytes(2, 'big'))
            await writer.drain()

            header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
            if header[0] != 0x05 or header[1] != 0x00 or header[2] != 0x00 or header[3] not in (1, 3, 4):
                return False, float('inf'), 0

            addr_len = 4 if header[3] == 0x01 else 16 if header[3] == 0x04 else (
                await asyncio.wait_for(reader.readexactly(1), timeout=timeout)
            )[0] if header[3] == 0x03 else 0

            if addr_len:
                await asyncio.wait_for(reader.readexactly(addr_len), timeout=timeout)
            await asyncio.wait_for(reader.readexactly(2), timeout=timeout)

        # Send HTTP GET request to root path
        http_request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {target_host}\r\n"
            f"User-Agent: UPT/1.0\r\n"
            f"Connection: close\r\n\r\n"
        ).encode()
        writer.write(http_request)
        await writer.drain()

        # Read response until we have HTTP status line
        first_line = b""
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            remaining = max(0.001, deadline - loop.time())
            data = await asyncio.wait_for(reader.readline(), timeout=remaining)
            if not data:
                break
            first_line += data
            if data.endswith(b"\r\n"):
                break

        if not first_line:
            return False, float('inf'), 0

        parts = first_line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
            success = 200 <= status_code < 400
            latency = (loop.time() - start) * 1000.0
            return success, latency, status_code

        return False, float('inf'), 0
    except Exception:
        return False, float('inf'), 0
    finally:
        await safe_close(writer)


# ============================================================================
#   STAGE 1: HANDSHAKE WORKERS
# ============================================================================

async def handshake_worker(
    queue: asyncio.Queue,
    output_queue: asyncio.Queue,
    selected_type: str,
    conn_to: float,
    read_to: float,
    sem: asyncio.Semaphore,
    logger: Logger,
    progress: 'ProgressCounter'
):
    """Worker that performs the handshake and pushes results to the next stage."""
    while True:
        try:
            item = await queue.get()
        except asyncio.CancelledError:
            raise
        if item is None:
            queue.task_done()
            break

        host, port, username, password, protocol = item
        entry = ProxyEntry(protocol=protocol, host=host, port=port, username=username, password=password)

        async with sem:
            try:
                # Build order of handshake attempts based on selected_type
                order = []
                if selected_type == 'http':
                    order = [(_http_handshake, ProxyType.HTTP_NO_AUTH if not entry.username else ProxyType.HTTP_AUTH)]
                else:  # socks
                    order = [
                        (_socks5_handshake, ProxyType.SOCKS5_NO_AUTH if not entry.username else ProxyType.SOCKS5_AUTH),
                        (_socks4_handshake, ProxyType.SOCKS4_NO_AUTH if not entry.username else ProxyType.SOCKS4_AUTH),
                    ]
                    if entry.protocol and "socks4" in entry.protocol:
                        order = [
                            (_socks4_handshake, ProxyType.SOCKS4_NO_AUTH if not entry.username else ProxyType.SOCKS4_AUTH),
                            (_socks5_handshake, ProxyType.SOCKS5_NO_AUTH if not entry.username else ProxyType.SOCKS5_AUTH),
                        ]

                success, ptype, lat, status = False, ProxyType.DEAD, float('inf'), 0
                for func, pt in order:
                    ok, l, st = await func(entry, conn_to, read_to, logger)
                    if ok:
                        success, ptype, lat, status = True, pt, l, st
                        break

                if success:
                    resolved_ip = None
                    if geoip.is_loaded and not (is_ipv4(host) or is_ipv6(host)):
                        resolved_ip, _ = await resolve_host(host)
                        if resolved_ip == host:
                            resolved_ip = None
                    hresult = HandshakeResult(
                        entry=entry,
                        proxy_type=ptype,
                        latency_ms=lat,
                        status_code=status,
                        success=True,
                        resolved_ip=resolved_ip
                    )
                    await output_queue.put(hresult)

            except asyncio.CancelledError:
                raise
            except Exception as e:
                await logger.error(f"Handshake error {entry.host}:{entry.port} - {type(e).__name__}", e)
            finally:
                queue.task_done()
                progress.increment()


# ============================================================================
#   STAGE 2: VERIFICATION WORKERS
# ============================================================================

async def verify_proxy(
    entry: ProxyEntry,
    ptype: ProxyType,
    http_session: Any,
    logger: Logger
) -> Tuple[bool, float, int]:
    """Verify the proxy using HTTP or SOCKS verification as appropriate."""
    try:
        if "HTTP" in ptype.name:
            credentials = f"{quote(entry.username, safe='')}:{quote(entry.password, safe='')}@" if entry.username else ""
            proxy_host = f"[{entry.host}]" if is_ipv6(entry.host) else entry.host
            proxy_url = f"http://{credentials}{proxy_host}:{entry.port}"
            endpoints = VERIFY_ENDPOINTS.copy()
            random.shuffle(endpoints)
            last_status = 0
            last_latency = float('inf')

            for ep in endpoints[:2]:
                try:
                    start = asyncio.get_running_loop().time()
                    async with http_session.get(
                        ep,
                        proxy=proxy_url,
                        timeout=aiohttp.ClientTimeout(total=VERIFY_TIMEOUT)
                    ) as resp:
                        latency = (asyncio.get_running_loop().time() - start) * 1000.0
                        if 200 <= resp.status < 400:
                            return True, latency, resp.status
                        if resp.status == 407:
                            return False, latency, 407
                        last_status, last_latency = resp.status, latency
                except Exception as exc:
                    if getattr(exc, 'status', None) == 407:
                        latency = (asyncio.get_running_loop().time() - start) * 1000.0
                        return False, latency, 407
                    continue
            return False, last_latency, last_status
        else:
            return await _verify_socks_proxy(entry, ptype, VERIFY_TIMEOUT, logger)
    except Exception:
        return False, float('inf'), 0


async def verify_worker(
    input_queue: asyncio.Queue,
    results_queue: asyncio.Queue,
    http_session: Any,
    sem: asyncio.Semaphore,
    logger: Logger
):
    """Worker that verifies proxies and pushes results to the writer."""
    while True:
        try:
            item = await input_queue.get()
        except asyncio.CancelledError:
            raise
        if item is None:
            input_queue.task_done()
            break

        hresult: HandshakeResult = item
        entry = hresult.entry

        async with sem:
            try:
                if hresult.status_code == 407:
                    v_ok, v_lat, v_status = False, float('inf'), 407
                else:
                    v_ok, v_lat, v_status = await verify_proxy(entry, hresult.proxy_type, http_session, logger)

                total_lat = hresult.latency_ms + (v_lat if math.isfinite(v_lat) else 0)

                if v_status == 407:
                    status_label = "AUTH"
                elif v_ok:
                    status_label = "OK"
                else:
                    status_label = "FAILED"

                # Use resolved IP for GeoIP if available (domain handling)
                ip_for_geo = hresult.resolved_ip if hresult.resolved_ip else entry.host
                loc = None
                if geoip.is_loaded:
                    loc = geoip.get_location(ip_for_geo)

                entry_dict = {
                    "type": hresult.proxy_type.name,
                    "ip": entry.host,
                    "port": entry.port,
                    "handshake_ms": round(hresult.latency_ms, 2),
                    "verify_ms": round(v_lat, 2) if math.isfinite(v_lat) else None,
                    "total_ms": round(total_lat, 2),
                    "status_code": v_status,
                    "status": status_label
                }
                if loc:
                    entry_dict["location"] = loc

                await results_queue.put(entry_dict)

                await logger.result(
                    f"{entry.host}:{entry.port}  {hresult.proxy_type.name}  {total_lat:.1f}ms",
                    entry_dict
                )

                await logger.verbose_line(
                    ip=entry.host,
                    port=entry.port,
                    ptype=hresult.proxy_type.name,
                    status=status_label,
                    code=v_status,
                    handshake_ms=hresult.latency_ms,
                    verify_ms=v_lat if math.isfinite(v_lat) else None,
                    total_ms=total_lat,
                    loc=loc
                )

            except asyncio.CancelledError:
                raise
            except Exception as e:
                await logger.error(f"Verify loop fail for {entry.host}:{entry.port}", e)
            finally:
                input_queue.task_done()


# ============================================================================
#   PROGRESS TRACKING & FILE IO
# ============================================================================

class ProgressCounter:
    """Simple thread-safe progress counter (lock-free because asyncio is single-threaded)."""
    def __init__(self):
        self._value = 0

    def increment(self):
        self._value += 1

    def get(self) -> int:
        return self._value


async def progress_reporter(total: int, progress: ProgressCounter, logger: Logger):
    """Periodically report scan progress."""
    while True:
        done = progress.get()
        if done >= total:
            break
        pct = (done / total * 100) if total else 0
        bar_width = max(5, min(20, get_terminal_width() - 28))
        filled = int(bar_width * done / total) if total else 0
        bar = '#' * filled + '-' * (bar_width - filled)
        await logger.progress(f"Progress [{bar}] {done}/{total} {pct:.0f}%")
        await asyncio.sleep(0.5)


async def result_writer(
    results_queue: asyncio.Queue,
    txt_path: str,
    json_path: str,
    stop_event: asyncio.Event
):
    """
    Streaming result writer that writes results incrementally to disk.
    Handles None sentinel gracefully with task_done.
    """
    txt_handle = None
    json_handle = None
    json_first = True
    written = 0

    try:
        txt_handle = open(txt_path, 'w', encoding='utf-8')
        json_handle = open(json_path, 'w', encoding='utf-8')
        json_handle.write('[')

        while not stop_event.is_set() or not results_queue.empty():
            try:
                item = await asyncio.wait_for(results_queue.get(), timeout=0.5)
            except asyncio.TimeoutError:
                continue

            if item is None:
                results_queue.task_done()
                break

            loc = item.get("location")
            loc_str = f" | {loc['country']} | {loc['city']}" if loc else ""
            status_with_code = f"{item['status']} ({item['status_code']})"

            # Write to TXT
            txt_handle.write(
                f"{item['type']} | {item['ip']}:{item['port']} | "
                f"{item['total_ms']}ms | {status_with_code}{loc_str}\n"
            )

            # Write to JSON
            if not json_first:
                json_handle.write(',')
            json_first = False
            json.dump(item, json_handle, ensure_ascii=True)

            txt_handle.flush()
            json_handle.flush()
            written += 1
            results_queue.task_done()

    except Exception as e:
        raise RuntimeError(f"Result writer error: {e}") from e
    finally:
        if txt_handle:
            txt_handle.close()
        if json_handle:
            json_handle.write(']\n')
            json_handle.close()
    return written


# ============================================================================
#   USER INPUT (Synchronous)
# ============================================================================

def get_user_inputs():
    """Collect all user inputs synchronously before starting the async event loop."""
    def choose(prompt, allowed, default=None):
        while True:
            value = input(prompt).strip().lower()
            if not value and default is not None:
                return default
            if value in allowed:
                return value
            print(f"Choose {' or '.join(allowed)}.")

    def positive_number(prompt, default, converter):
        while True:
            value = input(prompt).strip() or str(default)
            try:
                number = converter(value)
                if number > 0 and (not isinstance(number, float) or math.isfinite(number)):
                    return number
            except ValueError:
                pass
            print("Enter a number greater than zero.")

    print(generate_banner(get_terminal_width()))

    if not HAS_GEOIP:
        print("GeoIP unavailable (optional: pip install geoip2).")
    elif geoip.load():
        print("GeoIP database loaded.")
    else:
        print("GeoIP database not found; location disabled.")

    print("\nProxy type\n  1. HTTP / HTTPS\n  2. SOCKS4 / SOCKS5")
    mode_choice = choose("Select [1]: ", ("1", "2"), "1")

    if mode_choice == "1":
        selected_type = "http"
    else:
        selected_type = "socks"

    print(f"Selected: {selected_type.upper()}")

    print("\nProxy list\n  1. Paste entries\n  2. Read from file")
    input_choice = choose("Select [1]: ", ("1", "2"), "1")
    entries = []

    if input_choice == "2":
        path = input("File path: ").strip()
        try:
            with open(path, 'r', encoding='utf-8') as f:
                entries = parse_input_data(f.read())
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    else:
        print("Paste proxies, one per line. Press Enter on three empty lines to finish.")
        lines = []
        empty_count = 0
        while True:
            line = input()
            if not line.strip():
                empty_count += 1
                if empty_count >= 3:
                    break
                continue
            else:
                empty_count = 0
                lines.append(line)
        entries = parse_input_data("\n".join(lines))

    if not entries:
        print("No valid proxies extracted.")
        sys.exit(1)

    print(f"Loaded {len(entries)} unique proxies.")

    conn_to = positive_number("\nConnect timeout [2.0s]: ", 2.0, float)
    read_to = positive_number("Read timeout [3.0s]: ", 3.0, float)
    hw = positive_number("Handshake workers [100]: ", 100, int)
    vw = positive_number("Verify workers [30]: ", 30, int)
    default_verify = "y"
    if selected_type == "http" and not HAS_AIOHTTP:
        print("aiohttp is not installed; HTTP verification needs it.")
        default_verify = "n"
    verify_hint = "Y/n" if default_verify == "y" else "y/N"
    verify = choose(f"Verify with an HTTP request? [{verify_hint}]: ", ("y", "n"), default_verify) == "y"
    verbose = choose("Show each scan result? [y/N]: ", ("y", "n"), "n") == "y"
    max_conn = positive_number(f"Max concurrent connections [{DEFAULT_MAX_CONCURRENT}]: ", DEFAULT_MAX_CONCURRENT, int)

    return selected_type, entries, conn_to, read_to, hw, vw, verify, verbose, max_conn


# ============================================================================
#   MAIN ASYNC FUNCTION
# ============================================================================

async def main(
    selected_type: str,
    entries: List[ProxyEntry],
    conn_to: float,
    read_to: float,
    hw: int,
    vw: int,
    verify: bool,
    verbose: bool,
    max_conn: int
):
    """Main async pipeline – coordinates all workers and stages."""
    if not entries:
        raise ValueError("No valid proxies to scan")
    if not math.isfinite(conn_to) or not math.isfinite(read_to) or conn_to <= 0 or read_to <= 0 or hw <= 0 or vw <= 0 or max_conn <= 0:
        raise ValueError("Timeouts and worker/connection counts must be greater than zero")
    if verify and selected_type == "http" and not HAS_AIOHTTP:
        raise RuntimeError("HTTP verification requires aiohttp: pip install 'aiohttp>=3.10.0'")

    loop = asyncio.get_running_loop()
    loop.set_default_executor(ThreadPoolExecutor(max_workers=min(32, max_conn)))

    logger = Logger(verbose=verbose)
    logger.set_total(len(entries))
    await logger.start()

    sem = asyncio.Semaphore(max_conn)

    input_queue = asyncio.Queue(maxsize=hw * 3)
    handshake_output = asyncio.Queue(maxsize=hw * 2)
    results_queue = asyncio.Queue()

    progress = ProgressCounter()

    # Start handshake workers
    handshake_tasks = [
        asyncio.create_task(
            handshake_worker(
                input_queue, handshake_output, selected_type, conn_to, read_to,
                sem, logger, progress
            )
        )
        for _ in range(hw)
    ]

    # Start verification workers (or drain workers if verification disabled)
    http_session = None
    verify_tasks = []

    if verify:
        if HAS_AIOHTTP and selected_type == "http":
            http_session = aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=VERIFY_TIMEOUT),
                connector=aiohttp.TCPConnector(
                    limit=hw * 2,
                    limit_per_host=hw,
                    ttl_dns_cache=300,
                    enable_cleanup_closed=True
                )
            )
        verify_tasks = [
            asyncio.create_task(
                verify_worker(handshake_output, results_queue, http_session, sem, logger)
            )
            for _ in range(vw)
        ]
    else:
        drain_count = max(1, vw) if vw > 0 else 1

        async def drain_worker():
            while True:
                item = await handshake_output.get()
                if item is None:
                    handshake_output.task_done()
                    break

                hres: HandshakeResult = item
                ip_for_geo = hres.resolved_ip if hres.resolved_ip else hres.entry.host
                loc = None
                if geoip.is_loaded:
                    loc = geoip.get_location(ip_for_geo)

                entry_dict = {
                    "type": hres.proxy_type.name,
                    "ip": hres.entry.host,
                    "port": hres.entry.port,
                    "handshake_ms": round(hres.latency_ms, 2),
                    "verify_ms": None,
                    "total_ms": round(hres.latency_ms, 2),
                    "status_code": hres.status_code,
                    "status": "AUTH" if hres.status_code == 407 else "OK" if hres.status_code == 0 or 200 <= hres.status_code < 400 else "BAD"
                }
                if loc:
                    entry_dict["location"] = loc

                await results_queue.put(entry_dict)

                await logger.result(
                    f"{hres.entry.host}:{hres.entry.port}  {hres.proxy_type.name}  {hres.latency_ms:.1f}ms",
                    entry_dict
                )

                await logger.verbose_line(
                    ip=hres.entry.host,
                    port=hres.entry.port,
                    ptype=hres.proxy_type.name,
                    status=entry_dict["status"],
                    code=hres.status_code,
                    handshake_ms=hres.latency_ms,
                    verify_ms=None,
                    total_ms=hres.latency_ms,
                    loc=loc
                )
                handshake_output.task_done()

        verify_tasks = [asyncio.create_task(drain_worker()) for _ in range(drain_count)]

    reporter = asyncio.create_task(progress_reporter(len(entries), progress, logger))

    # Start the streaming result writer
    stop_event = asyncio.Event()
    writer_task = asyncio.create_task(
        result_writer(results_queue, "result.txt", "result.json", stop_event)
    )

    # Signal handling for graceful shutdown
    main_task = asyncio.current_task()

    def signal_handler():
        main_task.cancel()

    try:
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)
    except (NotImplementedError, RuntimeError):
        pass  # Windows may not support signal handlers

    interrupted = False
    saved_count = 0
    try:
        # Keep the writer active while the bounded input queue is filled.
        for entry in entries:
            await input_queue.put(entry.to_queue_tuple())

        # Wait for all handshakes to complete
        await input_queue.join()
        for _ in range(hw):
            await input_queue.put(None)
        await asyncio.gather(*handshake_tasks)

        # Wait for all verifications to complete
        for _ in range(len(verify_tasks)):
            await handshake_output.put(None)
        await asyncio.gather(*verify_tasks)

        # Cancel progress reporter
        reporter.cancel()
        try:
            await reporter
        except asyncio.CancelledError:
            pass

        # Signal writer to finish
        stop_event.set()
        await results_queue.put(None)
        saved_count = await writer_task

    except asyncio.CancelledError:
        interrupted = True
        await logger.info("Scan interrupted; saving completed results...")
        for task in handshake_tasks + verify_tasks:
            if not task.done():
                task.cancel()
        if handshake_tasks + verify_tasks:
            await asyncio.gather(*handshake_tasks, *verify_tasks, return_exceptions=True)

        stop_event.set()
        if not writer_task.done():
            await results_queue.put(None)
        saved_count = await writer_task

    except Exception as e:
        await logger.error(f"Runtime execution interrupted: {e}")
        for task in handshake_tasks + verify_tasks:
            if not task.done():
                task.cancel()
        if handshake_tasks + verify_tasks:
            await asyncio.gather(*handshake_tasks, *verify_tasks, return_exceptions=True)

        stop_event.set()
        if not writer_task.done():
            await results_queue.put(None)
            await writer_task
        raise

    finally:
        if not reporter.done():
            reporter.cancel()
            await asyncio.gather(reporter, return_exceptions=True)
        if http_session:
            await http_session.close()
        await logger.stop()

    print("\n" + "=" * min(get_terminal_width(), 60))
    print(f"Scan {'interrupted' if interrupted else 'finished'}. Input proxies: {len(entries)}")
    print(f"Saved results: {saved_count}")
    print("Results: result.txt and result.json")


# ============================================================================
#   ENTRYPOINT
# ============================================================================

def parse_args():
    def positive_float(value):
        try:
            number = float(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("must be a positive number") from exc
        if not math.isfinite(number) or number <= 0:
            raise argparse.ArgumentTypeError("must be a positive number")
        return number

    def positive_int(value):
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("must be a positive integer") from exc
        if number <= 0:
            raise argparse.ArgumentTypeError("must be a positive integer")
        return number

    parser = argparse.ArgumentParser(description="Ultimate Proxy Tester v1.0.0 Enterprise Edition")
    parser.add_argument("--type", choices=["http", "socks"], default="http", help="Proxy type to test")
    parser.add_argument("--file", help="File containing proxies (one per line)")
    parser.add_argument("--proxies", help="Comma-separated list of proxies")
    parser.add_argument("--connect-timeout", type=positive_float, default=DEFAULT_CONNECT_TIMEOUT, help="Connection timeout in seconds")
    parser.add_argument("--read-timeout", type=positive_float, default=DEFAULT_READ_TIMEOUT, help="Read timeout in seconds")
    parser.add_argument("--handshake-workers", type=positive_int, default=100, help="Number of handshake workers")
    parser.add_argument("--verify-workers", type=positive_int, default=30, help="Number of verification workers")
    parser.add_argument("--no-verify", action="store_true", help="Skip HTTP verification")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--max-conn", type=positive_int, default=DEFAULT_MAX_CONCURRENT, help="Max concurrent connections")
    return parser.parse_args()


def get_inputs_from_args(args):
    entries = []
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                entries = parse_input_data(f.read())
        except Exception as e:
            print(f"Error reading file: {e}")
            sys.exit(1)
    elif args.proxies:
        entries = parse_input_data(args.proxies)
    else:
        return get_user_inputs()

    if not entries:
        print("No valid proxies extracted.")
        sys.exit(1)

    print(f"Loaded {len(entries)} proxies from arguments.")
    return (
        args.type,
        entries,
        args.connect_timeout,
        args.read_timeout,
        args.handshake_workers,
        args.verify_workers,
        not args.no_verify,
        args.verbose,
        args.max_conn
    )


if __name__ == "__main__":
    args = parse_args()

    # Download GeoIP database if missing
    if HAS_GEOIP and not os.path.exists(GEOIP_DB_PATH) and not (args.file or args.proxies):
        print("GeoIP database not found.")
        if input("   Download now? (y/n): ").strip().lower() == 'y':
            tmp_path = None
            try:
                with tempfile.NamedTemporaryFile(
                    dir=os.path.dirname(GEOIP_DB_PATH), prefix='.geolite-', suffix='.tmp', delete=False
                ) as tmp:
                    tmp_path = tmp.name
                    with urllib.request.urlopen(GEOIP_DB_URL, timeout=30) as resp:
                        shutil.copyfileobj(resp, tmp, length=1024 * 1024)
                os.replace(tmp_path, GEOIP_DB_PATH)
                print("Download completed.")
            except Exception as e:
                print(f"Download failed: {e}")
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass

    if HAS_GEOIP:
        geoip.load()

    try:
        if args.file or args.proxies:
            selected_type, entries, conn_to, read_to, hw, vw, verify, verbose, max_conn = get_inputs_from_args(args)
        else:
            selected_type, entries, conn_to, read_to, hw, vw, verify, verbose, max_conn = get_user_inputs()
    except KeyboardInterrupt:
        print("\nInput cancelled.")
        sys.exit(0)
    except (ValueError, argparse.ArgumentTypeError) as exc:
        print(f"Invalid input: {exc}")
        sys.exit(2)

    try:
        asyncio.run(
            main(selected_type, entries, conn_to, read_to, hw, vw, verify, verbose, max_conn)
        )
    except KeyboardInterrupt:
        print("\nExecution terminated by user.")
        sys.exit(0)
    except (ValueError, RuntimeError) as exc:
        print(f"Error: {exc}")
        sys.exit(2)
