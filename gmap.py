
#!/usr/bin/env python3

import argparse
import requests
import ssl
import socket
import sys
import time
import threading
from urllib.parse import urlparse
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

VERSION = "1.1.0"
SITE = "https://gmap-org.netlify.app/"

def banner():
    print(Fore.CYAN + r"""
   ____ __  __    _    ____
  / ___|  \/  |  / \  |  _ \
 | |  _| |\/| | / _ \ | |_) |
 | |_| | |  | |/ ___ \|  __/
  \____|_|  |_/_/   \_\_|

       SECURITY SCANNER
    """ + Style.RESET_ALL)
    print(Fore.WHITE + f" Version: {VERSION}")
    print(Fore.BLUE + f" Official: {SITE}")
    print(Fore.CYAN + "-" * 48)

def scan_animation(stop_event, message):
    frames = ["|", "/", "-", "\\"]
    i = 0
    while not stop_event.is_set():
        print(
            f"\r{Fore.CYAN}[GMAP] {frames[i % len(frames)]} "
            f"{message}...",
            end="",
            flush=True
        )
        i += 1
        time.sleep(0.1)
    print("\r" + " " * 70 + "\r", end="")

def animated_check(message, function):
    stop_event = threading.Event()
    thread = threading.Thread(
        target=scan_animation,
        args=(stop_event, message),
        daemon=True
    )
    thread.start()
    try:
        return function()
    finally:
        stop_event.set()
        thread.join()

def main():
    parser = argparse.ArgumentParser(
        description="GMAP Security Scanner",
        epilog=f"Official website: {SITE}"
    )
    parser.add_argument("-v", action="version", version=VERSION)
    parser.add_argument("-u", metavar="URL", help="Authorized target URL")
    parser.add_argument("-H", action="store_true", help="Check HTTP headers")
    parser.add_argument("-s", action="store_true", help="Check HTTPS")
    parser.add_argument("-b", action="store_true", help="Basic checks")
    parser.add_argument("-d", action="store_true", help="Data exposure checks")
    parser.add_argument("-r", action="store_true", help="Generate report")
    parser.add_argument("-o", metavar="FILE", help="Save results")
    parser.add_argument("-t", type=int, default=5, help="Timeout in seconds")
    parser.add_argument("-z", action="store_true", help="Reserved")
    args = parser.parse_args()

    banner()

    if args.z:
        print(Fore.YELLOW + "[GMAP] This feature is reserved.")
        return

    if not args.u:
        parser.print_help()
        return

    if not 1 <= args.t <= 30:
        parser.error("Timeout must be between 1 and 30 seconds.")

    url = args.u.strip()
    if "://" not in url:
        url = "https://" + url

    parsed = urlparse(url)
    if (parsed.scheme not in ("http", "https")
            or not parsed.hostname
            or parsed.username or parsed.password):
        parser.error("Invalid URL.")

    if parsed.port and parsed.port not in (
        (443,) if parsed.scheme == "https" else (80,)
    ):
        parser.error("Only standard ports 80 and 443 are supported.")

    print(Fore.WHITE + f"\nTarget: {url}")
    print(Fore.YELLOW + "Only scan websites you own or are authorized to test.\n")

    results = []
    response = None

    try:
        response = animated_check(
            "Connecting to target",
            lambda: requests.get(
                url,
                timeout=args.t,
                allow_redirects=True,
                headers={"User-Agent": "GMAP-Security-Scanner/1.1"}
            )
        )
        print(Fore.GREEN + f"[OK] HTTP response: {response.status_code}")
        results.append(f"HTTP status: {response.status_code}")

    except requests.RequestException as error:
        print(Fore.RED + f"[ERROR] Connection failed: {error}")
        results.append(f"Connection failed: {error}")

    if response is not None and (args.H or args.b or not (args.s or args.d)):
        def check_headers():
            headers = response.headers
            checks = {
                "Strict-Transport-Security": "HSTS",
                "Content-Security-Policy": "CSP",
                "X-Content-Type-Options": "X-Content-Type-Options",
                "X-Frame-Options": "X-Frame-Options",
            }
            findings = []
            for key, label in checks.items():
                if key in headers:
                    findings.append((label, True))
                else:
                    findings.append((label, False))
            return findings

        findings = animated_check(
            "Analyzing security headers",
            check_headers
        )

        for label, present in findings:
            if present:
                line = f"[PRESENT] {label}"
                print(Fore.GREEN + line)
            else:
                line = f"[REVIEW] {label} header missing"
                print(Fore.YELLOW + line)
            results.append(line)

    if args.s:
        def check_tls():
            if parsed.scheme != "https":
                return False, "URL uses HTTP, not HTTPS"
            context = ssl.create_default_context()
            with socket.create_connection(
                (parsed.hostname, 443), timeout=args.t
            ) as sock:
                with context.wrap_socket(
                    sock, server_hostname=parsed.hostname
                ) as secure_sock:
                    secure_sock.getpeercert()
            return True, "TLS certificate validated"

        try:
            ok, message = animated_check("Checking HTTPS certificate", check_tls)
            color = Fore.GREEN if ok else Fore.RED
            print(color + f"[{'OK' if ok else 'REVIEW'}] {message}")
            results.append(message)
        except Exception as error:
            print(Fore.RED + f"[ERROR] HTTPS check failed: {error}")
            results.append(f"HTTPS check failed: {error}")

    if args.d:
        animated_check("Reviewing exposure-check module", lambda: time.sleep(0.5))
        print(Fore.YELLOW + "[INFO] Active sensitive-file checks are not implemented yet.")
        results.append("Sensitive-file detection not implemented.")

    if args.r or args.o:
        filename = args.o or "gmap-report.txt"
        with open(filename, "w", encoding="utf-8") as file:
            file.write("GMAP SECURITY REPORT\n")
            file.write(f"Date: {datetime.now().isoformat()}\n")
            file.write(f"Official website: {SITE}\n")
            file.write(f"Target: {url}\n\n")
            file.write("\n".join(results))
        print(Fore.GREEN + f"\n[GMAP] Report saved: {filename}")

    print(Fore.CYAN + "\n[GMAP] Scan finished.")

if __name__ == "__main__":
    main()

