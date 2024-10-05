from urllib.parse import urlparse
import threading
import argparse
import socket
import socks
import time
import ssl
import sys
import os

class Colors:
    RED = "\u001b[31;1m"
    GREEN = "\u001b[32;1m"
    YELLOW = "\u001b[33;1m"
    BLUE = "\u001b[34;1m"
    PURPLE = "\u001b[35;1m"
    CYAN = "\u001b[36;1m"
    RESET = "\u001b[0;0m"
    
class ScannerConfig:
    THREADS = 10
    TIMEOUT = 10
    MAX_RETRIES = 3
    PROXY_TYPE = None
    PROXY_HOST = None
    PROXY_PORT = None
    ACTIVE_THREADS = 0

BANNER = f"""{Colors.PURPLE}╦ ╦╔╦╗╔╦╗╔═╗╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
╠═╣ ║  ║ ╠═╝╚═╗│  ├─┤││││││├┤ ├┬┘
╩ ╩ ╩  ╩ ╩  ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─{Colors.RESET}"""

def scan_host(domain: str, port: int, use_ssl: bool = False, no_verify: bool = False, retries: int = 0):
    if (retries >= ScannerConfig.MAX_RETRIES):
        return
    
    def _retry(use_ssl: bool = False, no_verify: bool = False):
        return scan_host(domain=domain, port=port, use_ssl=use_ssl, no_verify=no_verify, retries=retries + 1)
    
    ScannerConfig.ACTIVE_THREADS += 1

    try:
        if all([ScannerConfig.PROXY_TYPE, ScannerConfig.PROXY_HOST, ScannerConfig.PROXY_PORT]):
            sock = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
            sock.set_proxy(proxy_type=ScannerConfig.PROXY_TYPE, addr=ScannerConfig.PROXY_HOST, port=ScannerConfig.PROXY_PORT)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.connect((domain, port))

        if use_ssl:
            ctx = ssl.create_default_context()
            if no_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.VerifyMode.CERT_NONE
                sock = ctx.wrap_socket(sock=sock)
            else:
                try:
                    sock = ctx.wrap_socket(sock=sock, server_hostname=domain)
                except Exception:
                    return _retry(use_ssl=True, no_verify=True)
                
        print(f"Connected to {Colors.BLUE}{domain}:{port}{Colors.RESET}")

        request_data = f"GET / HTTP/1.1\r\n"

        request_headers = {
            "Host": f"{domain}{f':{port}' if not port in [80, 443] else ''}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
        }

        for header in request_headers:
            header_name = header
            header_value = request_headers[header_name]
            request_data += f"{header_name}: {header_value}\r\n"
        
        request_data += "\r\n"
        
        sock.send(request_data.encode())

        response_headers = b""

        while True:
            chunk = sock.recv(1)

            if not chunk:
                return _retry(use_ssl=True)
            
            response_headers += chunk

            if response_headers.endswith(b"\r\n\r\n"):
                break
        
        response_display = ""
        max_console_column = 50
        cols = 0
        for v in str(response_headers):
            response_display += v

            cols += 1
            if cols == max_console_column:
                cols = 0
                response_display += "\n"

        print(f"Response from {Colors.BLUE}{domain}:{port}{Colors.RESET} SSL: {Colors.BLUE}{use_ssl}{Colors.RESET} SSL.CERT_NONE: {Colors.BLUE}{no_verify}{Colors.RESET}\n{response_display}")

    except Exception as e:
        return _retry()

    finally:
        ScannerConfig.ACTIVE_THREADS -= 1

def scan_domains(domains: list, ports: list):
    threads = ScannerConfig.THREADS

    socket.setdefaulttimeout(ScannerConfig.TIMEOUT)

    for port in ports:
        for domain in domains:
            while True:
                if ScannerConfig.ACTIVE_THREADS >= threads:
                    time.sleep(0.05)
                    continue

                threading.Thread(target=scan_host, args=[domain, port], daemon=True).start()
                break
    
    while True:
        if ScannerConfig.ACTIVE_THREADS > 0:
            time.sleep(0.05)
            continue

        break

def clear_console():
    if sys.platform == "win32":
        os.system("cls")
    elif sys.platform in ["linux", "linux2"]:
        os.system("clear")

def main():
    clear_console()

    print(BANNER)

    parser = argparse.ArgumentParser(description="A tool used for scanning HTTP servers in domain list files extracted from `subdomainfinder.c99.nl`, using `github@lilmond/http_scanner/subdomain_ip_extractor.py`.")
    parser.add_argument("-f", "--file", type=argparse.FileType("r"), metavar="<TXT FILE>", required=True, help="Path to domain list file.")
    parser.add_argument("-p", "--port", action="append", metavar="<INT>", default=[80, 443, 8080, 8443], help="Append port to scan.")
    parser.add_argument("-t", "--threads", type=int, metavar="<INT>", default=ScannerConfig.THREADS, help=f"This tool is multi-threaded by default, with the value set to {ScannerConfig.THREADS}.")
    parser.add_argument("-n", "--proxy", type=str, metavar="<PROXY URL>", help="Tell the scanner to use connect via a proxy when sending requests.")
    parser.add_argument("--timeout", type=int, metavar="<INT>", default=ScannerConfig.TIMEOUT, help=f"Socket connection timeout in seconds. The default is {ScannerConfig.TIMEOUT}.")
    parser.add_argument("--max-retries", type=int, metavar="<INT>", default=ScannerConfig.MAX_RETRIES, help=f"Maximum scan retries per domain. The default is {ScannerConfig.MAX_RETRIES}.")

    args = parser.parse_args()
    
    domains = [line.strip() for line in args.file.read().splitlines() if line.strip() and not line.strip().startswith("#")]
    
    if not domains:
        print(f"Error: Nothing to scan in this file: {args.file.name}")
        return
    
    ScannerConfig.THREADS = args.threads
    ScannerConfig.TIMEOUT = args.timeout
    ScannerConfig.MAX_RETRIES = args.max_retries

    if args.proxy:
        proxy_url = urlparse(args.proxy)

        if not proxy_url.port:
            print(f"Error: PROXY URL requires port. Example: socks5://127.0.0.1:9050")
            return

        try:
            proxy_type = getattr(socks, f"PROXY_TYPE_{proxy_url.scheme.upper()}")
        except AttributeError:
            print(f"Error: Invalid PROXY URL scheme: {proxy_url.scheme}://. Valid: [http://, socks4://, socks5://]")
            return
        
        ScannerConfig.PROXY_TYPE = proxy_type
        ScannerConfig.PROXY_HOST = proxy_url.hostname
        ScannerConfig.PROXY_PORT = proxy_url.port

    scan_domains(domains=domains, ports=args.port)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit()
