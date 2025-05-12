#Developed By KAYLID(NiGGaCoder)

import socket
import pyfiglet
import threading
import time
import os
import sys
from datetime import datetime

# الالوان
BLUE = '\033[1;34m'
RED = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
PURPLE = '\033[1;35m'
CYAN = '\033[1;36m'
WHITE = '\033[1;37m'
RESET = '\033[0m'


def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# انميشن (ذكاء اصطناعي)
def progress_bar(duration, prefix=''):
    bar_length = 30
    for i in range(bar_length + 1):
        percent = i * 100.0 / bar_length
        bar = '█' * i + '░' * (bar_length - i)
        sys.stdout.write(f'\r{prefix} [{bar}] {percent:.1f}%')
        sys.stdout.flush()
        time.sleep(duration / bar_length)
    print()

# البورتات 
common_ports = {
    20: "FTP Data",
    21: "FTP Command",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    443: "HTTPS",
    445: "Microsoft-DS",
    514: "Syslog",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    1433: "Microsoft SQL Server",
    1521: "Oracle DB",
    1701: "L2TP",
    1723: "PPTP",
    2049: "NFS",
    2053: "DNS (TLS)",
    2083: "cPanel",
    2086: "WHM",
    2087: "cPanel Admin",
    2095: "Webmail",
    2096: "Webmail SSL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8008: "HTTP Alt",
    8080: "HTTP Proxy",
    8443: "HTTPS Alt",
    8888: "HTTP Alt",
    9898: "RDP Alternate",
    27017: "MongoDB",
    50000: "SAP Router",
    49152: "Dynamic Ports (Linux)",
    49153: "Dynamic Ports (Linux)",
    49154: "Dynamic Ports (Linux)",
    49155: "Dynamic Ports (Linux)",
    10000: "Webmin",
    12345: "NetBus",
    31337: "Back Orifice",
    6660: "IRC",
    6661: "IRC",
    6662: "IRC",
    6663: "IRC",
    6664: "IRC",
    6665: "IRC",
    6666: "IRC",
    1080: "SOCKS Proxy",
    2121: "FTP Alternate",
    6379: "Redis",
    7000: "AOL Instant Messenger",
    8000: "HTTP Alternate",
    9000: "HTTP Alternate",
}


open_ports = []
lock = threading.Lock()
scan_complete = False
timeout_value = 0.2

#وضع الدومين
def get_ip_from_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"{RED}Error: Could not resolve the domain name.{RESET}")
        return None

def scan_port(target, port, result_callback=None):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_value)
        result = sock.connect_ex((target, port))
        
        port_name = common_ports.get(port, f"Unknown")
        
        if result == 0:
            with lock:
                open_ports.append((port, port_name))
                if result_callback:
                    result_callback(port, port_name, True)
                else:
                    print(f"{GREEN}[✓] Port {port} ({port_name}) is OPEN on {target}{RESET}")
        elif result_callback:
            result_callback(port, port_name, False)
        sock.close()
    except socket.error:
        pass

def display_result(port, port_name, is_open):
    if is_open:
        print(f"{GREEN}[✓] Port {port} ({port_name}) is OPEN{RESET}")
    else:
        print(f"{RED}[✗] Port {port} ({port_name}) is CLOSED{RESET}")

def scan_with_threads(target, ports, thread_count=50, show_closed=True):
    global scan_complete
    scan_complete = False
    
    target_ip = get_ip_from_domain(target) if not target.replace('.', '').isdigit() else target
    if not target_ip:
        return
    
    print(f"{YELLOW}Starting scan on {target} ({target_ip}) with timeout {timeout_value}s{RESET}")
    
    start_time = time.time()
    

    threads = []
    for port in ports:
        callback = display_result if show_closed else None
        t = threading.Thread(target=scan_port, args=(target_ip, port, callback))
        threads.append(t)
    

    batch_size = thread_count
    for i in range(0, len(threads), batch_size):
        batch = threads[i:i + batch_size]
        for t in batch:
            t.start()
        for t in batch:
            t.join()
        
     
        progress = min(100, (i + batch_size) * 100 / len(threads))
        sys.stdout.write(f"\r{BLUE}Progress: [{('█' * int(progress // 5)).ljust(20, '░')}] {progress:.1f}%{RESET}")
        sys.stdout.flush()
    
    print("\n")
    duration = time.time() - start_time
    
    scan_complete = True
    return duration

def display_results(target, duration):
    print(f"\n{CYAN}{'=' * 50}{RESET}")
    print(f"{YELLOW}Scan completed in {duration:.2f} seconds{RESET}")
    print(f"{CYAN}{'=' * 50}{RESET}")
    
    if open_ports:
        print(f"\n{GREEN}Open ports on {target}:{RESET}")
        print(f"{CYAN}{'=' * 50}{RESET}")
        for port, name in sorted(open_ports):
            print(f"{GREEN}[✓] Port {port}: {name}{RESET}")
        
        save_option = input(f"\n{YELLOW}Save open ports to a file? (y/n): {RESET}").strip().lower()
        if save_option == 'y':
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"open_ports_{target}_{timestamp}.txt"
            
            with open(filename, "w") as file:
                file.write(f"PORT SCAN RESULTS FOR: {target}\n")
                file.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                file.write(f"Total Open Ports: {len(open_ports)}\n")
                file.write("-" * 50 + "\n\n")
                
                for port, name in sorted(open_ports):
                    file.write(f"Port {port}: {name}\n")
            
            print(f"{GREEN}Results saved to {filename}{RESET}")
    else:
        print(f"{RED}No open ports found on {target}.{RESET}")

#الشعار
def show_banner():
    clear_screen()
    banner = pyfiglet.figlet_format('UNI SXANNER v0.2', font='slant')
    print(f"{PURPLE}{banner}{RESET}")
    print(f"{BLUE}{'=' * 50}{RESET}")
    print(f"{GREEN}  Developed By @KAYLID{RESET}")
    print(f"{BLUE}{'=' * 50}{RESET}")
    print()
#القائمة
def show_menu():
    print(f"\n{YELLOW}Select scanning mode:{RESET}")
    print(f"{CYAN}1. Quick Scan (Common ports){RESET}")
    print(f"{CYAN}2. Full Scan (All ports 1-20000){RESET}")
    print(f"{CYAN}3. Custom Port Range{RESET}")
    print(f"{CYAN}4. Set timeout value (current: {timeout_value}s){RESET}")
    print(f"{CYAN}5. Exit{RESET}")
    
    choice = input(f"\n{YELLOW}Enter your choice (1-5): {RESET}")
    return choice

def main():
    global timeout_value
    show_banner()
    
    while True:
        target = input(f"{YELLOW}Enter the target domain or IP: {RESET}")
        if not target:
            print(f"{RED}Error: Target cannot be empty.{RESET}")
            continue
        #عرض القوائم
        choice = show_menu()
        
        if choice == '1':
            # فحص سريع للبورتات 
            ports_to_scan = list(common_ports.keys())
            progress_bar(1, prefix=f"{BLUE}Preparing scan...")
            duration = scan_with_threads(target, ports_to_scan, show_closed=False)
            if duration:
                display_results(target, duration)
        
        elif choice == '2':
            # فحص بورتات من 1 الى 20000
            ports_to_scan = range(1, 20001)
            show_closed = input(f"{YELLOW}Show closed ports? (y/n): {RESET}").strip().lower() == 'y'
            progress_bar(1, prefix=f"{BLUE}Preparing scan...")
            duration = scan_with_threads(target, ports_to_scan, show_closed=show_closed)
            if duration:
                display_results(target, duration)
        
        elif choice == '3':
            # بورتات يحددها المستخدم
            try:
                start_port = int(input(f"{YELLOW}Enter start port: {RESET}"))
                end_port = int(input(f"{YELLOW}Enter end port: {RESET}"))
                
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    print(f"{RED}Invalid port range. Ports must be between 1-65535.{RESET}")
                    continue
                    
                ports_to_scan = range(start_port, end_port + 1)
                show_closed = input(f"{YELLOW}Show closed ports? (y/n): {RESET}").strip().lower() == 'y'
                progress_bar(1, prefix=f"{BLUE}Preparing scan...")
                duration = scan_with_threads(target, ports_to_scan, show_closed=show_closed)
                if duration:
                    display_results(target, duration)
            
            except ValueError:
                print(f"{RED}Invalid input. Please enter numeric values for ports.{RESET}")
        
        elif choice == '4':
            # من الذكاء الاصطناعي
            try:
                new_timeout = float(input(f"{YELLOW}Enter new timeout value in seconds (0.1-5.0): {RESET}"))
                if 0.1 <= new_timeout <= 5.0:
                    timeout_value = new_timeout
                    print(f"{GREEN}Timeout value set to {timeout_value}s{RESET}")
                else:
                    print(f"{RED}Invalid timeout value. Using default.{RESET}")
            except ValueError:
                print(f"{RED}Invalid input. Using default timeout.{RESET}")
        
        elif choice == '5':
            #خروج
            print(f"{GREEN}Thank you for using UNI SXANNER v0.2!{RESET}")
            break
        
        else:
            print(f"{RED}Invalid choice. Please try again.{RESET}")
        
        open_ports.clear()
        
        if choice in ['1', '2', '3']:
            input(f"\n{YELLOW}Press Enter to continue...{RESET}")
            show_banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{RED}Scan cancelled by user.{RESET}")
        if scan_complete:
            sys.exit(0)
        sys.exit(1)
