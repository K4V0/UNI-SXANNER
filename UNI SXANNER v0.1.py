#porgramed by KAYLID(NiGGaCoder)



import socket
import pyfiglet
A = '\033[1;34m'  # ازرق
B = '\033[1;31m'  # احمر
C = '\033[1;32m'  # اخضر
D = '\033[1;33m'  # اصفر

logo = pyfiglet.figlet_format('UNI  SXANNER')
print(B + logo)
print(('\033[92m—'*12)+'\n BY @KAYLID\n'+('—'*12))


# you can put any port you want to scan it but actually i put the most common ports

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
    2053: "(tcp/udp)",
    2083: "(tcp/udp)",
    2086: "(tcp/udp)",
    2087: "(tcp/udp)",
    2095:"(tcp/udp)",
    2096:"(tcp/udp)",
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
    21_000: "VNC (Virtual Network Computing)",
    10000: "Webmin",
    12345: "NetBus",
    31337: "Back Orifice",
    6660: "IRC (Internet Relay Chat)",
    6661: "IRC (Internet Relay Chat)",
    6662: "IRC (Internet Relay Chat)",
    6663: "IRC (Internet Relay Chat)",
    6664: "IRC (Internet Relay Chat)",
    6665: "IRC (Internet Relay Chat)",
    6666: "IRC (Internet Relay Chat)",
    1080: "SOCKS Proxy",
    1521: "Oracle DB",
    2121: "FTP Alternate",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    7000: "AOL Instant Messenger",
    8000: "HTTP Alternate",
    9000: "HTTP Alternate",
    10000: "Webmin",
}

def scan_port(target, port):
    try:
       
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1) 
        
     
        result = sock.connect_ex((target, port))
        
        if result == 0:
            print(f"Port {port} is open on {target}      ✓")
        else:
            print(f"Port {port} is close on {target}")
        
        sock.close()
    except socket.error as e:
        print(f"Ereor: {e}")

def scan_ports(target):
    print(f"Scanning ports on {target} ...")
    for port in common_ports:
        scan_port(target, port)

if __name__ == "__main__":
    target = input("Enter the target domain or IP: ")
    scan_ports(target)
