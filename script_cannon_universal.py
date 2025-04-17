import subprocess
import platform
import socket
import psutil
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

# Teste de ping
def ping_ip(ip):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(["ping", param, "1", ip],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL,
                                text=True,
                                timeout=1)
        return "TTL=" in result.stdout or "ttl=" in result.stdout
    except:
        return False

# Teste de portas comuns
def port_open(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=0.5):
            return True
    except:
        return False

# Busca IPs em uso na rede local
def scan_host(ip):
    result = {"ip": ip, "ping": False, "ports": []}
    if ping_ip(ip):
        result["ping"] = True

    for port in [80, 443, 22, 23, 161, 8080, 554]:
        if port_open(ip, port):
            result["ports"].append(port)

    if result["ping"] or result["ports"]:
        return result
    return None

# Detecta IP base da Ethernet
def get_possible_ranges():
    ranges = [
        "192.168.0", "192.168.1", "192.168.88",
        "192.168.100", "192.168.254", "10.0.0",
        "169.254.1", "169.254.0", "169.254.2"
    ]
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ip = addr.address
                ip_base = ".".join(ip.split(".")[:3])
                if ip_base not in ranges:
                    ranges.insert(0, ip_base)
    return ranges

# Scanner total com threads
def full_scan():
    ranges = get_possible_ranges()
    found = []

    for r in ranges:
        print(f"\n🔎 Escaneando faixa: {r}.1 a {r}.254...")
        ips = [f"{r}.{i}" for i in range(1, 255)]

        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = {executor.submit(scan_host, ip): ip for ip in ips}
            for future in as_completed(futures):
                res = future.result()
                if res:
                    found.append(res)
                    print(f"[+] Detectado: {res['ip']} | Ping: {res['ping']} | Portas: {res['ports']}")

    if not found:
        print("\n❌ Nada encontrado.")
    else:
        print("\n✅ Dispositivos encontrados:")
        for res in found:
            print(f"IP: {res['ip']} | Ping: {res['ping']} | Portas: {res['ports']}")

if __name__ == "__main__":
    full_scan()
