import os
import platform
import subprocess
import socket
import ipaddress
import psutil
import webbrowser
from time import sleep

def get_interfaces_ipv4():
    interfaces = psutil.net_if_addrs()
    ipv4s = {}
    for iface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ipv4s[iface] = addr.address
    return ipv4s

def scan_network(ip_base):
    print(f"\n📡 Escaneando rede {ip_base}.0/24...")
    active_hosts = []
    for i in range(1, 255):
        ip = f"{ip_base}.{i}"
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        result = subprocess.run(['ping', param, '1', ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if 'TTL=' in result.stdout or 'ttl=' in result.stdout:
            print(f"[+] Dispositivo ativo: {ip}")
            active_hosts.append(ip)
    return active_hosts

def try_open_hosts(hosts):
    print("\n🌐 Tentando abrir os IPs ativos no navegador...")
    for ip in hosts:
        url = f"http://{ip}"
        print(f"Tentando abrir {url}")
        webbrowser.open(url)
        sleep(1.5)

def main():
    print("🔎 Buscando interfaces de rede com IPv4...")
    interfaces = get_interfaces_ipv4()

    for iface, ip in interfaces.items():
        if ip.startswith('127.'):
            continue
        print(f"\n🔌 Interface detectada: {iface} com IP: {ip}")
        try:
            ip_net = ipaddress.IPv4Interface(ip + '/24')
            base_ip = str(ip_net.network.network_address).rsplit('.', 1)[0]
            active_hosts = scan_network(base_ip)
            if active_hosts:
                try_open_hosts(active_hosts)
            else:
                print("❌ Nenhum dispositivo ativo encontrado.")
        except Exception as e:
            print(f"Erro ao escanear: {e}")

if __name__ == "__main__":
    main()
