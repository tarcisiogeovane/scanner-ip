import platform
import subprocess
import webbrowser
import psutil
from time import sleep

def get_ipv4_ethernet():
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == 2 and not addr.address.startswith("127."):
                if "Ethernet" in iface or "eth" in iface.lower():
                    return addr.address
    return None

def scan_range(ip_base):
    print(f"\n🔍 Escaneando faixa: {ip_base}.1 a {ip_base}.254")
    active_hosts = []
    for i in range(1, 255):
        ip = f"{ip_base}.{i}"
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(["ping", param, "1", ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if "TTL=" in result.stdout or "ttl=" in result.stdout:
            print(f"[+] Dispositivo ativo encontrado: {ip}")
            active_hosts.append(ip)
    return active_hosts

def try_open_hosts(hosts):
    for ip in hosts:
        url = f"http://{ip}"
        print(f"🌐 Abrindo no navegador: {url}")
        webbrowser.open(url)
        sleep(2)

def main():
    faixa_comum = [
        "192.168.0",
        "192.168.1",
        "192.168.88",
        "192.168.100",
        "192.168.254",
        "10.0.0",
        "169.254.1",  # faixa de fallback zerada
        "169.254.0",  # faixa de fallback comum
        "169.254.2",
    ]

    meu_ip = get_ipv4_ethernet()
    print(f"🖥️ IP detectado na Ethernet: {meu_ip}")

    if meu_ip:
        faixa_dinamica = ".".join(meu_ip.split(".")[:3])
        if faixa_dinamica not in faixa_comum:
            faixa_comum.insert(0, faixa_dinamica)

    total_achados = []
    for faixa in faixa_comum:
        hosts = scan_range(faixa)
        if hosts:
            try_open_hosts(hosts)
            total_achados.extend(hosts)

    if not total_achados:
        print("\n❌ Nenhum equipamento respondeu ao ping.")
    else:
        print(f"\n✅ Total de IPs encontrados: {len(total_achados)}")

if __name__ == "__main__":
    main()
