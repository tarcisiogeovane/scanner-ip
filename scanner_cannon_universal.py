import subprocess
import platform
import socket
import psutil
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity

# --- Função: Testa ping em um IP ---
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

# --- Função: Testa se uma porta está aberta ---
def port_open(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=0.5):
            return True
    except:
        return False

# --- Função: Faz consulta SNMP com comunidade "public" ---
def snmp_check(ip):
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData('public', mpModel=0),
            UdpTransportTarget((ip, 161), timeout=1, retries=0),
            ContextData(),
            ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
        )
        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
        if not errorIndication and not errorStatus:
            for varBind in varBinds:
                return str(varBind[1])
    except:
        pass
    return None

# --- Função: Busca MAC associado ao IP via tabela ARP ---
def get_mac(ip):
    try:
        arp_table = subprocess.check_output("arp -a", shell=True).decode()
        for line in arp_table.splitlines():
            if ip in line:
                parts = line.split()
                for part in parts:
                    if "-" in part or ":" in part:
                        return part.lower()
    except:
        return None

# --- Função: Verifica se um IP está ativo via ping, portas ou SNMP ---
def scan_host(ip):
    result = {"ip": ip, "ping": False, "ports": [], "mac": None, "snmp": None}
    if ping_ip(ip):
        result["ping"] = True

    # Testar portas padrão de equipamentos de rede
    for port in [80, 443, 22, 23, 161, 8080, 554]:
        if port_open(ip, port):
            result["ports"].append(port)

    # Testar SNMP (caso a porta 161 esteja aberta ou por tentativa mesmo assim)
    if 161 in result["ports"] or True:
        snmp_info = snmp_check(ip)
        if snmp_info:
            result["snmp"] = snmp_info

    # Verificar MAC address na tabela ARP
    mac = get_mac(ip)
    if mac:
        result["mac"] = mac

    # Retorna se alguma info foi coletada
    if result["ping"] or result["ports"] or result["mac"] or result["snmp"]:
        return result
    return None

# --- Função: Detecta possíveis faixas de IP ---
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

# --- Função: Scanner principal com multithreading ---
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
                    print(f"[+] IP: {res['ip']} | Ping: {res['ping']} | Portas: {res['ports']} | MAC: {res['mac']} | SNMP: {res['snmp']}")

    if not found:
        print("\n❌ Nada encontrado.")
    else:
        print("\n✅ Dispositivos encontrados:")
        for res in found:
            print(f"IP: {res['ip']} | Ping: {res['ping']} | Portas: {res['ports']} | MAC: {res['mac']} | SNMP: {res['snmp']}")

# --- Execução principal ---
if __name__ == "__main__":
    full_scan()
