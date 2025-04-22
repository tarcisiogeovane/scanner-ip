import subprocess
import platform
import socket
import psutil
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue

# --- Prefixos MAC conhecidos da Motorola Canopy ---
motorola_prefixes = ["00:04:56", "00:0F:66", "00:12:BF", "00:15:6D", "00:1B:2F", "00:1D:7E", "00:20:40"]

# --- Verifica se o MAC começa com prefixo Motorola ---
def is_motorola_mac(mac):
    if not mac:
        return False
    for prefix in motorola_prefixes:
        if mac.lower().startswith(prefix.lower()):
            return True
    return False

# --- Pinga o IP pra ver se está ativo ---
def ping_ip(ip):
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(
            ["ping", param, "1", ip],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=1
        )
        return "TTL=" in result.stdout or "ttl=" in result.stdout
    except Exception:
        return False

# --- Verifica se porta está aberta ---
def port_open(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=0.5):
            return True
    except Exception:
        return False

# --- Faz consulta SNMP ---
def snmp_check(ip, community):
    try:
        errorIndication, errorStatus, errorIndex, varBinds = next(
            getCmd(
                SnmpEngine(),
                CommunityData(community, mpModel=0),  # SNMPv1
                UdpTransportTarget((ip, 161), timeout=1, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
            )
        )
        if errorIndication or errorStatus:
            return None
        for varBind in varBinds:
            return str(varBind[1])
    except Exception:
        return None

# --- Tenta capturar o MAC pela tabela ARP ---
def get_mac(ip):
    try:
        arp_table = subprocess.check_output("arp -a", shell=True, text=True)
        for line in arp_table.splitlines():
            if ip in line:
                parts = line.split()
                for part in parts:
                    if "-" in part or ":" in part:
                        return part.lower()
    except Exception:
        return None

# --- Verifica as infos de um host ---
def scan_host(ip, do_ping, do_ports, do_snmp, do_mac, community, result_queue):
    result = {"ip": ip, "ping": False, "ports": [], "mac": None, "snmp": None, "is_motorola": False}
    
    # Ping
    if do_ping and ping_ip(ip):
        result["ping"] = True

    # Portas comuns (adicionadas portas típicas de dispositivos de rede)
    if do_ports:
        for port in [80, 443, 22, 23, 161, 8080, 554, 81, 8000]:
            if port_open(ip, port):
                result["ports"].append(port)

    # SNMP
    if do_snmp:
        snmp_info = snmp_check(ip, community)
        if snmp_info:
            result["snmp"] = snmp_info

    # MAC
    if do_mac:
        mac = get_mac(ip)
        if mac:
            result["mac"] = mac
            if is_motorola_mac(mac):
                result["is_motorola"] = True

    if result["ping"] or result["ports"] or result["mac"] or result["snmp"]:
        result_queue.put(result)

# --- Gera faixas possíveis para escanear ---
def get_possible_ranges():
    ranges = [
        "192.168.0", "192.168.1", "192.168.88",
        "192.168.100", "192.168.254", "10.0.0",
        "169.254.0", "169.254.1", "169.254.2",
        "169.254.128"  # Common for devices like radios
    ]
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                ip = addr.address
                ip_base = ".".join(ip.split(".")[:3])
                if ip_base not in ranges:
                    ranges.insert(0, ip_base)
    return ranges

# --- Detecta dispositivos conectados diretamente ---
def get_connected_devices():
    devices = []
    try:
        # Escanear ARP para dispositivos conectados
        arp_table = subprocess.check_output("arp -a", shell=True, text=True)
        for line in arp_table.splitlines():
            parts = line.split()
            if len(parts) > 0 and "." in parts[0]:
                ip = parts[0]
                devices.append(ip)
        
        # Adicionar IPs padrão de dispositivos (e.g., radios)
        default_ips = [
            "169.254.1.1", "192.168.0.1", "192.168.1.1",
            "10.0.0.1", "169.254.128.1"
        ]
        for ip in default_ips:
            if ping_ip(ip) or port_open(ip, 80) or port_open(ip, 161):
                if ip not in devices:
                    devices.append(ip)
    except Exception:
        pass
    return devices

# --- GUI ---
class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Scanner de Rede Universal")
        self.root.geometry("800x600")
        self.scan_thread = None
        self.stop_scan = False
        self.result_queue = queue.Queue()

        # Frame principal
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Seleção de faixa de IP
        ttk.Label(self.main_frame, text="Faixa de IP (ex: 192.168.1.1-254):").grid(row=0, column=0, sticky=tk.W)
        self.ip_range = ttk.Combobox(self.main_frame, values=[f"{r}.1-254" for r in get_possible_ranges()], width=30)
        self.ip_range.grid(row=0, column=1, sticky=tk.W)
        self.ip_range.set(f"{get_possible_ranges()[0]}.1-254")

        # Community string SNMP
        ttk.Label(self.main_frame, text="Community String SNMP:").grid(row=1, column=0, sticky=tk.W)
        self.community = ttk.Entry(self.main_frame, width=20)
        self.community.grid(row=1, column=1, sticky=tk.W)
        self.community.insert(0, "public")

        # Opções de escaneamento
        self.ping_var = tk.BooleanVar(value=True)
        self.ports_var = tk.BooleanVar(value=True)
        self.snmp_var = tk.BooleanVar(value=True)
        self.mac_var = tk.BooleanVar(value=True)

        ttk.Checkbutton(self.main_frame, text="Ping", variable=self.ping_var).grid(row=2, column=0, sticky=tk.W)
        ttk.Checkbutton(self.main_frame, text="Portas", variable=self.ports_var).grid(row=2, column=1, sticky=tk.W)
        ttk.Checkbutton(self.main_frame, text="SNMP", variable=self.snmp_var).grid(row=3, column=0, sticky=tk.W)
        ttk.Checkbutton(self.main_frame, text="MAC", variable=self.mac_var).grid(row=3, column=1, sticky=tk.W)

        # Botões
        self.scan_button = ttk.Button(self.main_frame, text="Escanear Faixa Selecionada", command=self.start_scan)
        self.scan_button.grid(row=4, column=0, pady=10)

        self.scan_all_button = ttk.Button(self.main_frame, text="Escanear Todas as Redes", command=self.start_scan_all)
        self.scan_all_button.grid(row=4, column=1, pady=10)

        self.quick_scan_button = ttk.Button(self.main_frame, text="Escaneamento Rápido (Dispositivos Conectados)", command=self.start_quick_scan)
        self.quick_scan_button.grid(row=5, column=0, columnspan=2, pady=5)

        self.stop_button = ttk.Button(self.main_frame, text="Parar Escaneamento", command=self.stop_scan_func, state=tk.DISABLED)
        self.stop_button.grid(row=6, column=0, columnspan=2, pady=5)

        # Área de resultados
        self.result_text = scrolledtext.ScrolledText(self.main_frame, width=90, height=20)
        self.result_text.grid(row=7, column=0, columnspan=2, pady=10)

        # Barra de status
        self.status_var = tk.StringVar(value="Pronto")
        ttk.Label(self.main_frame, textvariable=self.status_var).grid(row=8, column=0, columnspan=2, sticky=tk.W)

        # Configurar redimensionamento
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)

        # Atualizar resultados periodicamente
        self.update_results()

    def parse_ip_range(self, ip_range):
        try:
            start_ip, end_range = ip_range.split("-")
            base = ".".join(start_ip.split(".")[:3])
            start = int(start_ip.split(".")[-1])
            end = int(end_range)
            return [f"{base}.{i}" for i in range(start, end + 1)]
        except Exception:
            return []

    def start_scan(self):
        self.result_text.delete(1.0, tk.END)
        self.scan_button.config(state=tk.DISABLED)
        self.scan_all_button.config(state=tk.DISABLED)
        self.quick_scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_scan = False
        self.result_queue = queue.Queue()

        ip_range = self.ip_range.get()
        community = self.community.get()
        do_ping = self.ping_var.get()
        do_ports = self.ports_var.get()
        do_snmp = self.snmp_var.get()
        do_mac = self.mac_var.get()

        ips = self.parse_ip_range(ip_range)
        if not ips:
            self.result_text.insert(tk.END, "Erro: Faixa de IP inválida.\n")
            self.scan_button.config(state=tk.NORMAL)
            self.scan_all_button.config(state=tk.NORMAL)
            self.quick_scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            return

        self.scan_thread = threading.Thread(
            target=self.scan_network,
            args=([ips], do_ping, do_ports, do_snmp, do_mac, community)
        )
        self.scan_thread.start()

    def start_scan_all(self):
        self.result_text.delete(1.0, tk.END)
        self.scan_button.config(state=tk.DISABLED)
        self.scan_all_button.config(state=tk.DISABLED)
        self.quick_scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_scan = False
        self.result_queue = queue.Queue()

        community = self.community.get()
        do_ping = self.ping_var.get()
        do_ports = self.ports_var.get()
        do_snmp = self.snmp_var.get()
        do_mac = self.mac_var.get()

        ranges = get_possible_ranges()
        all_ips = []
        for r in ranges:
            ips = [f"{r}.{i}" for i in range(1, 255)]
            all_ips.append(ips)

        self.scan_thread = threading.Thread(
            target=self.scan_network,
            args=(all_ips, do_ping, do_ports, do_snmp, do_mac, community)
        )
        self.scan_thread.start()

    def start_quick_scan(self):
        self.result_text.delete(1.0, tk.END)
        self.scan_button.config(state=tk.DISABLED)
        self.scan_all_button.config(state=tk.DISABLED)
        self.quick_scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.stop_scan = False
        self.result_queue = queue.Queue()

        community = self.community.get()
        do_ping = self.ping_var.get()
        do_ports = self.ports_var.get()
        do_snmp = self.snmp_var.get()
        do_mac = self.mac_var.get()

        # Detectar dispositivos conectados
        devices = get_connected_devices()
        if not devices:
            self.result_text.insert(tk.END, "Nenhum dispositivo detectado. Tente conectar o dispositivo e executar novamente.\n")
            self.scan_button.config(state=tk.NORMAL)
            self.scan_all_button.config(state=tk.NORMAL)
            self.quick_scan_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            return

        self.scan_thread = threading.Thread(
            target=self.scan_network,
            args=([devices], do_ping, do_ports, do_snmp, do_mac, community)
        )
        self.scan_thread.start()

    def scan_network(self, ip_ranges, do_ping, do_ports, do_snmp, do_mac, community):
        for idx, ips in enumerate(ip_ranges):
            if self.stop_scan:
                break
            self.status_var.set(f"Escaneando dispositivos ({idx + 1}/{len(ip_ranges)})...")
            self.result_queue.put(f"\n🔍 Escaneando {len(ips)} IPs...")

            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {executor.submit(scan_host, ip, do_ping, do_ports, do_snmp, do_mac, community, self.result_queue): ip for ip in ips}
                for future in as_completed(futures):
                    if self.stop_scan:
                        break
                    try:
                        ip = futures[future]
                        future.result()
                    except Exception as e:
                        self.result_queue.put(f"Erro ao escanear {ip}: {e}")

        self.result_queue.put("FIM")
        self.status_var.set("Escaneamento concluído.")

    def update_results(self):
        try:
            while True:
                item = self.result_queue.get_nowait()
                if item == "FIM":
                    self.scan_button.config(state=tk.NORMAL)
                    self.scan_all_button.config(state=tk.NORMAL)
                    self.quick_scan_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    break
                if isinstance(item, dict):
                    motorola_tag = "🟢 MOTOROLA" if item["is_motorola"] else ""
                    self.result_text.insert(
                        tk.END,
                        f"[+] IP: {item['ip']} | Ping: {item['ping']} | Portas: {item['ports']} | "
                        f"MAC: {item['mac']} | SNMP: {item['snmp']} {motorola_tag}\n"
                    )
                else:
                    self.result_text.insert(tk.END, f"{item}\n")
                self.result_text.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(100, self.update_results)

    def stop_scan_func(self):
        self.stop_scan = True
        self.status_var.set("Parando escaneamento...")
        self.scan_button.config(state=tk.NORMAL)
        self.scan_all_button.config(state=tk.NORMAL)
        self.quick_scan_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()