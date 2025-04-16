import os
import platform
import subprocess

# Detecta o sistema operacional (Windows usa '-n', Linux/Mac usa '-c')
param = '-n' if platform.system().lower() == 'windows' else '-c'

# Faixa de IPs para varrer
base_ip = "169.254.1."

print("Iniciando varredura de IPs Canopy (169.254.1.1 até 169.254.1.254)...")

for i in range(1, 255):
    ip = base_ip + str(i)
    try:
        resultado = subprocess.run(["ping", param, "1", ip], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        if "TTL=" in resultado.stdout or "ttl=" in resultado.stdout:
            print(f"[+] Dispositivo ativo encontrado em: {ip}")
    except KeyboardInterrupt:
        print("\nInterrompido pelo usuário.")
        break
    except Exception as e:
        print(f"Erro ao testar {ip}: {e}")
