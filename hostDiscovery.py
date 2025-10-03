import json
import itertools
import subprocess
import platform
import os
import time
import re # Novo import para expressão regular
from concurrent.futures import ThreadPoolExecutor
import requests 

# Não precisamos mais do pysnmp. 
# Removida toda a lógica de tratamento de imports e mocks de SNMP.

# --- Funções de Leitura e Expansão (MANTIDAS) ---

def expand_range(ip_range: str):
    """Expande ranges de IP em qualquer octeto."""
    parts = ip_range.split(".")
    expanded_parts = []

    for part in parts:
        part = part.strip("'").strip('"') 
        
        if "-" in part:
            try:
                start, end = map(int, part.split("-"))
                expanded_parts.append(range(start, end + 1))
            except ValueError:
                return []
        else:
            try:
                expanded_parts.append([int(part)])
            except ValueError:
                return []

    ips = []
    for combo in itertools.product(*expanded_parts):
        ips.append(".".join(map(str, combo)))

    return ips


def load_conf(filename="conf.json"):
    """Carrega todas as configurações, incluindo as do Zabbix, do arquivo conf.json."""
    
    # Cria o arquivo de exemplo se ele não existir
    if not os.path.exists(filename):
        print(f"Criando arquivo de configuração '{filename}' com o exemplo Zabbix...")
        example_conf = {
          "ranges": ["192.168.1.1-10"],
          "timeout": 1,
          "threads": 5,
          "community": "public",
          "zabbix_api": {
            "url": "http://seu.zabbix.server/api_jsonrpc.php", 
            "api_token": "COLE_SEU_TOKEN_API_AQUI", 
            "host_group_id": "1",
            "template_id": "10001",
            "proxy_hostid": "0" 
          }
        }
        with open(filename, "w") as f:
            json.dump(example_conf, f, indent=4)

    with open(filename, "r") as f:
        data = json.load(f)

    all_ips = []
    for r in data.get("ranges", []):
        all_ips.extend(expand_range(r))
        
    zabbix_conf = data.get("zabbix_api", {})

    return {
        "ips": all_ips,
        "timeout": data.get("timeout", 1),
        "threads": data.get("threads", 5),
        "community": data.get("community", "public"),
        "zabbix": zabbix_conf
    }


# --- Funções de Scanner (Ping + SNMP) (NOVA VERSÃO SEM pysnmp) ---

def scan_host(ip: str, ping_timeout: int, snmp_community: str) -> tuple[str, str] | None:
    """Verifica o ping. Se ativo, tenta o SNMP (via snmpget). Retorna (IP, Nome_do_Dispositivo)."""
    
    # 1. PING
    current_os = platform.system().lower()
    if current_os == "windows":
        command_ping = ["ping", "-n", "1", "-w", str(ping_timeout * 1000), ip]
    else:
        command_ping = ["ping", "-c", "1", "-W", str(ping_timeout), ip]
        
    try:
        result_ping = subprocess.run(command_ping, capture_output=True, text=True, timeout=ping_timeout + 1)
        if result_ping.returncode != 0:
            return None
    except Exception:
        return None
        
    device_name = ip
    
    # 2. SNMPGET (sysName)
    try:
        # Comando snmpget para coletar sysName (OID: 1.3.6.1.2.1.1.5.0)
        command_snmp = [
            "snmpget", 
            "-v2c", 
            "-c", snmp_community, 
            ip, 
            "1.3.6.1.2.1.1.5.0"
        ]
        
        # O timeout do snmpget é controlado pelo sistema, mas usamos um timeout geral aqui.
        result_snmp = subprocess.run(command_snmp, capture_output=True, text=True, timeout=ping_timeout + 1)

        if result_snmp.returncode == 0:
            # A saída é algo como: 'iso.3.6.1.2.1.1.5.0 = STRING: "NomeDoDevice"'
            output_line = result_snmp.stdout.strip()
            
            # Expressão regular para encontrar o valor dentro das aspas após "STRING:"
            match = re.search(r'STRING:\s*"?([^"]+)"?', output_line)
            
            if match:
                name_value = match.group(1).strip()
                if name_value:
                    device_name = name_value
                    print(f"  [DEBUG SNMP {ip}] NOME EXTRAÍDO: {device_name}") # Retorno de debug
            else:
                print(f"  [DEBUG SNMP {ip}] Falha ao parsear STRING. Saída: {output_line}")

        else:
            # Imprime o erro do snmpget (ex: Timeout, No Such Name)
            print(f"  [DEBUG SNMP {ip}] SNMPGET ERRO ({result_snmp.returncode}): {result_snmp.stderr.strip()}")

    except FileNotFoundError:
        print("  [DEBUG SNMP] O comando 'snmpget' não foi encontrado. Instale o pacote 'snmp-utils'.")
        # Continua usando o IP como nome
    except Exception as e:
        print(f"  [DEBUG SNMP {ip}] EXCEÇÃO GERAL: {e}")
        pass
            
    return ip, device_name


# --- Funções de Cadastro no Zabbix com 'requests' (MANTIDAS) ---

# ... (Funções check_host_name_existence, check_host_ip_existence e add_host_to_zabbix_with_requests mantidas)

# Remova ou comente o código das funções auxiliares aqui para manter a resposta concisa, 
# mas use a versão completa do script do passo anterior, apenas substituindo a função scan_host.
def check_host_name_existence(url: str, token: str, name: str) -> bool:
    # ... (MANTIDA)
    payload = {"jsonrpc": "2.0", "method": "host.get", "params": {"output": ["hostid"], "filter": {"host": name}}, "auth": token, "id": 1}
    try:
        response = requests.post(url, json=payload, headers={'Content-Type': 'application/json-rpc'}, timeout=5)
        response.raise_for_status()
        result = response.json()
        if 'error' in result:
             error_data = result['error'].get('data')
             print(f"  [ZABBIX] ❌ ERRO de API ao checar NOME '{name}'. Detalhe: {error_data}")
             return True 
        return len(result.get('result', [])) > 0
    except requests.exceptions.RequestException as e:
        print(f"  [ZABBIX] ❌ ERRO de Requisição ao checar NOME '{name}': {e}")
        return True
    except Exception as e:
        print(f"  [ZABBIX] ❌ ERRO inesperado ao checar NOME '{name}': {e}")
        return True

def check_host_ip_existence(url: str, token: str, ip: str) -> bool:
    # ... (MANTIDA)
    payload = {"jsonrpc": "2.0", "method": "hostinterface.get", "params": {"output": ["hostid"], "filter": {"ip": ip}}, "auth": token, "id": 1}
    try:
        response = requests.post(url, json=payload, headers={'Content-Type': 'application/json-rpc'}, timeout=5)
        response.raise_for_status()
        result = response.json()
        if 'error' in result:
             error_data = result['error'].get('data')
             print(f"  [ZABBIX] ❌ ERRO de API ao checar IP {ip}. Detalhe: {error_data}")
             return True 
        return len(result.get('result', [])) > 0
    except requests.exceptions.RequestException as e:
        print(f"  [ZABBIX] ❌ ERRO de Requisição ao checar IP {ip}: {e}")
        return True
    except Exception as e:
        print(f"  [ZABBIX] ❌ ERRO inesperado ao checar IP {ip}: {e}")
        return True

def add_host_to_zabbix_with_requests(ip: str, name: str, conf: dict) -> bool:
    # ... (MANTIDA)
    zabbix_conf = conf['zabbix']
    url = zabbix_conf['url']
    token = zabbix_conf['api_token']
    host_group_id = zabbix_conf['host_group_id']
    template_id = zabbix_conf['template_id']
    proxy_hostid = zabbix_conf.get('proxy_hostid', '0') 
    snmp_community = conf['community']

    if check_host_name_existence(url, token, name):
        print(f"  [ZABBIX] Host com NOME '{name}' já existe. Pulando IP {ip}.")
        return True

    if check_host_ip_existence(url, token, ip):
        print(f"  [ZABBIX] Host com IP '{ip}' já existe, mesmo com nome novo. Pulando.")
        return True
        
    interface = {'type': 2, 'main': 1, 'useip': 1, 'ip': ip, 'dns': '', 'port': '161', 'details': {'version': 2, 'community': snmp_community}}
    
    payload = {
        "jsonrpc": "2.0", "method": "host.create",
        "params": {
            "host": name, "name": name, "interfaces": [interface],
            "groups": [{'groupid': host_group_id}], "templates": [{'templateid': template_id}],
            "proxy_hostid": proxy_hostid
        },
        "auth": token, "id": 2
    }
    
    try:
        response = requests.post(url, json=payload, headers={'Content-Type': 'application/json-rpc'}, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        if 'error' in result:
            error_data = result['error'].get('data', 'Erro de API desconhecido')
            print(f"  [ZABBIX] ❌ ERRO ao criar host '{name}' (IP: {ip}): {error_data}")
            return False

        host_id = result['result']['hostids'][0]
        proxy_info = f"(Proxy ID: {proxy_hostid})" if proxy_hostid != '0' else "(Monitored by Server)"
        print(f"  [ZABBIX] ✅ Host '{name}' criado com sucesso! ID: {host_id} {proxy_info}")
        return True

    except requests.exceptions.RequestException as e:
        print(f"  [ZABBIX] ❌ ERRO de Requisição HTTP ao criar host '{name}': {e}")
        return False
    except Exception as e:
        print(f"  [ZABBIX] ❌ ERRO inesperado ao criar host '{name}': {e}")
        return False


# --- Bloco Principal de Execução (MANTIDO) ---

if __name__ == "__main__":
    
    # O aviso de pysnmp não é mais necessário, mas o de FileNotFoundError (snmpget não instalado) é importante.

    try:
        start_time = time.time()
        conf = load_conf()
        ips_to_scan = conf["ips"]
        total_ips = len(ips_to_scan)
        
        print("🔧 Configurações carregadas:")
        print(f"Total de IPs a escanear: {total_ips} IPs")
        print(f"Threads de varredura: {conf['threads']}")
        print(f"URL Zabbix: {conf['zabbix']['url']}")
        print("-" * 50)
        
        active_devices = [] 
        
        # 1. VARREDURA (PING + SNMP)
        print("📡 Iniciando varredura de PING e SNMP (Host Discovery)...")
        with ThreadPoolExecutor(max_workers=conf['threads']) as executor:
            future_to_ip = {
                executor.submit(
                    scan_host, 
                    ip, 
                    conf['timeout'], 
                    conf['community']
                ): ip for ip in ips_to_scan
            }
            
            for future in future_to_ip:
                result = future.result()
                if result:
                    ip_addr, device_name = result
                    active_devices.append(result)
                    print(f"🟢 ATIVO: {ip_addr} -> Nome: {device_name}")

        print("-" * 50)
        
        # 2. CADASTRO NO ZABBIX USANDO 'REQUESTS'
        if active_devices:
            print("🚀 Iniciando cadastro no Zabbix via requests...")
            
            hosts_created_count = 0
            for ip, name in active_devices:
                if add_host_to_zabbix_with_requests(ip, name, conf):
                    hosts_created_count += 1
            
            print(f"\nTotal de Hosts tentados no Zabbix: {len(active_devices)}")
            print(f"Total de Hosts Criados/Atualizados: {hosts_created_count}")
        else:
            print("Nenhum host ativo encontrado. Nenhuma tentativa de cadastro no Zabbix.")
        
        
        end_time = time.time()
        print("\n--- Processo Finalizado ---")
        print(f"Tempo total de execução: {end_time - start_time:.2f} segundos")

    except FileNotFoundError:
        print("ERRO: O arquivo 'conf.json' não foi encontrado. Verifique se ele está no mesmo diretório do script.")
    except json.JSONDecodeError as e:
        print(f"ERRO: O arquivo 'conf.json' está mal formatado. Detalhe: {e}")
    except Exception as e:
        print(f"Ocorreu um erro inesperado: {e}")