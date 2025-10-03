import json
import itertools
import subprocess
import platform
import os
import time
from concurrent.futures import ThreadPoolExecutor
import requests 

# --- ZABBIX E SNMP IMPORTS ---
try:
    from pysnmp.hlapi import *
    SNMP_AVAILABLE = True
except ImportError:
    SNMP_AVAILABLE = False
    def getCmd(*args, **kwargs):
        return [(None, None, 0), None, 0, None] 


# --- Funções de Leitura e Expansão ---

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
            "proxy_hostid": "0" # ID de um proxy Zabbix (ou "0" para o Server)
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


# --- Funções de Scanner (Ping + SNMP) ---

def scan_host(ip: str, ping_timeout: int, snmp_community: str) -> tuple[str, str] | None:
    """Verifica o ping. Se ativo, tenta o SNMP. Retorna (IP, Nome_do_Dispositivo)."""
    current_os = platform.system().lower()
    if current_os == "windows":
        command = ["ping", "-n", "1", "-w", str(ping_timeout * 1000), ip]
    else:
        command = ["ping", "-c", "1", "-W", str(ping_timeout), ip]
        
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=ping_timeout + 1)
        if result.returncode != 0:
            return None
    except Exception:
        return None
        
    device_name = ip
    
    if SNMP_AVAILABLE:
        try:
            # Consulta SNMP para sysName
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData(snmp_community, mpModel=1), 
                    UdpTransportTarget((ip, 161), timeout=ping_timeout, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.5.0'))
                )
            )

            if not error_indication and not error_status:
                name_value = var_binds[0][1].prettyPrint()
                device_name = name_value.strip("'").strip('"') 

        except Exception:
            pass
            
    return ip, device_name


# --- Funções de Cadastro no Zabbix com 'requests' ---

def check_host_name_existence(url: str, token: str, name: str) -> bool:
    """Verifica se um host com o mesmo NOME (host) já existe no Zabbix."""
    
    payload = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {
            "output": ["hostid"],
            "filter": {"host": name}
        },
        "auth": token,
        "id": 1
    }
    
    try:
        response = requests.post(url, json=payload, headers={'Content-Type': 'application/json-rpc'}, timeout=5)
        response.raise_for_status()
        
        result = response.json()
        
        if 'error' in result:
             error_data = result['error'].get('data')
             # Em caso de erro, assumimos que o host não deve ser criado
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
    """Verifica se um host com o mesmo IP já existe no Zabbix."""
    
    payload = {
        "jsonrpc": "2.0",
        "method": "hostinterface.get",
        "params": {
            "output": ["hostid"],
            "filter": {"ip": ip}
        },
        "auth": token,
        "id": 1
    }
    
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
    """
    Cria o host no Zabbix usando requisições HTTP (requests).
    Verifica primeiro por NOME e depois por IP.
    """
    zabbix_conf = conf['zabbix']
    url = zabbix_conf['url']
    token = zabbix_conf['api_token']
    host_group_id = zabbix_conf['host_group_id']
    template_id = zabbix_conf['template_id']
    proxy_hostid = zabbix_conf.get('proxy_hostid', '0')
    snmp_community = conf['community']

    # 1. Checagem de Existência pelo NOME
    if check_host_name_existence(url, token, name):
        print(f"  [ZABBIX] Host com NOME '{name}' já existe. Pulando IP {ip}.")
        return True

    # 2. Checagem de Existência pelo IP (Se o nome for novo, checa o IP)
    # Embora a API não permita duplicar hosts com o mesmo nome, essa checagem 
    # é útil para o caso de o sysName ser o próprio IP (dispositivo não-SNMP)
    if check_host_ip_existence(url, token, ip):
        print(f"  [ZABBIX] Host com IP '{ip}' já existe, mesmo com nome novo. Pulando.")
        return True
        
    # 3. Construção do Payload (Host.create)
    interface = {
        'type': 2,        # Tipo 2: SNMP
        'main': 1,
        'useip': 1,       # Usar IP
        'ip': ip,
        'dns': '',
        'port': '161',
        'details': {
            'version': 2, # SNMP v2c
            'community': snmp_community
        }
    }
    
    payload = {
        "jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": name, 
            "name": name, 
            "interfaces": [interface],
            "groups": [{'groupid': host_group_id}],
            "templates": [{'templateid': template_id}],
            "proxy_hostid": proxy_hostid
        },
        "auth": token,
        "id": 2
    }
    
    # 4. Envio da Requisição
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


# --- Bloco Principal de Execução ---

if __name__ == "__main__":
    
    if not SNMP_AVAILABLE:
        print("AVISO: A biblioteca 'pysnmp' não está instalada. A coleta de sysName será ignorada.")

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