# Proteção contra SSRF no próprio Sentinela. Qualquer endereço que o servidor
# vá acessar a pedido do usuário (alvo do scan, destino de webhook/Slack) passa
# por aqui antes.
#
# Política:
#  - só http/https, com host;
#  - SEMPRE bloqueado: link-local (169.254.0.0/16, fe80::/10 — inclui o serviço
#    de metadados de nuvem), 0.0.0.0, multicast e metadados conhecidos;
#  - loopback e redes privadas são PERMITIDOS por padrão (homologação interna
#    do banco, demos locais). Para bloquear: SENTINELA_BLOCK_PRIVATE_TARGETS=on;
#  - SENTINELA_TARGET_ALLOWLIST=host1,host2 restringe a destinos a esses hosts.
#
# Limitação: a resolução de DNS é feita na validação e de novo na requisição;
# um DNS malicioso poderia mudar a resposta entre as duas (DNS rebinding).

import ipaddress
import os
import socket
from urllib.parse import urlparse

METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}
METADATA_IPS = {ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("100.100.100.200"), ipaddress.ip_address("fd00:ec2::254")}


class TargetNotAllowed(ValueError):
    pass


def _env_on(name: str) -> bool:
    return os.environ.get(name, "").lower() in ("1", "on", "true", "yes")


def _addresses(host: str) -> list:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as err:
        raise TargetNotAllowed(f"Não foi possível resolver o endereço '{host}'.") from err
    return [ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos]


def validate_url(url: str) -> str:
    """Devolve a URL normalizada (sem barra final) ou levanta TargetNotAllowed."""
    url = (url or "").strip()
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or any(c.isspace() for c in url):
        raise TargetNotAllowed("URL inválida — use o formato https://exemplo.com (sem espaços).")
    host = parsed.hostname.lower()

    allow = [h.strip().lower() for h in os.environ.get("SENTINELA_TARGET_ALLOWLIST", "").split(",") if h.strip()]
    if allow and host not in allow:
        raise TargetNotAllowed(f"O endereço '{host}' não está na lista de destinos autorizados (SENTINELA_TARGET_ALLOWLIST).")

    if host in METADATA_HOSTS:
        raise TargetNotAllowed("Endereços de metadados de nuvem não são permitidos.")

    block_private = _env_on("SENTINELA_BLOCK_PRIVATE_TARGETS")
    for ip in _addresses(host):
        if ip.version == 6 and ip.ipv4_mapped:  # ::ffff:169.254.169.254 não pode escapar da checagem de IPv4
            ip = ip.ipv4_mapped
        # loopback (127.0.0.0/8, ::1) é tratado abaixo; o ::1 cai em ::/8, que o Python marca como "reservado"
        if not ip.is_loopback and (ip in METADATA_IPS or ip.is_link_local or ip.is_unspecified or ip.is_multicast or ip.is_reserved):
            raise TargetNotAllowed("Este endereço (link-local, metadados ou reservado) não é um destino permitido.")
        if ip in METADATA_IPS:
            raise TargetNotAllowed("Este endereço (link-local, metadados ou reservado) não é um destino permitido.")
        if block_private and (ip.is_private or ip.is_loopback):
            raise TargetNotAllowed("Redes privadas e loopback estão bloqueadas neste ambiente (SENTINELA_BLOCK_PRIVATE_TARGETS).")
    return url.rstrip("/")
