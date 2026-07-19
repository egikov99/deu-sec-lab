import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse


PRIVATE_HOSTS = {"localhost"}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
)


@dataclass(frozen=True)
class ValidatedTarget:
    original: str
    host: str
    url: str
    is_domain: bool
    is_ip: bool


def _is_private_host(host: str) -> bool:
    normalized = host.lower().strip("[]")
    if normalized in PRIVATE_HOSTS:
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local or address.is_multicast


def validate_target(target: str, allow_private: bool = False) -> ValidatedTarget:
    value = target.strip()
    if not value:
        raise ValueError("Target is required")
    if any(char in value for char in [" ", "\t", "\n", "\r", ";", "&", "|", "`", "$", "(", ")", "<", ">"]):
        raise ValueError("Target contains unsupported characters")

    parsed = urlparse(value if "://" in value else f"https://{value}")
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http and https targets are allowed")
    if parsed.username or parsed.password:
        raise ValueError("Credentials in target URLs are not allowed")
    if parsed.params:
        raise ValueError("URL parameters are not supported")
    if not parsed.hostname:
        raise ValueError("Target host is required")

    host = parsed.hostname.lower()
    try:
        ipaddress.ip_address(host)
        is_ip = True
        is_domain = False
    except ValueError:
        is_ip = False
        is_domain = bool(DOMAIN_RE.match(host))
        if not is_domain:
            raise ValueError("Target must be a valid domain, IP address, or http/https URL")

    if _is_private_host(host) and not allow_private:
        raise ValueError("Private, local, and loopback targets are disabled by default")

    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or ""
    query = f"?{parsed.query}" if parsed.query else ""
    url = f"{parsed.scheme}://{host}{port}{path}{query}"
    return ValidatedTarget(original=value, host=host, url=url, is_domain=is_domain, is_ip=is_ip)
