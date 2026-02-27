import ssl
import socket
from typing import Optional, List
from ldap3 import Server, Connection, ALL, NTLM, SIMPLE, SUBTREE, ALL_ATTRIBUTES, Tls
from ldap3.core.exceptions import LDAPException


def resolve_dc(domain: str) -> Optional[str]:
    for name in (f"_ldap._tcp.dc._msdcs.{domain}", domain):
        try:
            return socket.gethostbyname(name)
        except Exception:
            continue
    return None


class ADConnector:
    def __init__(self, dc_ip: str, domain: str, username: str, password: str,
                 use_ssl: bool = True, verify_cert: bool = False):
        self.dc_ip       = dc_ip
        self.domain      = domain
        self.username    = username
        self.password    = password
        self.use_ssl     = use_ssl
        self.verify_cert = verify_cert
        self.conn        = None
        self.server      = None
        self.base_dn     = self._to_dn(domain)
        self.config_dn   = f"CN=Configuration,{self.base_dn}"
        self.schema_dn   = f"CN=Schema,{self.config_dn}"

    @staticmethod
    def _to_dn(domain: str) -> str:
        return ",".join(f"DC={p}" for p in domain.split("."))

    def connect(self) -> bool:
        # Try LDAPS (636) first, fall back to LDAP (389) if it fails
        if self.use_ssl:
            if self._connect_ldaps():
                return True
            print("[!] LDAPS failed, falling back to LDAP port 389...")

        return self._connect_ldap()

    def _connect_ldaps(self) -> bool:
        tls = Tls(
            validate=ssl.CERT_REQUIRED if self.verify_cert else ssl.CERT_NONE,
            version=ssl.PROTOCOL_TLS_CLIENT if self.verify_cert else ssl.PROTOCOL_TLS
        )
        self.server = Server(self.dc_ip, port=636, use_ssl=True,
                             tls=tls, get_info=ALL)

        attempts = [
            # (auth_type, user_format)
            (NTLM,   f"{self.domain}\\{self.username}"),
            (NTLM,   f"{self.username}@{self.domain}"),
            ("SIMPLE", f"{self.username}@{self.domain}"),
        ]

        for auth, user in attempts:
            try:
                self.conn = Connection(
                    self.server,
                    user=user,
                    password=self.password,
                    authentication=auth,
                    auto_bind=True
                )
                print(f"[+] Connected via LDAPS (port 636, auth={auth}, user={user})")
                return True
            except Exception as e:
                print(f"[!] LDAPS attempt failed (auth={auth}, user={user}): {e}")

        return False

    def _connect_ldap(self) -> bool:
        try:
            self.server = Server(self.dc_ip, port=389, get_info=ALL)
            self.conn = Connection(
                self.server,
                user=f"{self.domain}\\{self.username}",
                password=self.password,
                authentication=NTLM,
                auto_bind=True
            )
            print("[+] Connected via LDAP (port 389)")
            return True
        except LDAPException as e:
            print(f"[!] LDAP connection failed: {e}")
            return False

    def search(self, filt: str, attrs: list = None,
               base: str = None, scope=SUBTREE) -> List:
        b = base or self.base_dn
        a = attrs or [ALL_ATTRIBUTES]
        try:
            self.conn.search(
                search_base=b, search_filter=filt,
                search_scope=scope, attributes=a, size_limit=10000
            )
            return self.conn.entries
        except LDAPException as e:
            print(f"  [~] LDAP search error ({filt[:60]}): {e}")
            return []

    def get_domain_object(self) -> Optional[object]:
        r = self.search("(objectClass=domain)", base=self.base_dn)
        return r[0] if r else None

    def attr_int(self, entry, attr: str, default: int = 0) -> int:
        v = getattr(entry, attr, None)
        if v is None or v.value is None:
            return default
        try:
            return int(str(v.value))
        except (ValueError, TypeError):
            return default

    def attr_str(self, entry, attr: str, default: str = "") -> str:
        v = getattr(entry, attr, None)
        if v is None or v.value is None:
            return default
        return str(v.value)

    def attr_list(self, entry, attr: str) -> List[str]:
        v = getattr(entry, attr, None)
        if v is None or v.value is None:
            return []
        val = v.value
        if isinstance(val, list):
            return [str(x) for x in val]
        return [str(val)]

    def resolve_sid(self, sid: str) -> str:
        """Resolve a SID string to a sAMAccountName, or return the SID if not found."""
        try:
            results = self.search(
                f"(objectSid={sid})",
                ["sAMAccountName", "objectClass"],
                base=self.base_dn
            )
            if results:
                name = self.attr_str(results[0], "sAMAccountName")
                classes = self.attr_list(results[0], "objectClass")
                kind = "computer" if "computer" in classes else \
                       "group"    if "group"    in classes else "user"
                return f"{name} ({kind})" if name else sid
        except Exception:
            pass
        return sid