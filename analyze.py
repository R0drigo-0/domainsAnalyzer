from datetime import datetime
import pyarrow.parquet as pq
import pandas as pd
import json
import os

from itertools import product
from datetime import datetime
import dns.resolver
import tldextract
import requests
import difflib
import socket
import struct
import whois
import json
import ssl
import re


def read_json(file_path, keyword: str = None) -> list:
    with open(file_path, "r") as f:
        data = json.load(f)
    if keyword:
        return data.get(keyword, [])
    return data


def analyze_domains(domain: str):
    if not domain:
        return None

    domain_info = {
        "domain": domain,
        "analysis_timestamp": datetime.now().isoformat(),
        "dns_records": {},
        "whois_info": {},
        "ssl_info": {},
        "http_info": {},
        "related_domains": [],
        "security_checks": {},
    }

    extract_result = tldextract.extract(domain)
    domain_info["domain_parts"] = {
        "subdomain": extract_result.subdomain,
        "domain": extract_result.domain,
        "suffix": extract_result.suffix,
        "registered_domain": extract_result.registered_domain,
    }
    print(f"Analyzing domain: {domain}")
    dns_types = [
        "A",  # IPv4 address mapping - Maps hostnames to IPv4 addresses
        "AAAA",  # IPv6 address mapping - Maps hostnames to IPv6 addresses
        "AFSDB",  # AFS database location - Used by AFS clients to locate servers
        "APL",  # Address Prefix List - Specifies address ranges (experimental)
        "CAA",  # Certificate Authority Authorization - Restricts which CAs can issue certificates
        "CDNSKEY",  # Child copy of DNSKEY record - For transfer to parent zone
        "CDS",  # Child copy of DS record - For transfer to parent zone
        "CERT",  # Certificate storage - Stores PKIX, SPKI, PGP certificates
        "CNAME",  # Canonical name - Alias of one name to another
        "CSYNC",  # Child-to-Parent Synchronization - Syncs NS records between child and parent
        "DHCID",  # DHCP identifier - Used with FQDN option in DHCP
        "DNAME",  # Delegation name - Alias for a domain and all its subdomains
        "DNSKEY",  # DNS Key for DNSSEC - Public key used for DNSSEC validation
        "DS",  # Delegation Signer - Identifies DNSSEC signing key of delegated zone
        "EUI48",  # 48-bit MAC address - Maps hardware MAC address to domain
        "EUI64",  # 64-bit MAC address - Maps hardware MAC address to domain
        "HINFO",  # Host information - CPU type and OS info (rarely used today)
        "HIP",  # Host Identity Protocol - Separates IP address from host identity
        "HTTPS",  # HTTPS service binding - Improves performance for HTTPS connections
        "IPSECKEY",  # IPsec key - Key record used with IPsec
        "KX",  # Key Exchanger - Identifies key management agent for domain
        "LOC",  # Geographic location - Physical location of server (lat/long)
        "MX",  # Mail exchange - Specifies mail servers for the domain
        "NAPTR",  # Name Authority Pointer - Used for ENUM, SIP, and other services
        "NS",  # Name server - Delegates DNS zone to authoritative servers
        "NSEC",  # Next Secure - Part of DNSSEC, proves name doesn't exist
        "NSEC3",  # NSEC version 3 - Enhanced DNSSEC record that prevents zone walking
        "NSEC3PARAM",  # NSEC3 parameters - Parameters for use with NSEC3
        "OPENPGPKEY",  # OpenPGP public key - DANE method for publishing OpenPGP keys
        "PTR",  # Pointer record - Maps IP to hostname (reverse DNS)
        "RP",  # Responsible Person - Contact info for domain administrators
        "RRSIG",  # DNSSEC signature - Digital signature for DNSSEC-secured records
        "SIG",  # Signature - Legacy signature record (replaced by RRSIG)
        "SMIMEA",  # S/MIME certificate association - Associates S/MIME cert with domain
        "SOA",  # Start of Authority - Defines zone parameters and primary nameserver
        "SRV",  # Service locator - Locates services like SIP, XMPP, LDAP
        "SSHFP",  # SSH public key fingerprint - Verifies SSH host keys via DNS
        "SVCB",  # Service Binding - Generic version of HTTPS record for service endpoints
        "TLSA",  # TLS Authentication - DANE method to verify TLS certificates
        "TXT",  # Text record - Stores arbitrary text, SPF, DKIM, DMARC, etc.
        "URI",  # Uniform Resource Identifier - Maps hostnames to URIs
    ]
    for record_type in dns_types:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            domain_info["dns_records"][record_type] = [str(rdata) for rdata in answers]
        except Exception as e:
            domain_info["dns_records"][record_type] = str(e)

    try:
        ip_addresses = socket.gethostbyname_ex(domain)[2]
        domain_info["ip_addresses"] = ip_addresses
    except Exception as e:
        domain_info["ip_addresses_error"] = str(e)

    try:
        whois_data = whois.whois(domain)
        domain_info["whois_info"] = {
            "registrar": whois_data.registrar,
            "creation_date": str(whois_data.creation_date),
            "expiration_date": str(whois_data.expiration_date),
            "last_updated": str(whois_data.updated_date),
            "name_servers": whois_data.name_servers,
        }
        domain_info["whois_info"]["age_days"] = (
            ((datetime.now() - whois_data.creation_date[0])
             if isinstance(whois_data.creation_date, list)
             else (datetime.now() - whois_data.creation_date)).days
            if whois_data.creation_date else None
        )
    except Exception as e:
        domain_info["whois_info_error"] = str(e)

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                domain_info["ssl_info"] = {
                    "subject": dict(x[0] for x in cert["subject"]),
                    "issuer": dict(x[0] for x in cert["issuer"]),
                    "version": cert["version"],
                    "serialNumber": cert["serialNumber"],
                    "notBefore": cert["notBefore"],
                    "notAfter": cert["notAfter"],
                    "subjectAltName": [x[1] for x in cert["subjectAltName"]],
                }
    except Exception as e:
        domain_info["ssl_info_error"] = str(e)

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        for protocol in ["https", "http"]:
            try:
                response = requests.get(
                    f"{protocol}://{domain}",
                    headers=headers,
                    timeout=5,
                    allow_redirects=True,
                )
                domain_info["http_info"][protocol] = {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "redirect_history": [
                        {"url": r.url, "status_code": r.status_code}
                        for r in response.history
                    ],
                    "final_url": response.url,
                    "content_length": len(response.text),
                    "title": (
                        response.text.split("<title>")[1].split("</title>")[0]
                        if "<title>" in response.text
                        else None
                    ),
                }
                break  # If HTTPS works, no need to check HTTP
            except Exception as e:
                domain_info["http_info"][protocol] = {"error": str(e)}
    except Exception as e:
        domain_info["http_info_error"] = str(e)

    # Security checks
    age_days = domain_info["whois_info"].get("age_days")
    domain_info["security_checks"] = {
        "is_newly_registered": True if age_days is not None and age_days < 30 else False,
        "has_ssl": "ssl_info_error" not in domain_info,
        "uses_cloudflare": (
            any(
                "cloudflare" in str(v).lower()
                for k, v in domain_info.get("http_info", {})
                .get("https", {})
                .get("headers", {})
                .items()
            )
            if "https" in domain_info.get("http_info", {}) else False
        ),
        "suspicious_tld": extract_result.suffix in [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz"],
        "domain_typos": None,
    }

    return domain_info


def analyze_ip(ip: str):
    if not ip:
        return None

    ip_info = {
        "ip": ip,
        "analysis_timestamp": datetime.now().isoformat(),
        "basic_info": {},
        "geolocation": {},
        "dns_info": {},
        "network_info": {},
        "open_ports": [],
        "connected_domains": [],
    }

    try:
        socket.inet_aton(ip)
        ip_type = "IPv4"

        ip_num = struct.unpack("!I", socket.inet_aton(ip))[0]

        private_ranges = [
            ("10.0.0.0", "10.255.255.255"),  # Class A private range
            ("172.16.0.0", "172.31.255.255"),  # Class B private range
            ("192.168.0.0", "192.168.255.255"),  # Class C private range
            ("127.0.0.0", "127.255.255.255"),  # Loopback range
            (
                "169.254.0.0",
                "169.254.255.255",
            ),  # Link-local range (missing in original)
        ]

        private_ranges_int = [
            (
                struct.unpack("!I", socket.inet_aton(lower))[0],
                struct.unpack("!I", socket.inet_aton(upper))[0],
            )
            for lower, upper in private_ranges
        ]

        is_private = any(
            lower <= ip_num <= upper for lower, upper in private_ranges_int
        )

        ip_info["basic_info"] = {
            "ip_type": ip_type,
            "is_private": is_private,
            "is_valid": True,
        }
    except socket.error:
        ip_info["basic_info"] = {
            "is_valid": False,
            "error": "Invalid IP address format",
        }
        return ip_info

    # Get geolocation info (no API key required)
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if response.status_code == 200:
            data = response.json()
            ip_info["geolocation"] = {
                "country": data.get("country_name"),
                "country_code": data.get("country_code"),
                "region": data.get("region"),
                "city": data.get("city"),
                "latitude": data.get("latitude"),
                "longitude": data.get("longitude"),
                "timezone": data.get("timezone"),
                "org": data.get("org"),
                "asn": data.get("asn"),
            }
    except Exception as e:
        ip_info["geolocation_error"] = str(e)

    # Reverse DNS lookup
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        ip_info["dns_info"]["hostname"] = hostname
    except (socket.herror, socket.gaierror):
        ip_info["dns_info"]["hostname"] = None

    # Check common open ports (FUTURE)

    return ip_info


def _extract_domain_parts(domain):
    # For domains like abc.domain.com or login.user.domain.com
    parts = domain.lower().split(".")
    domain = domain.lower()
    if len(parts) >= 3:
        subdomain = ".".join(parts[:-2])
        base = ".".join(parts[-2:])
        return subdomain, parts[-2], base
    elif len(parts) == 2:
        # For domains like google.com
        return "", parts[0], ".".join(parts)
    else:
        # For single label domains
        return "", parts[0], parts[0]


def _check_char_substitution(domain: str, phishing_domain: str) -> bool:
    if not domain or not phishing_domain:
        return False

    _, main_domain, base_domain = _extract_domain_parts(domain)
    subdomain, main_phishing_domain, base_phishing_domain = _extract_domain_parts(
        phishing_domain
    )

    if main_domain == main_phishing_domain:
        return False

    substitutions = {
        "a": [
            "4",
            "@",
            "à",
            "á",
            "â",
            "ã",
            "ä",
            "å",
            "а",
            "ạ",
            "ą",
            "ă",
            "ǎ",
            "ȧ",
            "ɑ",
            "α",
            "ａ",
            "A",
            "Д",
        ],
        "b": [
            "8",
            "6",
            "ḅ",
            "ḃ",
            "ḇ",
            "б",
            "ḅ",
            "ɓ",
            "ḃ",
            "ƀ",
            "β",
            "ｂ",
            "lb",
            "io",
            "lo",
            "B",
            "Б",
            "ß",
        ],
        "c": [
            "(",
            "{",
            "[",
            "<",
            "¢",
            "ç",
            "ć",
            "č",
            "с",
            "ƈ",
            "ċ",
            "ĉ",
            "ɕ",
            "ϲ",
            "ｃ",
            "C",
            "С",
            "Ç",
        ],
        "d": [
            "cl",
            "dl",
            "ḋ",
            "ḍ",
            "ḏ",
            "ḑ",
            "ḓ",
            "д",
            "ɗ",
            "đ",
            "ď",
            "ḋ",
            "ð",
            "ｄ",
            "cl",
            "ol",
            "D",
            "Д",
        ],
        "e": [
            "3",
            "€",
            "è",
            "é",
            "ê",
            "ë",
            "ē",
            "ĕ",
            "ė",
            "ę",
            "ě",
            "е",
            "э",
            "ё",
            "є",
            "ɛ",
            "ε",
            "ｅ",
            "E",
            "Е",
            "Э",
        ],
        "f": ["ph", "ƒ", "ḟ", "ф", "ſ", "ẝ", "ƭ", "ｆ", "F", "Ф"],
        "g": [
            "6",
            "9",
            "ǵ",
            "ğ",
            "ġ",
            "ģ",
            "ǧ",
            "ǥ",
            "г",
            "ɡ",
            "ɢ",
            "ǥ",
            "ǧ",
            "ｇ",
            "q",
            "G",
            "Г",
            "Ģ",
        ],
        "h": ["ĥ", "ħ", "н", "ḧ", "ḩ", "ḫ", "ẖ", "ⱨ", "ｈ", "ln", "li", "lh", "H", "Н"],
        "i": [
            "1",
            "!",
            "|",
            "ì",
            "í",
            "î",
            "ï",
            "ĩ",
            "ī",
            "ĭ",
            "į",
            "ı",
            "и",
            "і",
            "ı",
            "ɪ",
            "ι",
            "｜",
            "ｉ",
            "l",
            "j",
            "I",
            "І",
            "Ї",
        ],
        "j": ["ĵ", "ǰ", "й", "ʝ", "ɉ", "ｊ", "i", "J", "Й", "Ĵ"],
        "k": ["к", "ķ", "ƙ", "ǩ", "ҝ", "κ", "ｋ", "K", "К"],
        "l": [
            "1",
            "|",
            "ĺ",
            "ļ",
            "ľ",
            "ŀ",
            "ł",
            "л",
            "ḷ",
            "ḹ",
            "ḻ",
            "ḽ",
            "ｌ",
            "i",
            "ӏ",
            "I",
            "L",
            "Л",
            "£",
        ],
        "m": [
            "rn",
            "rri",
            "ṁ",
            "ṃ",
            "м",
            "ḿ",
            "ṁ",
            "ṃ",
            "ɱ",
            "ｍ",
            "nn",
            "nw",
            "rnrn",
            "M",
            "М",
        ],
        "n": [
            "ñ",
            "ń",
            "ņ",
            "ň",
            "ŉ",
            "ŋ",
            "н",
            "ṅ",
            "ṇ",
            "ṉ",
            "ṋ",
            "ｎ",
            "m",
            "r",
            "N",
            "Н",
            "Ñ",
        ],
        "o": [
            "0",
            "()",
            "[]",
            "{]",
            "ò",
            "ó",
            "ô",
            "õ",
            "ö",
            "ø",
            "ō",
            "ŏ",
            "ő",
            "о",
            "ọ",
            "ỏ",
            "ơ",
            "ɵ",
            "ο",
            "ｏ",
            "Q",
            "O",
            "Ο",
            "О",
            "Ø",
            "Ô",
            "Ö",
            "θ",
            "၀",
        ],
        "p": ["ṗ", "р", "ƥ", "ρ", "ｐ", "q", "ք", "þ", "ρ", "ƿ", "Р", "P", "П"],
        "q": ["9", "ԛ", "ɋ", "ｑ", "g", "զ", "Q", "Ԛ", "ʠ", "φ", "ϑ", "ợ", "Ф"],
        "r": [
            "®",
            "ŕ",
            "ŗ",
            "ř",
            "ṙ",
            "ṛ",
            "ṝ",
            "ṟ",
            "р",
            "ɍ",
            "ɼ",
            "ｒ",
            "n",
            "ʀ",
            "ʁ",
            "я",
            "г",
            "ℛ",
            "ʳ",
            "ᵣ",
            "ɾ",
            "ⓡ",
            "R",
            "Я",
            "Р",
        ],
        "s": [
            "5",
            "$",
            "ś",
            "ŝ",
            "ş",
            "š",
            "ș",
            "ṡ",
            "ṣ",
            "с",
            "ʂ",
            "ｓ",
            "z",
            "ѕ",
            "S",
            "§",
            "ϟ",
            "ˢ",
            "ⓢ",
            "ꜱ",
            "ꞩ",
            "С",
        ],
        "t": [
            "7",
            "+",
            "†",
            "ţ",
            "ť",
            "ŧ",
            "ṫ",
            "ṭ",
            "ṯ",
            "ṱ",
            "т",
            "ƭ",
            "ｔ",
            "f",
            "τ",
            "T",
            "Τ",
            "Т",
            "ᴛ",
            "ⓣ",
            "ţ",
            "ʇ",
            "ȶ",
        ],
        "u": [
            "µ",
            "ù",
            "ú",
            "û",
            "ü",
            "ũ",
            "ū",
            "ŭ",
            "ů",
            "ű",
            "ų",
            "у",
            "ṳ",
            "ｕ",
            "v",
            "υ",
            "ц",
            "U",
            "Ü",
            "Û",
            "Ù",
            "Ú",
            "µ",
            "ʉ",
            "ᵤ",
            "ꞟ",
            "У",
        ],
        "v": [
            "ṿ",
            "ṽ",
            "в",
            "ⱱ",
            "ｖ",
            "u",
            "ν",
            "ѵ",
            "V",
            "ʋ",
            "Ѵ",
            "ⅴ",
            "ᵥ",
            "ⓥ",
            "ᴠ",
            "В",
        ],
        "w": [
            "vv",
            "\\/\\/",
            "ŵ",
            "ẁ",
            "ẃ",
            "ẅ",
            "ẇ",
            "ẉ",
            "ш",
            "щ",
            "ɯ",
            "ω",
            "ｗ",
            "uu",
            "uv",
            "ѡ",
            "ԝ",
            "W",
            "Ԝ",
            "Ѡ",
            "ᴡ",
            "ⓦ",
            "Ⱳ",
            "ʬ",
            "Ш",
            "Щ",
        ],
        "x": [
            "×",
            "ẋ",
            "ẍ",
            "х",
            "ⅹ",
            "ｘ",
            "k",
            "ҳ",
            "X",
            "Х",
            "χ",
            "ⓧ",
            "᙭",
            "ˣ",
            "ⅹ",
            "Ж",
        ],
        "y": [
            "j",
            "ý",
            "ÿ",
            "ŷ",
            "ẏ",
            "ỳ",
            "ỵ",
            "ỷ",
            "ỹ",
            "у",
            "ӯ",
            "ｙ",
            "γ",
            "ү",
            "Y",
            "Υ",
            "Ү",
            "ʸ",
            "ʏ",
            "ⓨ",
            "ẙ",
            "У",
        ],
        "z": [
            "2",
            "ź",
            "ż",
            "ž",
            "ẑ",
            "ẓ",
            "ẕ",
            "з",
            "ʐ",
            "ɀ",
            "ｚ",
            "s",
            "ʐ",
            "ծ",
            "Z",
            "Ζ",
            "Z",
            "ᴢ",
            "ⓩ",
            "ẕ",
            "ẓ",
            "З",
        ],
        "0": [
            "o",
            "O",
            "о",
            "О",
            "ο",
            "Ο",
            "၀",
            "०",
            "٠",
            "໐",
            "〇",
            "零",
            "𝟎",
            "𝟘",
            "𝟢",
            "𝟬",
            "𝟶",
        ],
        "1": [
            "l",
            "I",
            "і",
            "ı",
            "ӏ",
            "１",
            "١",
            "۱",
            "१",
            "១",
            "১",
            "൧",
            "፩",
            "១",
            "១",
            "၁",
            "๑",
            "𝟏",
            "𝟙",
            "𝟣",
            "𝟭",
            "𝟷",
        ],
        "2": [
            "z",
            "Z",
            "２",
            "٢",
            "۲",
            "२",
            "២",
            "২",
            "൨",
            "፪",
            "២",
            "២",
            "၂",
            "๒",
            "𝟐",
            "𝟚",
            "𝟤",
            "𝟮",
            "𝟸",
        ],
        "3": [
            "e",
            "E",
            "е",
            "з",
            "З",
            "Ε",
            "ε",
            "３",
            "٣",
            "۳",
            "३",
            "៣",
            "৩",
            "൩",
            "፫",
            "៣",
            "៣",
            "၃",
            "๓",
            "𝟑",
            "𝟛",
            "𝟥",
            "𝟯",
            "𝟹",
        ],
        "4": [
            "a",
            "A",
            "４",
            "٤",
            "۴",
            "४",
            "៤",
            "৪",
            "൪",
            "፬",
            "៤",
            "៤",
            "၄",
            "๔",
            "𝟒",
            "𝟜",
            "𝟦",
            "𝟰",
            "𝟺",
        ],
        "5": [
            "s",
            "S",
            "５",
            "٥",
            "۵",
            "५",
            "៥",
            "৫",
            "൫",
            "፭",
            "៥",
            "៥",
            "၅",
            "๕",
            "𝟓",
            "𝟝",
            "𝟧",
            "𝟱",
            "𝟻",
        ],
        "6": [
            "b",
            "G",
            "б",
            "Б",
            "６",
            "٦",
            "۶",
            "६",
            "៦",
            "৬",
            "൬",
            "፮",
            "៦",
            "៦",
            "၆",
            "๖",
            "𝟔",
            "𝟞",
            "𝟨",
            "𝟲",
            "𝟼",
        ],
        "7": [
            "T",
            "t",
            "７",
            "٧",
            "۷",
            "७",
            "៧",
            "৭",
            "൭",
            "፯",
            "៧",
            "៧",
            "၇",
            "๗",
            "𝟕",
            "𝟟",
            "𝟩",
            "𝟳",
            "𝟽",
        ],
        "8": [
            "B",
            "b",
            "８",
            "٨",
            "۸",
            "८",
            "៨",
            "৮",
            "൮",
            "፰",
            "៨",
            "៨",
            "၈",
            "๘",
            "𝟖",
            "𝟠",
            "𝟪",
            "𝟴",
            "𝟾",
        ],
        "9": [
            "g",
            "q",
            "９",
            "٩",
            "۹",
            "९",
            "៩",
            "৯",
            "൯",
            "፱",
            "៩",
            "៩",
            "၉",
            "๙",
            "𝟗",
            "𝟡",
            "𝟫",
            "𝟵",
            "𝟿",
        ],
    }

    # To remove noise
    if abs(len(main_domain) - len(main_phishing_domain)) > 10:
        return False

    for i, char in enumerate(main_domain):
        if i >= len(main_phishing_domain):
            continue

        if char == main_phishing_domain[i]:
            continue

        if char in substitutions and main_phishing_domain[i] in substitutions[char]:
            return True

        if (
            char == "m"
            and i < len(main_phishing_domain) - 1
            and main_phishing_domain[i : i + 2] == "rn"
        ):
            return True

    matched_chars = sum(1 for a, b in zip(main_domain, main_phishing_domain) if a == b)
    similarity_ratio = matched_chars / max(len(main_domain), len(main_phishing_domain))

    if similarity_ratio > 0.6:
        for i, (a, b) in enumerate(zip(main_domain, main_phishing_domain)):
            if a != b:
                if (a in substitutions and b in substitutions[a]) or any(
                    a in subs and b == orig for orig, subs in substitutions.items()
                ):
                    return True

    return False


def _check_typosquatting(domain: str, phishing_domain: str) -> bool:
    if not domain or not phishing_domain:
        return False

    domain = domain.lower()
    phishing_domain = phishing_domain.lower()

    if domain == phishing_domain:
        return False

    _, main_domain, base_domain = _extract_domain_parts(domain)
    subdomain, main_phishing_domain, base_phishing_domain = _extract_domain_parts(
        phishing_domain
    )

    if abs(len(main_domain) - len(main_phishing_domain)) > 2:
        return False

    keyboard_adjacents = {
        "a": ["q", "w", "s", "z", "1", "2", "@"],
        "b": ["v", "g", "h", "n", "f", "c"],
        "c": ["x", "d", "f", "v", "s", "b"],
        "d": ["s", "e", "r", "f", "c", "x", "w", "3", "2"],
        "e": ["w", "s", "d", "r", "3", "4", "f", "2"],
        "f": ["d", "r", "t", "g", "v", "c", "e", "4", "5"],
        "g": ["f", "t", "y", "h", "b", "v", "r", "5", "6", "c"],
        "h": ["g", "y", "u", "j", "n", "b", "t", "6", "7", "m"],
        "i": ["u", "j", "k", "o", "8", "9", "l", "["],
        "j": ["h", "u", "i", "k", "m", "n", "y", "7", "8", "l"],
        "k": ["j", "i", "o", "l", "m", "u", "8", "9", ","],
        "l": ["k", "o", "p", "i", "9", "0", ";", "."],
        "m": ["n", "j", "k", "b", "h", ",", "l"],
        "n": ["b", "h", "j", "m", "g", "y", "u", "k", ","],
        "o": ["i", "k", "l", "p", "9", "0", "-", "[", ";"],
        "p": ["o", "l", "0", "-", "=", "[", "]"],
        "q": ["w", "a", "s", "1", "2", "`", "~"],
        "r": ["e", "d", "f", "t", "4", "5", "g", "3"],
        "s": ["a", "w", "e", "d", "x", "z", "q", "2", "3", "c", "f"],
        "t": ["r", "f", "g", "y", "5", "6", "4", "h"],
        "u": ["y", "h", "j", "i", "7", "8", "k", "o"],
        "v": ["c", "f", "g", "b", "d", "x"],
        "w": ["q", "a", "s", "e", "2", "3", "d", "1"],
        "x": ["z", "s", "d", "c", "a", "v", "f"],
        "y": ["t", "g", "h", "u", "6", "7", "j", "i"],
        "z": ["a", "s", "x", "q", "d", "c"],
        "1": ["q", "w", "2", "`", "~", "!", "@"],
        "2": ["q", "w", "1", "3", "@", "#", "e", "s", "a"],
        "3": ["w", "e", "2", "4", "#", "$", "r", "d", "s"],
        "4": ["e", "r", "3", "5", "$", "%", "f", "t", "d"],
        "5": ["r", "t", "4", "6", "%", "^", "g", "f", "y"],
        "6": ["t", "y", "5", "7", "^", "&", "h", "g", "u"],
        "7": ["y", "u", "6", "8", "&", "*", "j", "h", "i"],
        "8": ["u", "i", "7", "9", "*", "(", "k", "j", "o"],
        "9": ["i", "o", "8", "0", "(", ")", "l", "k", "p"],
        "0": ["o", "p", "9", "-", ")", "_", "[", "l", ";"],
        "-": ["0", "p", "=", "_", "+", "]", "[", "o"],
        ".": [",", "/", "l", ";", ">"],
        ",": ["m", "n", ".", "k", "l", "<"],
        "/": [".", "l", ";", "[", "?"],
        ";": ["l", "k", "'", "/", ":"],
        "'": [";", "k", "l", "[", '"'],
        "[": ["p", "o", "]", "'", "{"],
        "]": ["[", "p", "\\", "}", "{"],
        "\\": ["]", "=", "|"],
        "=": ["-", "p", "[", "\\", "+"],
        "`": ["1", "~", "q", "~"],
        "~": ["`", "!", "1", "q", "`"],
        "!": ["1", "~", "@", "q", "w", "2"],
        "@": ["2", "!", "#", "q", "w", "e", "1", "3"],
        "#": ["3", "@", "$", "w", "e", "r", "2", "4"],
        "$": ["4", "#", "%", "e", "r", "t", "3", "5"],
        "%": ["5", "$", "^", "r", "t", "y", "4", "6"],
        "^": ["6", "%", "&", "t", "y", "u", "5", "7"],
        "&": ["7", "^", "*", "y", "u", "i", "6", "8"],
        "*": ["8", "&", "(", "u", "i", "o", "7", "9"],
        "(": ["9", "*", ")", "i", "o", "p", "8", "0"],
        ")": ["0", "(", "_", "o", "p", "-", "9"],
        "_": ["-", ")", "+", "p", "[", "0"],
        "+": ["=", "_", "{", "[", "-"],
        ":": [";", '"', "'", "l", "k"],
        '"': ["'", ":", "{", "[", ";"],
        "{": ["[", '"', "}", "]", "'"],
        "}": ["]", "{", "|", "\\", "["],
        "|": ["\\", "}", "=", "]"],
        "<": [",", "m", ".", "l", "k"],
        ">": [".", "/", "?", "l", ";"],
        "?": ["/", ">", "_", "+", ";"],
    }

    if len(main_domain) == len(main_phishing_domain):
        diff_pos = [
            i
            for i in range(min(len(main_domain), len(main_phishing_domain)))
            if main_domain[i] != main_phishing_domain[i]
        ]

        if len(diff_pos) == 1:
            pos = diff_pos[0]
            if main_domain[pos] in keyboard_adjacents and main_phishing_domain[
                pos
            ] in keyboard_adjacents.get(main_domain[pos], []):
                return True

        if len(diff_pos) == 2 and abs(diff_pos[0] - diff_pos[1]) == 1:
            if (
                main_domain[diff_pos[0]] == main_phishing_domain[diff_pos[1]]
                and main_domain[diff_pos[1]] == main_phishing_domain[diff_pos[0]]
            ):
                return True

    if len(main_domain) - len(main_phishing_domain) == 1:
        for i in range(len(main_domain)):
            if main_domain[:i] + main_domain[i + 1 :] == main_phishing_domain:
                return True

    if len(main_phishing_domain) - len(main_domain) == 1:
        for i in range(len(main_phishing_domain)):
            if main_phishing_domain[:i] + main_phishing_domain[i + 1 :] == main_domain:
                return True

    domain_parts = domain.split(".")
    phishing_parts = phishing_domain.split(".")

    if len(domain_parts) >= 2 and len(phishing_parts) >= 2:
        domain_without_tld = ".".join(domain_parts[:-1])
        phishing_without_tld = ".".join(phishing_parts[:-1])

        if (
            domain_without_tld == phishing_without_tld
            and domain_parts[-1] != phishing_parts[-1]
        ):
            return True

    def levenshtein_distance(s1, s2):
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    distance = levenshtein_distance(main_domain, main_phishing_domain)
    max_length = max(len(main_domain), len(main_phishing_domain))

    if max_length > 0 and distance / max_length < 0.2:
        return True

    return False


def _check_combo_squatting(domain: str, phishing_domain: str) -> bool:
    if not domain or not phishing_domain:
        return False

    domain = domain.lower()
    phishing_domain = phishing_domain.lower()

    if domain == phishing_domain:
        return False

    _, main_domain, base_domain = _extract_domain_parts(domain)
    subdomain, main_phishing_domain, base_phishing_domain = _extract_domain_parts(
        phishing_domain
    )

    common_keywords = read_json("./config/suspicious_keywords.json", "keywords")

    if main_domain in main_phishing_domain:
        prefix = main_phishing_domain[: main_phishing_domain.find(main_domain)]
        suffix = main_phishing_domain[
            main_phishing_domain.find(main_domain) + len(main_domain) :
        ]

        if prefix and prefix.rstrip("-") in common_keywords:
            return True

        if suffix and suffix.lstrip("-") in common_keywords:
            return True

    if subdomain and main_domain in subdomain:
        return True

    if main_domain == main_phishing_domain and base_domain != base_phishing_domain:
        return True

    return False


def _check_subdomain_impersonation(domain: str, phishing_domain: str) -> bool:
    if not domain or not phishing_domain:
        return False

    domain = domain.lower()
    phishing_domain = phishing_domain.lower()

    if domain == phishing_domain:
        return False

    subdomain, main_domain, base_domain = _extract_domain_parts(domain)
    phish_subdomain, phish_main, phish_base = _extract_domain_parts(phishing_domain)

    suspicious_keywords = read_json("./config/suspicious_keywords.json", "keywords")

    if phish_subdomain and (
        main_domain in phish_subdomain or base_domain in phish_subdomain
    ):
        return True

    separators = [".", "-", "_"]
    all_patterns = []

    for keyword in suspicious_keywords:
        for sep in separators:
            all_patterns.append(f"{main_domain}{sep}{keyword}")
            all_patterns.append(f"{keyword}{sep}{main_domain}")

    for pattern in all_patterns:
        if pattern == phish_main or (phish_subdomain and pattern in phish_subdomain):
            return True

    for sep in separators:
        parts = phish_main.split(sep)
        if len(parts) > 1 and main_domain in parts:
            for part in parts:
                if part in suspicious_keywords:
                    return True
            return True

    if phish_subdomain:
        for sep in separators:
            subdomain_parts = phish_subdomain.split(sep)
            for part in subdomain_parts:
                if part in suspicious_keywords and (
                    main_domain in phish_main or base_domain == phish_base
                ):
                    return True

        if main_domain in phish_subdomain:
            for keyword in suspicious_keywords:
                if keyword in phish_subdomain:
                    return True

    if phish_subdomain:
        for keyword in suspicious_keywords:
            combo_patterns = [
                f"{keyword}.{main_domain}",
                f"{main_domain}.{keyword}",
                f"{keyword}-{main_domain}",
                f"{main_domain}-{keyword}",
                f"{keyword}_{main_domain}",
                f"{main_domain}_{keyword}",
            ]
            for pattern in combo_patterns:
                if pattern in phish_subdomain:
                    return True

    return False


def _check_suspicious_tld(domain: str) -> bool:
    suspicious_tlds = read_json("./config/suspicious_tld.json", "tlds")
    ext = tldextract.extract(domain)
    tld = f".{ext.suffix}"

    return tld in suspicious_tlds


def _check_url_length(domain: str) -> bool:
    return len(domain) > 30


def _check_brand_impersonation(domain: str, known_brands: list) -> bool:
    ext = tldextract.extract(domain)
    parts = [ext.subdomain] + ext.domain.split("-")
    parts = [p for p in parts if p]

    for brand in known_brands:
        brand = brand.lower()
        for part in parts:
            ratio = difflib.SequenceMatcher(None, part.lower(), brand).ratio()
            if ratio >= 0.7:
                if ext.registered_domain != (brand + "." + ext.suffix):
                    return True

    return False


def check_phishing_domain(domain: str, target_domains: list) -> dict:
    results = {
        "domain": domain,
        "is_suspicious": False,
        "score": 0,
        "detected_patterns": [],
        "target_similarity": {},
    }

    if _check_url_length(domain):
        results["score"] += 1
        results["detected_patterns"].append("suspicious_length")

    if _check_suspicious_tld(domain):
        results["score"] += 2
        results["detected_patterns"].append("suspicious_tld")

    for target in target_domains:
        target_results = {"target": target, "patterns": [], "similarity_score": 0}

        if _check_char_substitution(target, domain):
            target_results["patterns"].append("char_substitution")
            target_results["similarity_score"] += 4

        if _check_typosquatting(target, domain):
            target_results["patterns"].append("typosquatting")
            target_results["similarity_score"] += 3

        if _check_combo_squatting(target, domain):
            target_results["patterns"].append("combo_squatting")
            target_results["similarity_score"] += 3

        if _check_subdomain_impersonation(target, domain):
            target_results["patterns"].append("subdomain_impersonation")
            target_results["similarity_score"] += 4

        if _check_brand_impersonation(domain, [target.split(".")[0]]):
            target_results["patterns"].append("brand_impersonation")
            target_results["similarity_score"] += 3

        if target_results["similarity_score"] > 0:
            results["target_similarity"][target] = target_results
            results["score"] += target_results["similarity_score"]

    results["is_suspicious"] = results["score"] >= 3
    return results


def process_parquet(file_path, batch_size=1000):
    """
    "query_type",  # Type of DNS query made (A, AAAA, MX, etc.)
    "query_name",  # Domain name queried (example.com)
    "response_type",  # Type of DNS response received
    "response_name",  # Domain name in the response
    "response_ttl",  # Time-to-live value for the record (in seconds)
    "timestamp",  # When the DNS query was made
    "rtt",  # Round-trip time for the query (in milliseconds)
    "worker_id",  # ID of the worker that processed the query
    "status_code",  # DNS response code (NOERROR, NXDOMAIN, etc.)
    "ad_flag",  # Authenticated Data flag for DNSSEC validation
    "section",  # Section of DNS response (ANSWER, AUTHORITY, ADDITIONAL)
    "ip4_address",  # IPv4 address in the response (for A records)
    "ip6_address",  # IPv6 address in the response (for AAAA records)
    "country",  # Country associated with the IP address
    "as",  # Autonomous System number
    "as_full",  # Full Autonomous System information
    "ip_prefix",  # IP prefix/range for the address
    "cname_name",  # Target domain name in CNAME records
    "dname_name",  # Target domain name in DNAME records
    "mx_address",  # Mail server hostname in MX records
    "mx_preference",  # Priority value for the MX record
    "ns_address",  # Nameserver hostname in NS records
    "txt_text",  # Text content in TXT records
    "ds_key_tag",  # Key tag in DS records (DNSSEC)
    "ds_algorithm",  # Cryptographic algorithm in DS records
    "ds_digest_type",  # Digest type used in DS records
    "ds_digest",  # Digest value in DS records
    "dnskey_flags",  # Flags field in DNSKEY records
    "dnskey_protocol",  # Protocol field in DNSKEY records (always 3)
    "dnskey_algorithm",  # Algorithm used for the DNSKEY
    "dnskey_pk_rsa_n",  # RSA modulus for DNSKEY
    "dnskey_pk_rsa_e",  # RSA exponent for DNSKEY
    "dnskey_pk_rsa_bitsize",  # Bit size of the RSA key
    "dnskey_pk_eccgost_x",  # ECCGOST x-coordinate for DNSKEY
    "dnskey_pk_eccgost_y",  # ECCGOST y-coordinate for DNSKEY
    "dnskey_pk_dsa_t",  # DSA t-parameter for DNSKEY
    "dnskey_pk_dsa_q",  # DSA q-parameter for DNSKEY
    "dnskey_pk_dsa_p",  # DSA p-parameter for DNSKEY
    "dnskey_pk_dsa_g",  # DSA g-parameter for DNSKEY
    "dnskey_pk_dsa_y",  # DSA y-parameter for DNSKEY
    "dnskey_pk_eddsa_a",  # EdDSA a-parameter for DNSKEY
    "dnskey_pk_wire",  # Wire format of the public key
    "nsec_next_domain_name",  # Next secure domain name in NSEC records
    "nsec_owner_rrset_types",  # Record types present for the owner name in NSEC
    "nsec3_hash_algorithm",  # Hash algorithm used in NSEC3
    "nsec3_flags",  # Flags field in NSEC3 records
    "nsec3_iterations",  # Number of hash iterations in NSEC3
    "nsec3_salt",  # Salt value used in NSEC3 hashing
    "nsec3_next_domain_name_hash",  # Hash of the next domain name in NSEC3
    "nsec3_owner_rrset_types",  # Record types present for the owner name in NSEC3
    "nsec3param_hash_algorithm",  # Hash algorithm in NSEC3PARAM records
    "nsec3param_flags",  # Flags field in NSEC3PARAM records
    "nsec3param_iterations",  # Number of hash iterations in NSEC3PARAM
    "nsec3param_salt",  # Salt value used in NSEC3PARAM
    "spf_text",  # SPF record text content (legacy)
    "soa_mname",  # Primary master nameserver in SOA records
    "soa_rname",  # Admin email address in SOA records
    "soa_serial",  # Zone serial number in SOA records
    "soa_refresh",  # Refresh interval for secondary nameservers
    "soa_retry",  # Retry interval for failed zone transfers
    "soa_expire",  # Expiration time for secondary nameservers
    "soa_minimum",  # Minimum TTL for negative caching
    "rrsig_type_covered",  # Record type covered by the RRSIG
    "rrsig_algorithm",  # Algorithm used for the RRSIG
    "rrsig_labels",  # Number of labels in the covered name
    "rrsig_original_ttl",  # Original TTL of the covered records
    "rrsig_signature_inception",  # When signature validity begins
    "rrsig_signature_expiration",  # When signature validity ends
    "rrsig_key_tag",  # Key tag of the signing key
    "rrsig_signer_name",  # Domain name of the signing zone
    "rrsig_signature",  # The cryptographic signature
    "cds_key_tag",  # Key tag in CDS records
    "cds_algorithm",  # Algorithm in CDS records
    "cds_digest_type",  # Digest type in CDS records
    "cds_digest",  # Digest value in CDS records
    "cdnskey_flags",  # Flags field in CDNSKEY records
    "cdnskey_protocol",  # Protocol field in CDNSKEY records
    "cdnskey_algorithm",  # Algorithm in CDNSKEY records
    "cdnskey_pk_rsa_n",  # RSA modulus for CDNSKEY
    "cdnskey_pk_rsa_e",  # RSA exponent for CDNSKEY
    "cdnskey_pk_rsa_bitsize",  # Bit size of the RSA key for CDNSKEY
    "cdnskey_pk_eccgost_x",  # ECCGOST x-coordinate for CDNSKEY
    "cdnskey_pk_eccgost_y",  # ECCGOST y-coordinate for CDNSKEY
    "cdnskey_pk_dsa_t",  # DSA t-parameter for CDNSKEY
    "cdnskey_pk_dsa_q",  # DSA q-parameter for CDNSKEY
    "cdnskey_pk_dsa_p",  # DSA p-parameter for CDNSKEY
    "cdnskey_pk_dsa_g",  # DSA g-parameter for CDNSKEY
    "cdnskey_pk_dsa_y",  # DSA y-parameter for CDNSKEY
    "cdnskey_pk_eddsa_a",  # EdDSA a-parameter for CDNSKEY
    "cdnskey_pk_wire",  # Wire format of the CDNSKEY public key
    "caa_flags",  # Flags field in CAA records (critical bit)
    "caa_tag",  # Property tag in CAA records (issue, issuewild, iodef)
    "caa_value",  # Value field in CAA records (CA domain or URL)
    "tlsa_usage",  # Certificate usage field in TLSA records
    "tlsa_selector",  # Selector field in TLSA records
    "tlsa_matchtype",  # Matching type in TLSA records
    "tlsa_certdata",  # Certificate data in TLSA records
    "ptr_name",  # Domain name in PTR records (reverse DNS)
    """

    file_path = os.path.normpath(file_path)

    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return None

    print(f"Processing {file_path}")
    
    target_domains = read_json("./config/domains_to_search.json", "domains")

    print(f"Target domains: {target_domains}")

    found_domains = set()
    potential_phishing = {}

    parquet_file = pq.ParquetFile(file_path)
    for batch_idx, batch in enumerate(parquet_file.iter_batches(batch_size=batch_size)):
        df = batch.to_pandas()
        df["query_name"] = df["query_name"].apply(
            lambda x: x.rstrip(".") if isinstance(x, str) else x
        )

        batch_domains = set()
        if "query_name" in df.columns:
            batch_domains.update(df["query_name"].dropna().tolist())
        if "cname_name" in df.columns:
            batch_domains.update(df["cname_name"].dropna().tolist())
        if "mx_address" in df.columns:
            batch_domains.update(df["mx_address"].dropna().tolist())
        if "ns_address" in df.columns:
            batch_domains.update(df["ns_address"].dropna().tolist())

        found_domains.update(batch_domains)

        print(f"Processed batch {batch_idx+1} with {len(batch_domains)} domains")

    print(f"Total unique domains found: {len(found_domains)}")

    # For each target domain, find potential phishing domains
    for target_domain in target_domains:
        print(f"Analyzing potential phishing domains for: {target_domain}")
        phishing_candidates = check_phishing_domain(target_domain, found_domains)
        potential_phishing[target_domain] = phishing_candidates
        print(f"Found {len(phishing_candidates)} potential phishing domains")

    # Save results to file
    with open("phishing_analysis.json", "w") as f:
        json.dump(
            {
                "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "total_domains": len(found_domains),
                "target_domains": target_domains,
                "suspicious_domains": potential_phishing,
            },
            f,
            indent=2,
        )

    print("Analysis complete and saved to phishing_analysis.json")

    # Optionally, analyze the most suspicious domains
    top_suspicious = []
    for target, target_results in potential_phishing.items():
        if "target_similarity" in target_results:
            for candidate_domain, similarity_info in target_results["target_similarity"].items():
                if similarity_info["similarity_score"] >= 8:
                    detailed_analysis = analyze_domains(candidate_domain)
                    if detailed_analysis:
                        similarity_info["detailed_analysis"] = detailed_analysis
                        similarity_info["domain"] = candidate_domain
                        top_suspicious.append(similarity_info)

    if top_suspicious:
        with open("high_risk_domains.json", "w") as f:
            json.dump(
                {
                    "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "high_risk_domains": top_suspicious,
                },
                f,
                indent=2,
            )
        print(
            f"Detailed analysis of {len(top_suspicious)} high-risk domains saved to high_risk_domains.json"
        )

    return potential_phishing


if __name__ == "__main__":
    file_path = (
        "zoneFile\\part-00003-a00ba7e9-88f5-4c53-8aa8-c1a0f47dc2bb.c000.gz.parquet"
    )
    output_excel = True  # Define output_excel with a default value
    process_parquet(file_path)
