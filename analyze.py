from datetime import datetime
import pyarrow.parquet as pq
import pandas as pd
import json
import os

from datetime import datetime
import dns.resolver
import tldextract
import requests
import socket
import struct
import whois
import ssl
import json


def read_json(file_path, keyword: str = None):
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

    dns_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
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
            (
                (datetime.now() - whois_data.creation_date[0])
                if isinstance(whois_data.creation_date, list)
                else (datetime.now() - whois_data.creation_date)
            ).days
            if whois_data.creation_date
            else None
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
    domain_info["security_checks"] = {
        "is_newly_registered": (
            domain_info["whois_info"].get("age_days", 365) < 30
            if "age_days" in domain_info["whois_info"]
            else None
        ),
        "has_ssl": "ssl_info_error" not in domain_info,
        "uses_cloudflare": (
            any(
                "cloudflare" in str(v).lower()
                for k, v in domain_info.get("http_info", {})
                .get("https", {})
                .get("headers", {})
                .items()
            )
            if "https" in domain_info.get("http_info", {})
            else False
        ),
        "suspicious_tld": extract_result.suffix
        in [".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz"],
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

    # Check traceroute information
    try:
        import subprocess

        if os.name == "nt":  # Windows
            output = subprocess.check_output(
                ["tracert", "-d", "-w", "500", "-h", "10", ip],
                stderr=subprocess.STDOUT,
                timeout=15,
            )
        else:  # Linux/Mac
            output = subprocess.check_output(
                ["traceroute", "-n", "-w", "1", "-m", "10", ip],
                stderr=subprocess.STDOUT,
                timeout=15,
            )

        output_str = output.decode("utf-8", errors="ignore")
        ip_info["network_info"]["traceroute"] = output_str
    except Exception as e:
        ip_info["network_info"]["traceroute_error"] = str(e)

    return ip_info


def process_parquet(file_path, batch_size=5000):
    file_path = os.path.normpath(file_path)

    if not os.path.exists(file_path):
        print(f"Error: File not found: {file_path}")
        return None

    print(f"Processing {file_path}")

    # Configuration
    min_cluster_size = 5
    low_ttl_threshold = 300

    # Data collectors
    domains = {}
    ip_to_domains = {}
    keywords_found = {}

    # Lists of suspicious patterns
    suspicious_keywords = read_json("suspicious_keywords.json", "keywords")

    brands = ["google", "facebook", "paypal", "amazon", "apple", "microsoft", "netflix"]

    # Process the file in batches
    parquet_file = pq.ParquetFile(file_path)
    total_records = 0

    for batch_idx, batch in enumerate(parquet_file.iter_batches(batch_size=batch_size)):
        df = batch.to_pandas()
        batch_size = len(df)
        total_records += batch_size
        print(f"Batch {batch_idx+1}: {batch_size} records (total: {total_records})")
        print(df.head())


if __name__ == "__main__":
    file_path = (
        "zoneFile\\part-00003-a00ba7e9-88f5-4c53-8aa8-c1a0f47dc2bb.c000.gz.parquet"
    )
    process_parquet(file_path)
