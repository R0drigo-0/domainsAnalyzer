import pyarrow.parquet as pq
import pandas as pd
import os
import json
import tldextract
from datetime import datetime


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
    suspicious_keywords = [
        # Financial/Banking
        "login",
        "account",
        "secure",
        "verify",
        "bank",
        "pay",
        "wallet",
        "crypto",
        "payment",
        "invoice",
        "transaction",
        "banking",
        "credit",
        "debit",
        "finance",
        "paypal",
        "billing",
        "checkout",
        "balance",
        "transfer",
        "deposit",
        "withdraw",
        # Authentication/Security
        "support",
        "service",
        "update",
        "confirm",
        "auth",
        "validation",
        "verify",
        "password",
        "recovery",
        "reset",
        "security",
        "protect",
        "access",
        "unlock",
        "authenticate",
        "authorize",
        "verification",
        "identity",
        "trusted",
        "safe",
        # E-commerce
        "shop",
        "store",
        "order",
        "track",
        "shipping",
        "delivery",
        "purchase",
        "customer",
        "refund",
        "discount",
        "deal",
        "offer",
        "cart",
        "buy",
        "sale",
        # Email/Communication
        "mail",
        "webmail",
        "inbox",
        "message",
        "notification",
        "alert",
        "confirm",
        "subscribe",
        "newsletter",
        "contact",
        "help",
        "chat",
        "support",
        # Common actions
        "sign",
        "signin",
        "signup",
        "register",
        "submit",
        "renew",
        "extend",
        "activate",
        "reactivate",
        "upgrade",
        "manage",
        "suspend",
        "blocked",
        "limited",
        "restore",
        "recover",
        "fix",
        "repair",
        # Urgency terms
        "expire",
        "expiry",
        "urgent",
        "important",
        "alert",
        "warning",
        "limited",
        "notice",
        "critical",
        "immediate",
        "deadline",
        "required",
        "mandatory",
        "suspended",
        "locked",
        "disabled",
        "restricted",
        "compromised",
        # Government/Official
        "gov",
        "tax",
        "revenue",
        "official",
        "legal",
        "form",
        "document",
        "license",
        "permit",
        "certificate",
        "statement",
        "record",
        "file",
        "claim",
        "benefit",
        # Tech platforms
        "cloud",
        "storage",
        "drive",
        "sync",
        "connect",
        "app",
        "portal",
        "panel",
        "dashboard",
        "platform",
        "profile",
        "setting",
        "preference",
        "subscription",
        # Cryptocurrency
        "bitcoin",
        "eth",
        "ethereum",
        "wallet",
        "crypto",
        "token",
        "coin",
        "mining",
        "exchange",
        "blockchain",
        "nft",
        "defi",
        "stake",
        "yield",
        "liquidity",
        # Social engineering
        "prize",
        "winner",
        "reward",
        "bonus",
        "gift",
        "voucher",
        "coupon",
        "free",
        "grant",
        "compensation",
        "survey",
        "questionnaire",
        "feedback",
        "review",
        # Technical combinations
        "web-access",
        "online-banking",
        "user-portal",
        "client-area",
        "member-login",
        "account-verify",
        "password-reset",
        "security-check",
        "identity-confirm",
        "payment-update",
        "billing-info",
        "verification-required",
    ]

    brands = ["google", "facebook", "paypal", "amazon", "apple", "microsoft", "netflix"]

    # Process the file in batches
    parquet_file = pq.ParquetFile(file_path)
    total_records = 0

    for batch_idx, batch in enumerate(parquet_file.iter_batches(batch_size=batch_size)):
        df = batch.to_pandas()
        batch_size = len(df)
        total_records += batch_size
        print(f"Batch {batch_idx+1}: {batch_size} records (total: {total_records})")

        # Process A records (IP addresses)
        a_records = df[df["query_type"] == "A"]
        for _, row in a_records.iterrows():
            if pd.notna(row.get("ip4_address")):
                domain = row["query_name"].rstrip(".")
                ip = row["ip4_address"]
                ttl = row.get("response_ttl", 0)
                timestamp = row.get("timestamp", 0)

                # Store domain info
                if domain not in domains:
                    domains[domain] = {
                        "ips": set(),
                        "nameservers": set(),
                        "mail_servers": set(),
                        "first_seen": timestamp,
                        "record_types": set(),
                        "ttl": [],
                        "keywords": set(),
                    }

                domains[domain]["ips"].add(ip)
                domains[domain]["ttl"].append(ttl)
                domains[domain]["record_types"].add("A")

                # Map IP to domain
                if ip not in ip_to_domains:
                    ip_to_domains[ip] = set()
                ip_to_domains[ip].add(domain)

                # Check domain name for suspicious keywords
                ext = tldextract.extract(domain)
                base_domain = ext.domain.lower()

                for keyword in suspicious_keywords:
                    if keyword in base_domain:
                        domains[domain]["keywords"].add(keyword)
                        if keyword not in keywords_found:
                            keywords_found[keyword] = set()
                        keywords_found[keyword].add(domain)

                for brand in brands:
                    if brand in base_domain and brand != base_domain:
                        domains[domain]["keywords"].add(f"brand:{brand}")
                        if "brand_impersonation" not in keywords_found:
                            keywords_found["brand_impersonation"] = set()
                        keywords_found["brand_impersonation"].add(domain)

        # Process NS records
        ns_records = df[df["query_type"] == "NS"]
        for _, row in ns_records.iterrows():
            if pd.notna(row.get("ns_address")):
                domain = row["query_name"].rstrip(".")
                ns = row["ns_address"].rstrip(".")

                if domain in domains:
                    domains[domain]["nameservers"].add(ns)
                    domains[domain]["record_types"].add("NS")

        # Process MX records
        mx_records = df[df["query_type"] == "MX"]
        for _, row in mx_records.iterrows():
            if pd.notna(row.get("mx_address")):
                domain = row["query_name"].rstrip(".")
                mx = row["mx_address"].rstrip(".")

                if domain in domains:
                    domains[domain]["mail_servers"].add(mx)
                    domains[domain]["record_types"].add("MX")

        # Process SOA records
        soa_records = df[df["query_type"] == "SOA"]
        for _, row in soa_records.iterrows():
            domain = row["query_name"].rstrip(".")

            if domain in domains:
                domains[domain]["record_types"].add("SOA")
                if pd.notna(row.get("soa_serial")):
                    domains[domain]["soa_serial"] = row.get("soa_serial")

        # Free memory
        del df

    print(f"Finished processing {total_records} records")
    print(f"Found {len(domains)} unique domains")

    # Find suspicious domains
    suspicious = []

    # Find IP clusters
    ip_clusters = {
        ip: list(doms)
        for ip, doms in ip_to_domains.items()
        if len(doms) >= min_cluster_size
    }

    for domain, info in domains.items():
        # Calculate suspicion score
        score = 0
        reasons = []

        # Check if domain is in an IP cluster
        for ip in info["ips"]:
            if ip in ip_clusters:
                score += 2
                reasons.append(f"Shares IP {ip} with {len(ip_clusters[ip])} domains")
                break

        # Check for suspicious keywords
        if info["keywords"]:
            score += 3
            reasons.append(f"Contains keywords: {', '.join(info['keywords'])}")

        # Check for low TTL
        if any(t < low_ttl_threshold for t in info["ttl"]):
            score += 2
            min_ttl = min(info["ttl"])
            reasons.append(f"Low TTL: {min_ttl}")

        # Check for missing essential records
        if "MX" not in info["record_types"] and "SOA" not in info["record_types"]:
            score += 1
            reasons.append("Missing essential DNS records")

        # If score is high enough, add to suspicious list
        if score >= 5:
            # Convert sets to lists for JSON serialization
            domain_info = {
                "domain": domain,
                "score": score,
                "reasons": reasons,
                "ips": list(info["ips"]),
                "nameservers": list(info["nameservers"]),
                "mail_servers": list(info["mail_servers"]),
                "record_types": list(info["record_types"]),
                "first_seen": info["first_seen"],
                "first_seen_date": datetime.fromtimestamp(
                    info["first_seen"] / 1000
                ).strftime("%Y-%m-%d %H:%M:%S"),
                "keywords": list(info["keywords"]),
            }

            suspicious.append(domain_info)

    # Sort by score
    suspicious.sort(key=lambda x: x["score"], reverse=True)
    print(f"Found {len(suspicious)} suspicious domains")

    # Prepare output
    results = {
        "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_domains": len(domains),
        "suspicious_domains": suspicious,
        "ip_clusters": ip_clusters,
        "keyword_stats": {k: len(v) for k, v in keywords_found.items()},
    }

    # Save to file
    output_file = "phishing_analysis.json"
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)

    print(f"Results saved to {output_file}")

    # Print top results
    if suspicious:
        print("\nTop suspicious domains:")
        for domain in suspicious[:5]:
            print(f"- {domain['domain']} (Score: {domain['score']})")
            print(f"  Reasons: {', '.join(domain['reasons'])}")
            print(f"  IPs: {', '.join(domain['ips'])}")

    return suspicious


if __name__ == "__main__":
    file_path = (
        "zoneFile\\part-00003-a00ba7e9-88f5-4c53-8aa8-c1a0f47dc2bb.c000.gz.parquet"
    )
    process_parquet(file_path)
