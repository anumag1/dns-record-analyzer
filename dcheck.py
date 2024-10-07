import dns.resolver
import argparse
from typing import List, Tuple, Optional

POSSIBLE_SELECTORS = ["default", "selector1", "selector2", "mail",
                      "google", "smtp", "dmarc", "newsletter",
                      "mailgun", "sendgrid", "postmark", "amazonses",
                      'ggl', 'goo', "selector3", "selector4",
                      "test", "production", "bounce", "transactional",
                      "support", "notifications", "billing", "campaign",
                      "sales", "user", "info", "alerts"]
DNS_RECORD_TYPE_TXT = 'TXT'
DNS_RECORD_TYPE_MX = 'MX'
DNS_RECORD_TYPE_DNSKEY = 'DNSKEY'


def get_dns_record(domain: str, record_type: str) -> Optional[List[str]]:
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        return None
    except Exception as e:
        return [str(e)]


def analyze_mx(domain: str) -> Tuple[List[str], List[str]]:
    mx_records = get_dns_record(domain, DNS_RECORD_TYPE_MX)
    vulnerabilities = []
    if not mx_records:
        vulnerabilities.append("No MX records found.")
    else:
        if len(mx_records) == 1:
            vulnerabilities.append("Only one MX record found.")
    return mx_records, vulnerabilities


def analyze_spf(spf_record: Optional[str]) -> Tuple[List[str], List[str]]:
    vulnerabilities = []
    authorized_sources = []
    if not spf_record:
        vulnerabilities.append("SPF record is missing.")
    else:
        if "v=spf1" not in spf_record:
            vulnerabilities.append("SPF record version is not specified.")
        if "+all" in spf_record:
            vulnerabilities.append("SPF record allows any server to send emails (+all).")
        if "~all" in spf_record:
            vulnerabilities.append("SPF record has softfail (~all).")
        mechanisms = spf_record.split()
        for mechanism in mechanisms:
            if mechanism.startswith("include:"):
                included_domain = mechanism.split(":")[1]
                authorized_sources.append(f"Including domain: {included_domain}")
            elif mechanism.startswith("ip4:"):
                ip4_address = mechanism.split(":")[1]
                authorized_sources.append(f"Authorized IP (IPv4): {ip4_address}")
            elif mechanism.startswith("ip6:"):
                ip6_address = mechanism.split(":")[1]
                authorized_sources.append(f"Authorized IP (IPv6): {ip6_address}")
            elif mechanism.startswith("a"):
                authorized_sources.append("Authorizing all A records of the domain.")
            elif mechanism.startswith("mx"):
                authorized_sources.append("Authorizing MX records of the domain.")
    return authorized_sources, vulnerabilities


def analyze_dkim(domain: str) -> Tuple[List[str], List[str]]:
    dkim_records = []
    vulnerabilities = []
    for selector in POSSIBLE_SELECTORS:
        dkim_selector = f'{selector}._domainkey.{domain}'
        dkim_record = get_dns_record(dkim_selector, DNS_RECORD_TYPE_TXT)
        if dkim_record:
            if any("v=DKIM1" in record for record in dkim_record):
                dkim_records.append(f"DKIM record for selector {selector}: {dkim_record}")
    if not dkim_records:
        vulnerabilities.append("No DKIM records found for any selector.")
    return dkim_records, vulnerabilities


def analyze_dmarc(domain: str) -> Tuple[Optional[List[str]], List[str]]:
    dmarc_record = get_dns_record('_dmarc.' + domain, DNS_RECORD_TYPE_TXT)
    vulnerabilities = []
    if not dmarc_record:
        vulnerabilities.append("DMARC record is missing.")
    else:
        for record in dmarc_record:
            if 'p=none' in record:
                vulnerabilities.append("DMARC policy is 'none'. It is recommended to set 'p=quarantine' or 'p=reject'.")
            if 'rua=' not in record:
                vulnerabilities.append("DMARC record does not contain report URI (rua). Reporting allows tracking of email abuse.")
    return dmarc_record, vulnerabilities


def analyze_dnssec(domain: str) -> Tuple[Optional[List[str]], List[str]]:
    dnskey_record = get_dns_record(domain, DNS_RECORD_TYPE_DNSKEY)
    vulnerabilities = []
    if not dnskey_record:
        vulnerabilities.append("DNSSEC is not enabled. No DNSKEY records found.")
    else:
        dnskey_analysis = [f"DNSKEY record: {r}" for r in dnskey_record]
    return dnskey_record, vulnerabilities


def generate_report(domain: str) -> str:
    report = [f"DNS Records Analysis for {domain}:\n"]
    mx_records, mx_vulnerabilities = analyze_mx(domain)
    report.append(f"MX Record(s):\n{chr(10).join(mx_records) if mx_records else 'Not Found'}\n")
    spf_records = get_dns_record(domain, DNS_RECORD_TYPE_TXT)
    spf_record = next((txt for txt in spf_records if "v=spf1" in txt), None) if spf_records else None
    report.append(f"SPF Record(s):\n{spf_record or 'Not Found'}\n")
    authorized_sources, spf_vulnerabilities = analyze_spf(spf_record)
    if authorized_sources:
        report.append(f"Authorized senders/IPs from SPF record:\n{chr(10).join(authorized_sources)}\n")
    dkim_records, dkim_vulnerabilities = analyze_dkim(domain)
    report.append(f"DKIM Record(s):\n{chr(10).join(dkim_records) if dkim_records else 'No DKIM records found'}\n")
    dmarc_record, dmarc_vulnerabilities = analyze_dmarc(domain)
    report.append(f"DMARC Record(s):\n{dmarc_record[0] if dmarc_record else 'Not Found'}\n")
    dnskey_record, dnssec_vulnerabilities = analyze_dnssec(domain)
    report.append(f"DNSSEC Record(s):\n{chr(10).join(dnskey_record) if dnskey_record else 'Not Found'}\n")
    report.append("\nPossible vulnerabilities:\n")
    if mx_vulnerabilities:
        report.extend(mx_vulnerabilities)
    if spf_vulnerabilities:
        report.extend(spf_vulnerabilities)
    if dkim_vulnerabilities:
        report.extend(dkim_vulnerabilities)
    if dmarc_vulnerabilities:
        report.extend(dmarc_vulnerabilities)
    if dnssec_vulnerabilities:
        report.extend(dnssec_vulnerabilities)
    if not any([mx_vulnerabilities, spf_vulnerabilities, dkim_vulnerabilities, dmarc_vulnerabilities, dnssec_vulnerabilities]):
        report.append("No vulnerabilities found.")
    return "\n".join(report)


def parse_arguments():
    parser = argparse.ArgumentParser(description='Analyze DNS records for a given domain.')
    parser.add_argument('domain', type=str, help='The domain to analyze')
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    domain = args.domain
    report = generate_report(domain)
    print(report)
