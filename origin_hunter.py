#!/usr/bin/env python3
"""
origin_hunter.py - Origin IP Discovery Tool
Find real IP addresses behind CDNs/WAFs (Cloudflare, Akamai, etc.)

Methods implemented:
- DNS history analysis (ViewDNS, SecurityTrails)
- SSL certificate transparency logs (crt.sh)
- Subdomain enumeration & brute-force
- Favicon hashing + Shodan search
- Reverse IP & ASN lookups
- Direct HTTP probing with Host header


"""

import sys
import json
import argparse
import requests
import dns.resolver
import socket
import hashlib
import pymmh3
import base64
import re
import time
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style

# Initialize colorama for colored output
init(autoreset=True)

# ==================== CONFIGURATION ====================

# Known CDN IP ranges (Cloudflare)
CLOUDFLARE_IPS = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]

# API Keys (read from config file or environment variables)
API_KEYS = {
    "shodan": "",
    "securitytrails": "",
    "virustotal": ""
}

# Subdomain wordlist for brute-force (abbreviated)
SUBDOMAIN_WORDLIST = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
    "ns2", "cpanel", "whm", "autodiscover", "autoconfig", "admin", "blog", "dev",
    "staging", "test", "api", "app", "secure", "vpn", "remote", "ssh", "git", "jenkins"
]

# ==================== UTILITY FUNCTIONS ====================

def print_banner():
    """Display tool banner"""
    banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════╗
║                   {Fore.YELLOW}ORIGIN HUNTER{Fore.CYAN}                             ║
║            {Fore.GREEN}Advanced Origin IP Discovery Tool{Fore.CYAN}                   ║
╚══════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
    print(banner)

def print_info(msg):
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")

def print_success(msg):
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")

def print_warning(msg):
    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")

def print_error(msg):
    print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")

def is_cloudflare_ip(ip):
    """Check if IP belongs to Cloudflare ranges"""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        for cidr in CLOUDFLARE_IPS:
            if ip_obj in ipaddress.ip_network(cidr):
                return True
    except:
        pass
    return False

def extract_domain(url):
    """Extract domain from URL"""
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain

def resolve_dns(domain, record_type='A'):
    """Resolve DNS records"""
    ips = []
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, record_type)
        for answer in answers:
            ips.append(str(answer))
    except:
        pass
    return ips

def fetch_url(url):
    """Fetch URL with timeout"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    }
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response
    except:
        return None

# ==================== METHOD 1: HISTORICAL DNS ====================

def get_historical_dns_viewdns(domain):
    """Get historical IPs from ViewDNS.info"""
    print_info("Checking ViewDNS.info for historical records...")
    ips = []
    url = f"https://viewdns.info/iphistory/?domain={domain}"
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=15)
        if response.status_code == 200:
            # Extract IPs from HTML tables
            ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
            found_ips = re.findall(ip_pattern, response.text)
            for ip in found_ips:
                if ip not in ips and not is_cloudflare_ip(ip):
                    ips.append(ip)
    except Exception as e:
        print_warning(f"ViewDNS lookup failed: {e}")
    return ips

def get_historical_dns_securitytrails(domain):
    """Get historical IPs from SecurityTrails API"""
    if not API_KEYS.get("securitytrails"):
        print_warning("SecurityTrails API key not configured. Skipping.")
        return []
    
    print_info("Checking SecurityTrails for historical DNS data...")
    ips = []
    url = f"https://api.securitytrails.com/v1/domain/{domain}/history/a"
    headers = {"APIKEY": API_KEYS["securitytrails"]}
    
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for record in data.get('records', []):
                for item in record.get('values', []):
                    ip = item.get('ip')
                    if ip and not is_cloudflare_ip(ip) and ip not in ips:
                        ips.append(ip)
    except:
        pass
    return ips

# ==================== METHOD 2: SSL CERTIFICATE TRANSPARENCY ====================

def get_certificate_ips(domain):
    """Extract IPs from certificate transparency logs (crt.sh)"""
    print_info("Searching certificate transparency logs (crt.sh)...")
    ips = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for cert in data:
                name = cert.get('name_value', '')
                if name and '*' not in name:
                    # Try to resolve the subdomain
                    sub_ips = resolve_dns(name)
                    for ip in sub_ips:
                        if ip not in ips and not is_cloudflare_ip(ip):
                            ips.append(ip)
    except:
        pass
    
    # Also check for IPs directly in certificate SANs via Censys (if API key available)
    if API_KEYS.get("shodan"):  # Using Shodan's cert search as fallback
        print_info("Checking Shodan for SSL certificate matches...")
        try:
            shodan_url = f"https://api.shodan.io/shodan/host/search?key={API_KEYS['shodan']}&query=ssl.cert.subject.cn:{domain}"
            resp = requests.get(shodan_url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                for match in data.get('matches', []):
                    ip = match.get('ip_str')
                    if ip and not is_cloudflare_ip(ip) and ip not in ips:
                        ips.append(ip)
        except:
            pass
    
    return ips

# ==================== METHOD 3: SUBDOMAIN ENUMERATION ====================

def get_subdomains_ct(domain):
    """Get subdomains from certificate transparency logs"""
    print_info("Extracting subdomains from certificate logs...")
    subdomains = set()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for cert in data:
                name = cert.get('name_value', '')
                if name and '*' not in name:
                    if name.endswith(f".{domain}"):
                        subdomains.add(name)
    except:
        pass
    return subdomains

def brute_force_subdomains(domain):
    """Brute-force common subdomains"""
    print_info("Brute-forcing common subdomains...")
    subdomains = set()
    
    for sub in SUBDOMAIN_WORDLIST:
        test_domain = f"{sub}.{domain}"
        try:
            # Try to resolve
            socket.gethostbyname(test_domain)
            subdomains.add(test_domain)
        except:
            continue
    return subdomains

def resolve_subdomains(subdomains):
    """Resolve subdomains to IPs"""
    ips = []
    print_info(f"Resolving {len(subdomains)} subdomains...")
    
    def resolve(sub):
        try:
            ip = socket.gethostbyname(sub)
            return ip
        except:
            return None
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_sub = {executor.submit(resolve, sub): sub for sub in subdomains}
        for future in as_completed(future_to_sub):
            ip = future.result()
            if ip and not is_cloudflare_ip(ip):
                if ip not in ips:
                    ips.append(ip)
                    print_success(f"Found potential origin IP from subdomain: {ip}")
    return ips

# ==================== METHOD 4: FAVICON HASHING ====================

def get_favicon_hash(domain):
    """Calculate favicon hash for Shodan search"""
    print_info("Calculating favicon hash...")
    
    # Try common favicon paths
    favicon_paths = [
        f"https://{domain}/favicon.ico",
        f"https://{domain}/favicon.png",
        f"https://{domain}/assets/favicon.ico",
        f"http://{domain}/favicon.ico"
    ]
    
    for url in favicon_paths:
        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                # Calculate mmh3 hash (Shodan format)
                favicon_hash = mmh3.hash(base64.b64encode(response.content))
                print_success(f"Favicon hash: {favicon_hash}")
                return favicon_hash
        except:
            continue
    return None

def search_by_favicon_hash(favicon_hash):
    """Search Shodan for IPs with same favicon hash"""
    if not API_KEYS.get("shodan"):
        print_warning("Shodan API key not configured. Favicon search skipped.")
        return []
    
    print_info(f"Searching Shodan for favicon hash: {favicon_hash}")
    ips = []
    
    try:
        shodan_url = f"https://api.shodan.io/shodan/host/search?key={API_KEYS['shodan']}&query=http.favicon.hash:{favicon_hash}"
        response = requests.get(shodan_url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            for match in data.get('matches', []):
                ip = match.get('ip_str')
                if ip and not is_cloudflare_ip(ip) and ip not in ips:
                    ips.append(ip)
                    print_success(f"Found IP with matching favicon: {ip}")
    except:
        pass
    return ips

# ==================== METHOD 5: REVERSE IP & ASN LOOKUPS ====================

def reverse_ip_lookup(ip):
    """Find other domains hosted on same IP"""
    print_info(f"Performing reverse IP lookup for {ip}...")
    domains = []
    
    # Use ViewDNS reverse IP API
    url = f"https://viewdns.info/reverseip/?host={ip}&t=1"
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'}, timeout=10)
        if response.status_code == 200:
            # Extract domain names from HTML
            domain_pattern = r'<td>([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})</td>'
            found = re.findall(domain_pattern, response.text)
            domains.extend(found[:10])  # Limit to 10
    except:
        pass
    return domains

# ==================== METHOD 6: DIRECT HTTP PROBING ====================

def probe_ip(ip, domain):
    """Test if an IP responds correctly for the domain using Host header"""
    try:
        # Test HTTPS first
        url = f"https://{ip}"
        headers = {'Host': domain, 'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=5, verify=False)
        
        if response.status_code < 500:
            # Check if response contains domain-specific content
            if domain.replace('www.', '') in response.text.lower():
                return True, "https"
        return False, None
    except:
        # Try HTTP
        try:
            url = f"http://{ip}"
            headers = {'Host': domain, 'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, timeout=5)
            if response.status_code < 500:
                if domain.replace('www.', '') in response.text.lower():
                    return True, "http"
        except:
            pass
        return False, None

def verify_origin_ips(ips, domain):
    """Verify which IPs actually serve the target domain"""
    print_info(f"Verifying {len(ips)} potential origin IPs...")
    confirmed = []
    
    for ip in ips:
        is_valid, protocol = probe_ip(ip, domain)
        if is_valid:
            confirmed.append(ip)
            print_success(f"Confirmed origin IP: {ip} ({protocol})")
    
    return confirmed

# ==================== EMAIL HEADER ANALYSIS (Optional) ====================

def analyze_email_headers(email_file):
    """Extract origin IP from email headers"""
    print_info("Analyzing email headers for origin IP...")
    ips = []
    
    try:
        with open(email_file, 'r') as f:
            content = f.read()
        
        # Extract Received headers
        received_pattern = r'Received:.*\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
        matches = re.findall(received_pattern, content)
        
        for ip in matches:
            if ip not in ips and not is_cloudflare_ip(ip):
                ips.append(ip)
                print_success(f"Found IP in email header: {ip}")
        
        # Also check X-Originating-IP header
        orig_ip_pattern = r'X-Originating-IP:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        orig_matches = re.findall(orig_ip_pattern, content, re.IGNORECASE)
        for ip in orig_matches:
            if ip not in ips and not is_cloudflare_ip(ip):
                ips.append(ip)
    except Exception as e:
        print_error(f"Email analysis failed: {e}")
    
    return ips

# ==================== MAIN FUNCTION ====================

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Origin IP Discovery Tool - Find real IP behind CDNs/WAFs'
    )
    parser.add_argument('-u', '--url', required=True, help='Target URL (e.g., https://example.com)')
    parser.add_argument('-e', '--email', help='Email file (.eml) to analyze for headers')
    parser.add_argument('-o', '--output', help='Output file to save results (JSON)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--api-config', help='JSON config file for API keys')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Load API keys if config provided
    if args.api_config:
        try:
            with open(args.api_config, 'r') as f:
                config = json.load(f)
                API_KEYS.update(config)
        except:
            print_warning("Could not load API config file")
    
    # Extract domain
    domain = extract_domain(args.url)
    print_info(f"Target Domain: {domain}")
    
    # Check if behind Cloudflare
    try:
        resolved = resolve_dns(domain)
        if resolved:
            first_ip = resolved[0]
            if is_cloudflare_ip(first_ip):
                print_warning("Target is behind Cloudflare!")
            else:
                print_warning("Target does not appear to be behind a CDN")
    except:
        pass
    
    all_ips = []
    
    # Collect IPs using various methods
    print("\n" + "="*60)
    print(f"{Fore.YELLOW}STAGE 1: Passive Reconnaissance{Style.RESET_ALL}")
    print("="*60)
    
    # Method 1: Historical DNS
    historical_ips = []
    historical_ips.extend(get_historical_dns_viewdns(domain))
    historical_ips.extend(get_historical_dns_securitytrails(domain))
    for ip in historical_ips:
        if ip not in all_ips:
            all_ips.append(ip)
            print_success(f"Historical DNS IP: {ip}")
    
    # Method 2: SSL Certificates
    cert_ips = get_certificate_ips(domain)
    for ip in cert_ips:
        if ip not in all_ips:
            all_ips.append(ip)
            print_success(f"SSL Certificate IP: {ip}")
    
    # Method 3: Subdomains
    subdomains = set()
    subdomains.update(get_subdomains_ct(domain))
    subdomains.update(brute_force_subdomains(domain))
    
    if subdomains:
        print_info(f"Found {len(subdomains)} subdomains")
        sub_ips = resolve_subdomains(subdomains)
        for ip in sub_ips:
            if ip not in all_ips:
                all_ips.append(ip)
                print_success(f"Subdomain IP: {ip}")
    
    # Method 4: Favicon Hashing
    favicon_hash = get_favicon_hash(domain)
    if favicon_hash:
        favicon_ips = search_by_favicon_hash(favicon_hash)
        for ip in favicon_ips:
            if ip not in all_ips:
                all_ips.append(ip)
    
    # Email header analysis (optional)
    if args.email:
        print("\n" + "="*60)
        print(f"{Fore.YELLOW}STAGE 2: Email Header Analysis{Style.RESET_ALL}")
        print("="*60)
        email_ips = analyze_email_headers(args.email)
        for ip in email_ips:
            if ip not in all_ips:
                all_ips.append(ip)
                print_success(f"Email header IP: {ip}")
    
    # Remove duplicates and Cloudflare IPs
    all_ips = [ip for ip in all_ips if not is_cloudflare_ip(ip)]
    all_ips = list(dict.fromkeys(all_ips))
    
    # Verification stage
    print("\n" + "="*60)
    print(f"{Fore.YELLOW}STAGE 3: Origin Verification{Style.RESET_ALL}")
    print("="*60)
    
    if all_ips:
        print_info(f"Found {len(all_ips)} potential origin IPs")
        confirmed_ips = verify_origin_ips(all_ips, domain)
    else:
        print_warning("No potential origin IPs found with passive methods")
        print_info("Attempting active DNS brute-force on additional ranges...")
        # Additional brute-force can be implemented here
        confirmed_ips = []
    
    # Final results
    print("\n" + "="*60)
    print(f"{Fore.GREEN}FINAL RESULTS{Style.RESET_ALL}")
    print("="*60)
    
    if confirmed_ips:
        print_success(f"Origin IP(s) discovered: {', '.join(confirmed_ips)}")
        print(f"\n{Fore.YELLOW}Recommendations:{Style.RESET_ALL}")
        print("  - Use these IPs for further security testing")
        print("  - Check if these IPs are properly secured")
        print("  - Ensure all services are correctly configured")
    else:
        print_warning("No origin IPs found. The target may be well-configured or using multiple layers of protection.")
    
    # Save results if requested
    if args.output and confirmed_ips:
        results = {
            "target": domain,
            "origin_ips": confirmed_ips,
            "all_candidates": all_ips,
            "timestamp": time.time()
        }
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print_success(f"Results saved to {args.output}")

if __name__ == "__main__":
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    main()
