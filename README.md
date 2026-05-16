# 🎯 Origin Hunter

**Origin Hunter** is a powerful reconnaissance tool designed to uncover the **real origin IP address** of web applications hidden behind Content Delivery Networks (CDNs), 
Web Application Firewalls (WAFs), or reverse proxies like Cloudflare, Akamai, and Sucuri.

When a website uses a CDN, its true server IP is masked – but misconfigurations, historical records, or forgotten subdomains often leak the origin. 
This tool automates the discovery process using multiple proven techniques, giving security professionals and penetration testers a reliable way to map attack surfaces during authorized assessments.

## ✨ Key Features

- 🕵️ **Historical DNS Lookups** – Checks ViewDNS.info & SecurityTrails for old A records that predate CDN activation.
- 🔐 **SSL Certificate Transparency** – Queries crt.sh and Censys to find IPs linked to the target's certificates.
- 🌐 **Subdomain Enumeration** – Discovers forgotten subdomains (dev, admin, mail) that often bypass CDN protection.
- 🖼️ **Favicon Hashing** – Matches the target's favicon hash against Shodan to locate servers using identical icons.
- 📧 **Email Header Analysis** – Extracts origin IPs from `Received` and `X-Originating-IP` headers in email files.
- ✅ **Origin Verification** – Actively probes candidate IPs with the correct `Host` header to confirm they serve the target.

## 🛡️ Use Cases

- **Bug Bounty Hunting** – Find hidden origin IPs to expand your testing scope.
- **Penetration Testing** – Identify exposed backend servers behind WAFs.
- **Infrastructure Auditing** – Verify that CDN/WAF configurations properly hide origin IPs.

> ⚠️ **Important**: This tool is for **educational purposes and authorized security testing only**. Unauthorized use against systems you do not own or have explicit permission to test may violate laws and regulations.
