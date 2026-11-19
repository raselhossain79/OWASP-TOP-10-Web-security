# Command Reference — By Testing Phase

A single lookup table mapping framework phase to the representative command,
linking back to the module with full flag explanations. Use this as a fast index,
not as a replacement for reading the module before running a command for the
first time.

| Phase | Representative Command | Full Explanation In |
|---|---|---|
| Subdomain enum | `subfinder -d target.com -silent -o subs.txt` | 02-Asset-Discovery/subdomain-enumeration.md |
| Live host check | `cat subs.txt \| httpx -silent -status-code -title` | 02-Asset-Discovery/live-host-discovery.md |
| Port scan | `nmap -p- --min-rate 1000 -T4 target.com` | 02-Asset-Discovery/port-service-enumeration.md |
| Tech fingerprint | `whatweb -a 3 https://target.com` | 02-Asset-Discovery/technology-fingerprinting.md |
| Origin IP check | `openssl s_client -connect target.com:443 -servername target.com` | 03-Origin-Infrastructure/origin-ip-discovery.md |
| WAF/CDN ID | `wafw00f https://target.com` | 03-Origin-Infrastructure/cdn-waf-identification.md |
| Endpoint discovery | `ffuf -u https://target.com/FUZZ -w wordlist.txt` | 04-Attack-Surface-Mapping/endpoint-discovery.md |
| Parameter discovery | `arjun -u https://target.com/profile -m GET` | 04-Attack-Surface-Mapping/parameter-discovery.md |
| JS analysis | `katana -u https://target.com -jc` | 04-Attack-Surface-Mapping/javascript-analysis.md |
| SQLi — error-based | `curl "https://target.com/item?id=14'"` | 06-Vulnerability-Testing/sqli.md |
| SQLi — time-based | `curl "https://target.com/item?id=14 AND SLEEP(5)"` | 06-Vulnerability-Testing/sqli.md |
| XSS — reflection check | `curl "https://target.com/search?q=xsstest12345"` | 06-Vulnerability-Testing/xss.md |
| SSRF — listener test | `nc -lvp 80` (then submit your listener's URL to the target feature) | 06-Vulnerability-Testing/ssrf.md |
| IDOR — cross-account check | `curl ".../orders/105" -H "Cookie: session=<OTHER_USER>"` | 06-Vulnerability-Testing/idor.md |
| WAF fingerprint (deep) | `wafw00f https://target.com -v` | 07-WAF-and-Filter-Analysis/waf-detection.md |
| Auth — username enumeration | `curl -s -i -X POST .../login -d "username=...&password=..."` | 06-Vulnerability-Testing/authentication.md |
| Broken access control | `curl -s -i https://target.com/api/admin/reports -H "Cookie: session=<LOW_PRIV>"` | 06-Vulnerability-Testing/broken-access-control.md |
| File upload probe | `curl -s -F "file=@test.svg;type=image/svg+xml" .../upload` | 06-Vulnerability-Testing/file-upload.md |
| Path traversal | `curl -s ".../download?file=../../../../etc/passwd"` | 06-Vulnerability-Testing/path-traversal-lfi.md |
| SSTI probe | `curl -s -X POST .../preview -d "bio={{7*7}}"` | 06-Vulnerability-Testing/ssti.md |
| XXE probe | `curl -s -X POST .../import -H "Content-Type: application/xml" --data-binary @xxe_test.xml` | 06-Vulnerability-Testing/xxe.md |
| CORS check | `curl -s -i .../api/account/details -H "Origin: https://evil-test.example"` | 06-Vulnerability-Testing/cors.md |
| Open redirect | `curl -s -i ".../login?return_to=https://evil-test.example"` | 06-Vulnerability-Testing/open-redirect.md |

## Reminder
Every command here assumes the scope/authorization check in
`01-Scope-and-Authorization.md` has already been done for the target in question.
