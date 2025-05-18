import requests
import argparse
import urllib.parse
import re
import json
import time
import socket
import concurrent.futures
import ssl
from transformers import pipeline
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    )
}

DIRS_TO_CHECK = [
    "/", "/admin/", "/uploads/", "/files/", "/backup/",
    "/config/", "/.git/", "/.svn/", "/private/", "/data/",
    "/logs/", "/test/", "/tmp/", "/old/", "/dev/", "/secret/",
    "/hidden/", "/config_backup/", "/database_backup/"
]

SENSITIVE_FILES = [
    ".env", "config.php", ".git/index", "phpinfo.php",
    "backup.zip", "db.sql", "config.bak", "id_rsa", "id_rsa.pub",
    "wp-config.php", "wp-config.bak", "database.sql"
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><script>alert(2)</script>",
    "\"><img src=x onerror=alert(3)>",
    "<svg/onload=alert(4)>",
    "<body/onload=alert(5)>",
    "';alert(6);//",
    "\";alert(7);//"
]

ERROR_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"Unclosed quotation mark after the character string",
        r"Microsoft OLE DB Provider for SQL Server",
        r"syntax error",
        r"Unexpected end of SQL command",
        r"ORA-\d{5}",
        r"Exception",
        r"Fatal error",
        r"Stack trace",
        r"Traceback most recent call last:",
        r"PDOException",
        r"could not find driver",
        r"mysql_fetch_assoc()",
        r"mysql_num_rows()"
    ]
]

TIMEOUT = 10
MAX_WORKERS = 20

nlp = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")

session = requests.Session()
retry = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[500, 502, 503, 504]
)
adapter = HTTPAdapter(max_retries=retry)
session.mount("http://", adapter)
session.mount("https://", adapter)


def request_url(url):
    try:
        r = session.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, allow_redirects=True)
        return r.status_code, r.text
    except requests.RequestException:
        return None, ""


def detect_directory_listing(url):
    code, content = request_url(url)
    if code == 200:
        keys = ["index of", "parent directory", "directory listing", "apache", "nginx"]
        content_lc = content.lower()
        for k in keys:
            if k in content_lc:
                return url
    return None


def detect_sensitive_file(url):
    code, content = request_url(url)
    if code == 200 and len(content) > 50:
        return url
    return None


def detect_xss(base_url, payload):
    test_url = f"{base_url}?q={urllib.parse.quote(payload)}"
    code, content = request_url(test_url)
    if code == 200 and payload in content:
        return test_url
    return None


def detect_error_messages(base_url):
    test_url = f"{base_url}/?id='"
    code, content = request_url(test_url)
    if code != 200 or not content:
        return []
    matches = []
    for pattern in ERROR_PATTERNS:
        for m in pattern.finditer(content):
            snippet = content[m.start():m.start() + 200]
            analysis = nlp(snippet[:512])
            matches.append({
                "pattern": pattern.pattern,
                "snippet": snippet,
                "ai_label": analysis[0]['label'],
                "ai_score": round(analysis[0]['score'], 3)
            })
    return matches


def dns_lookup(hostname):
    try:
        ips = socket.gethostbyname_ex(hostname)[2]
        return ips
    except socket.gaierror:
        return []


def ssl_certificate_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            return cert
    except Exception:
        return None


def cloudflare_protection_check(url):
    try:
        r = session.get(url, headers=HEADERS, timeout=TIMEOUT, verify=False, allow_redirects=True)
        if "cloudflare" in r.headers.get("Server", "").lower():
            return True
        if "cf-ray" in r.headers:
            return True
        if "cloudflare" in r.text.lower():
            return True
        return False
    except:
        return False


def parallel_check_urls(urls, func, *args):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(func, url, *args): url for url in urls}
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
    return results


def main():
    parser = argparse.ArgumentParser(description="AI-Powered Advanced Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL (http(s)://...)")
    args = parser.parse_args()
    base_url = args.url.rstrip('/')

    parsed = urllib.parse.urlparse(base_url)
    hostname = parsed.hostname

    dir_urls = [urllib.parse.urljoin(base_url + '/', d.lstrip('/')) for d in DIRS_TO_CHECK]
    sensitive_urls = [urllib.parse.urljoin(base_url + '/', f) for f in SENSITIVE_FILES]

    report = {
        "target": base_url,
        "dns": dns_lookup(hostname),
        "ssl_certificate": ssl_certificate_info(hostname),
        "cloudflare_protection": cloudflare_protection_check(base_url),
        "directory_listing": parallel_check_urls(dir_urls, detect_directory_listing),
        "sensitive_files": parallel_check_urls(sensitive_urls, detect_sensitive_file),
        "xss_vulnerabilities": [],
        "error_messages": detect_error_messages(base_url)
    }

    xss_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(detect_xss, base_url, payload) for payload in XSS_PAYLOADS]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                xss_results.append(res)
    report["xss_vulnerabilities"] = xss_results

    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()

