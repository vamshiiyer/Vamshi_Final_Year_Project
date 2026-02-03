from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import requests
import nmap
from urllib.parse import urlparse
import uvicorn

app = FastAPI(title="Automated Vulnerability Assessment")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

SECURITY_CHECKS = {
    "content-security-policy": ("Missing Content Security Policy", "HIGH", 20),
    "strict-transport-security": ("HSTS not enabled", "HIGH", 20),
    "x-frame-options": ("Clickjacking protection missing", "MEDIUM", 10),
    "x-content-type-options": ("MIME sniffing protection missing", "LOW", 5),
    "referrer-policy": ("Referrer policy missing", "LOW", 5),
    "permissions-policy": ("Permissions Policy missing", "LOW", 5),
}

def analyze_headers(url):
    findings = []
    score = 100

    try:
        r = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 SecurityScanner"}
        )

        headers = {k.lower(): v for k, v in r.headers.items()}

        if not url.startswith("https"):
            findings.append({
                "name": "Insecure Transport (HTTP)",
                "severity": "CRITICAL",
                "solution": "Enforce HTTPS and enable HSTS"
            })
            score -= 30

        for header, (name, severity, penalty) in SECURITY_CHECKS.items():
            if header not in headers:
                findings.append({
                    "name": name,
                    "severity": severity,
                    "solution": f"Configure {header} header"
                })
                score -= penalty

        if "server" in headers and any(c.isdigit() for c in headers["server"]):
            findings.append({
                "name": "Server Version Disclosure",
                "severity": "MEDIUM",
                "solution": "Hide server version information"
            })
            score -= 10

    except Exception:
        return [{
            "name": "Target Unreachable",
            "severity": "CRITICAL",
            "solution": "Ensure the target is reachable"
        }], 20

    return findings, max(score, 15)

def scan_ports(target):
    ports = []
    try:
        host = urlparse(target).hostname
        nm = nmap.PortScanner()
        nm.scan(host, arguments="-F --open")

        if host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port, data in nm[host][proto].items():
                    if data["state"] == "open":
                        ports.append(port)
    except:
        pass

    return ports

@app.get("/scan")
def scan(target: str):
    if not target.startswith("http"):
        target = "http://" + target

    findings, score = analyze_headers(target)
    ports = scan_ports(target)

    risk = (
        "CRITICAL" if score < 30 else
        "HIGH" if score < 60 else
        "LOW"
    )

    return {
        "target": target,
        "score": score,
        "risk_level": risk,
        "ports": ports,
        "findings": findings,
        "assessment_type": "Passive + Semi-Active (OWASP Aligned)"
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)


