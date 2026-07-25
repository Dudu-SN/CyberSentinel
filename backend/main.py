from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
import httpx
import ssl
import socket
import ipaddress
from urllib.parse import urlparse
import dns.resolver
from datetime import datetime, timezone


# ============================================================
# APP CONFIGURATION
# ============================================================

app = FastAPI(
    title="CyberSentinel",
    description="Defensive website security posture monitoring API",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# ============================================================
# REQUEST MODEL
# ============================================================

class ScanRequest(BaseModel):
    url: HttpUrl


# ============================================================
# SECURITY HEADERS
# ============================================================

SECURITY_HEADERS = {
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "severity": "high",
        "advice": (
            "Add a suitable Content-Security-Policy to reduce "
            "browser-side injection risks."
        ),
    },
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "severity": "medium",
        "advice": (
            "Enable HSTS after confirming HTTPS is correctly "
            "configured across the site."
        ),
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "low",
        "advice": "Set X-Content-Type-Options to nosniff.",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "advice": "Set an appropriate Referrer-Policy.",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "advice": (
            "Define a suitable Permissions-Policy for browser "
            "features."
        ),
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "advice": (
            "Set X-Frame-Options or an appropriate CSP "
            "frame-ancestors policy."
        ),
    },
}


def check_headers(headers):
    """
    Check common HTTP security headers.
    """

    findings = []
    present_headers = []

    normalized_headers = {
        key.lower(): value
        for key, value in headers.items()
    }

    for key, info in SECURITY_HEADERS.items():

        if key in normalized_headers:
            present_headers.append(info["name"])

        else:
            findings.append(
                {
                    "title": f"Missing {info['name']}",
                    "severity": info["severity"],
                    "advice": info["advice"],
                }
            )

    return findings, present_headers


# ============================================================
# COOKIE SECURITY
# ============================================================

def check_cookies(response):
    """
    Check Set-Cookie headers for common security attributes.
    """

    findings = []

    try:
        cookies = response.headers.get_list("set-cookie")
    except Exception:
        cookies = []

    for cookie in cookies:

        cookie_lower = cookie.lower()

        # Ignore empty cookie values
        if not cookie.strip():
            continue

        if "secure" not in cookie_lower:

            findings.append(
                {
                    "title": "Cookie missing Secure attribute",
                    "severity": "medium",
                    "advice": (
                        "Review whether sensitive cookies should "
                        "include the Secure attribute."
                    ),
                }
            )

        if "httponly" not in cookie_lower:

            findings.append(
                {
                    "title": "Cookie missing HttpOnly attribute",
                    "severity": "medium",
                    "advice": (
                        "Review whether session or sensitive "
                        "cookies should use HttpOnly."
                    ),
                }
            )

        if "samesite" not in cookie_lower:

            findings.append(
                {
                    "title": "Cookie missing SameSite attribute",
                    "severity": "low",
                    "advice": (
                        "Review whether cookies should explicitly "
                        "define SameSite."
                    ),
                }
            )

    return findings


# ============================================================
# SCORE CALCULATION
# ============================================================

def calculate_score(findings):

    deductions = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
    }

    score = 100

    for finding in findings:

        severity = finding.get("severity", "low")

        score -= deductions.get(severity, 0)

    return max(0, score)


def calculate_risk(score):

    if score >= 90:
        return "LOW"

    if score >= 70:
        return "MODERATE"

    if score >= 40:
        return "HIGH"

    return "CRITICAL"


# ============================================================
# IP / SSRF PROTECTION
# ============================================================

def is_private_or_local_ip(ip_string):

    try:

        ip = ipaddress.ip_address(ip_string)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )

    except ValueError:

        return False


def resolve_hostname(hostname):

    addresses = []

    try:

        results = socket.getaddrinfo(
            hostname,
            None,
            proto=socket.IPPROTO_TCP,
        )

        for result in results:

            address = result[4][0]

            if address not in addresses:
                addresses.append(address)

    except socket.gaierror:
        pass

    return addresses


# ============================================================
# DNS LOOKUP
# ============================================================

def dns_lookup(hostname):

    records = {
        "A": [],
        "AAAA": [],
        "CNAME": [],
        "MX": [],
    }

    record_types = [
        "A",
        "AAAA",
        "CNAME",
        "MX",
    ]

    for record_type in record_types:

        try:

            answers = dns.resolver.resolve(
                hostname,
                record_type,
                lifetime=3,
            )

            for answer in answers:

                if record_type == "MX":

                    records[record_type].append(
                        {
                            "exchange": str(answer.exchange),
                            "preference": answer.preference,
                        }
                    )

                else:

                    records[record_type].append(
                        str(answer)
                    )

        except Exception:
            pass

    return records


# ============================================================
# TLS CHECK
# ============================================================

def tls_check(hostname, port=443):

    result = {
        "available": False,
        "version": None,
        "cipher": None,
        "certificate_subject": None,
        "certificate_issuer": None,
        "certificate_expires": None,
        "days_until_expiry": None,
    }

    try:

        context = ssl.create_default_context()

        with socket.create_connection(
            (hostname, port),
            timeout=5,
        ) as sock:

            with context.wrap_socket(
                sock,
                server_hostname=hostname,
            ) as secure_sock:

                certificate = secure_sock.getpeercert()

                result["available"] = True

                result["version"] = (
                    secure_sock.version()
                )

                cipher = secure_sock.cipher()

                if cipher:
                    result["cipher"] = cipher[0]

                # Certificate subject
                subject = certificate.get(
                    "subject",
                    [],
                )

                for item in subject:

                    for key, value in item:

                        if key == "commonName":

                            result[
                                "certificate_subject"
                            ] = value

                # Certificate issuer
                issuer = certificate.get(
                    "issuer",
                    [],
                )

                issuer_values = []

                for item in issuer:

                    for key, value in item:

                        if key in {
                            "organizationName",
                            "commonName",
                        }:

                            issuer_values.append(
                                value
                            )

                if issuer_values:

                    result[
                        "certificate_issuer"
                    ] = ", ".join(
                        issuer_values
                    )

                # Certificate expiry
                expires = certificate.get(
                    "notAfter"
                )

                if expires:

                    expiry_date = datetime.strptime(
                        expires,
                        "%b %d %H:%M:%S %Y %Z",
                    ).replace(
                        tzinfo=timezone.utc
                    )

                    now = datetime.now(
                        timezone.utc
                    )

                    days_left = (
                        expiry_date - now
                    ).days

                    result[
                        "certificate_expires"
                    ] = expiry_date.isoformat()

                    result[
                        "days_until_expiry"
                    ] = days_left

    except Exception as exc:

        result["error"] = str(exc)

    return result


# ============================================================
# RESPONSE INFORMATION
# ============================================================

def inspect_response(response):

    return {
        "status_code": response.status_code,
        "http_version": response.http_version,
        "final_url": str(response.url),
        "content_type": response.headers.get(
            "content-type"
        ),
        "server": response.headers.get(
            "server"
        ),
        "powered_by": response.headers.get(
            "x-powered-by"
        ),
    }


# ============================================================
# BASIC HTTP SECURITY CHECKS
# ============================================================

def check_http_security(
    parsed_url,
    response,
):

    findings = []

    scheme = parsed_url.scheme.lower()

    # HTTPS
    if scheme != "https":

        findings.append(
            {
                "title": "Target is not using HTTPS",
                "severity": "high",
                "advice": (
                    "Use HTTPS for production web traffic."
                ),
            }
        )

    # HTTP Strict Transport Security
    if scheme == "https":

        hsts = response.headers.get(
            "strict-transport-security"
        )

        if hsts:

            hsts_lower = hsts.lower()

            if "max-age" not in hsts_lower:

                findings.append(
                    {
                        "title": "HSTS header has no max-age",
                        "severity": "medium",
                        "advice": (
                            "Configure a valid HSTS max-age."
                        ),
                    }
                )

    # Server header information
    server_header = response.headers.get("server")

    if server_header:

        findings.append(
            {
                "title": "Server technology disclosed",
                "severity": "low",
                "advice": (
                    "Consider minimizing unnecessary "
                    "server technology disclosure."
                ),
            }
        )

    # X-Powered-By
    powered_by = response.headers.get(
        "x-powered-by"
    )

    if powered_by:

        findings.append(
            {
                "title": "X-Powered-By header disclosed",
                "severity": "low",
                "advice": (
                    "Consider removing X-Powered-By "
                    "to reduce technology disclosure."
                ),
            }
        )

    return findings


# ============================================================
# MAIN SCAN ENDPOINT
# ============================================================

@app.post("/scan")
async def scan(request: ScanRequest):

    target = str(request.url)

    parsed = urlparse(target)

    # --------------------------------------------------------
    # Validate scheme
    # --------------------------------------------------------

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:

        raise HTTPException(
            status_code=400,
            detail=(
                "Only HTTP and HTTPS URLs "
                "are supported."
            ),
        )

    hostname = parsed.hostname

    if not hostname:

        raise HTTPException(
            status_code=400,
            detail="Invalid target hostname.",
        )

    hostname = hostname.lower()

    # --------------------------------------------------------
    # Resolve target
    # --------------------------------------------------------

    resolved_addresses = resolve_hostname(
        hostname
    )

    # --------------------------------------------------------
    # SSRF protection
    # --------------------------------------------------------

    for ip in resolved_addresses:

        if is_private_or_local_ip(ip):

            raise HTTPException(
                status_code=400,
                detail=(
                    "Scanning private, local, "
                    "loopback, or reserved IP "
                    "addresses is not allowed."
                ),
            )

    findings = []

    # --------------------------------------------------------
    # HTTP request
    # --------------------------------------------------------

    try:

        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=10.0,
            headers={
                "User-Agent": (
                    "CyberSentinel/"
                    "2.0-DefensiveScanner"
                )
            },
        ) as client:

            response = await client.get(
                target
            )

    except httpx.TooManyRedirects:

        raise HTTPException(
            status_code=502,
            detail=(
                "Target produced too many redirects."
            ),
        )

    except httpx.TimeoutException:

        raise HTTPException(
            status_code=504,
            detail=(
                "Target request timed out."
            ),
        )

    except httpx.RequestError as exc:

        raise HTTPException(
            status_code=502,
            detail=(
                f"Could not reach target: {exc}"
            ),
        )

    # --------------------------------------------------------
    # Redirect check
    # --------------------------------------------------------

    if str(response.url) != target:

        findings.append(
            {
                "title": "Target redirects to another URL",
                "severity": "low",
                "advice": (
                    "Review redirects and ensure "
                    "they lead to trusted HTTPS destinations."
                ),
            }
        )

    # --------------------------------------------------------
    # HTTP security
    # --------------------------------------------------------

    findings.extend(
        check_http_security(
            parsed,
            response,
        )
    )

    # --------------------------------------------------------
    # Security headers
    # --------------------------------------------------------

    header_findings, present_headers = (
        check_headers(response.headers)
    )

    findings.extend(
        header_findings
    )

    # --------------------------------------------------------
    # Cookies
    # --------------------------------------------------------

    cookie_findings = check_cookies(
        response
    )

    findings.extend(
        cookie_findings
    )

    # --------------------------------------------------------
    # DNS
    # --------------------------------------------------------

    dns_records = dns_lookup(
        hostname
    )

    # --------------------------------------------------------
    # TLS
    # --------------------------------------------------------

    tls = None

    if parsed.scheme.lower() == "https":

        tls = tls_check(
            hostname,
            443,
        )

        if not tls["available"]:

            findings.append(
                {
                    "title": (
                        "TLS connection "
                        "could not be verified"
                    ),
                    "severity": "high",
                    "advice": (
                        "Review the target's "
                        "HTTPS/TLS configuration."
                    ),
                }
            )

        else:

            # TLS version warning
            if tls["version"] in {
                "TLSv1",
                "TLSv1.1",
            }:

                findings.append(
                    {
                        "title": (
                            "Outdated TLS version detected"
                        ),
                        "severity": "high",
                        "advice": (
                            "Use TLS 1.2 or newer."
                        ),
                    }
                )

            # Certificate expiry
            days_left = tls.get(
                "days_until_expiry"
            )

            if days_left is not None:

                if days_left < 0:

                    findings.append(
                        {
                            "title": (
                                "TLS certificate is expired"
                            ),
                            "severity": "critical",
                            "advice": (
                                "Renew the TLS certificate."
                            ),
                        }
                    )

                elif days_left <= 30:

                    findings.append(
                        {
                            "title": (
                                "TLS certificate "
                                "expires soon"
                            ),
                            "severity": "medium",
                            "advice": (
                                "Renew the TLS certificate "
                                "before expiration."
                            ),
                        }
                    )

    # --------------------------------------------------------
    # Score
    # --------------------------------------------------------

    score = calculate_score(
        findings
    )

    risk = calculate_risk(
        score
    )

    # --------------------------------------------------------
    # Response information
    # --------------------------------------------------------

    response_info = inspect_response(
        response
    )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    return {
        "scanner": {
            "name": "CyberSentinel",
            "version": "2.0.0",
            "purpose": (
                "Defensive website security "
                "posture monitoring"
            ),
        },

        "target": target,

        "hostname": hostname,

        "resolved_addresses": resolved_addresses,

        "final_url": response_info[
            "final_url"
        ],

        "http": {
            "status_code": response_info[
                "status_code"
            ],
            "http_version": response_info[
                "http_version"
            ],
            "content_type": response_info[
                "content_type"
            ],
        },

        "security": {
            "security_score": score,
            "risk_level": risk,
            "findings_count": len(findings),
            "findings": findings,
            "present_security_headers": (
                present_headers
            ),
        },

        "dns": {
            "hostname": hostname,
            "A_records": dns_records["A"],
            "AAAA_records": dns_records["AAAA"],
            "CNAME_records": dns_records["CNAME"],
            "MX_records": dns_records["MX"],
        },

        "tls": tls,

        "technology": {
            "server": response_info[
                "server"
            ],
            "x_powered_by": response_info[
                "powered_by"
            ],
        },

        "scan_metadata": {
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
        },
    }


# ============================================================
# HOME
# ============================================================

@app.get("/")
def home():

    return {
        "name": "CyberSentinel",
        "status": "online",
        "version": "2.0.0",
        "message": (
            "Defensive security monitoring API "
            "is running."
        ),
        "docs": "/docs",
        "scan_endpoint": "POST /scan",
    }


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "service": "CyberSentinel",
        "version": "2.0.0",
    }