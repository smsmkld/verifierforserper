import smtplib
import dns.resolver
import re
import json
import time
import random
import string
import socket
from flask import Flask, request, jsonify
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import threading

app = Flask(__name__)

# ═══════════════════════════════════════════════════════════
# DISPOSABLE EMAIL DOMAINS
# ═══════════════════════════════════════════════════════════

DISPOSABLE_DOMAINS = {
    'mailinator.com', 'guerrillamail.com', 'tempmail.com',
    'throwaway.email', 'yopmail.com', 'sharklasers.com',
    'trashmail.com', '10minutemail.com', 'fakeinbox.com',
    'maildrop.cc', 'dispostable.com', 'spamgourmet.com',
    'getnada.com', 'mailnull.com', 'spamgourmet.org',
    'trashmail.me', 'discard.email', 'tempr.email',
    'mailnesia.com', 'spamfree24.org', 'tempinbox.com'
}

# ═══════════════════════════════════════════════════════════
# PER-DOMAIN THROTTLING
# Prevents hammering same MX server
# ═══════════════════════════════════════════════════════════

domain_locks = defaultdict(threading.Lock)
domain_last_attempt = defaultdict(float)
DOMAIN_THROTTLE_SECONDS = 2  # Wait 2 seconds between attempts to same domain


def throttle_domain(mx_host):
    """Wait if we've hit this MX server too recently"""
    with domain_locks[mx_host]:
        last = domain_last_attempt[mx_host]
        elapsed = time.time() - last
        if elapsed < DOMAIN_THROTTLE_SECONDS:
            time.sleep(DOMAIN_THROTTLE_SECONDS - elapsed)
        domain_last_attempt[mx_host] = time.time()


# ═══════════════════════════════════════════════════════════
# EMAIL PERMUTATION GENERATOR
# ═══════════════════════════════════════════════════════════

def generate_permutations(first, last, domain):
    """Generate all common email permutations for a name + domain"""
    first = first.lower().strip()
    last = last.lower().strip()
    f = first[0]  # first initial
    l = last[0]   # last initial

    permutations = [
        f"{first}@{domain}",
        f"{last}@{domain}",
        f"{first}.{last}@{domain}",
        f"{first}{last}@{domain}",
        f"{f}{last}@{domain}",
        f"{f}.{last}@{domain}",
        f"{first}{l}@{domain}",
        f"{first}_{last}@{domain}",
        f"{last}.{first}@{domain}",
        f"{last}{first}@{domain}",
        f"{f}{l}@{domain}",
    ]

    # Remove duplicates while preserving order
    seen = set()
    unique = []
    for p in permutations:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return unique


def generate_random_email(domain):
    """Generate a random email to test for catch-all"""
    random_local = ''.join(random.choices(string.ascii_lowercase + string.digits, k=16))
    return f"{random_local}@{domain}"


# ═══════════════════════════════════════════════════════════
# FORMAT VALIDATION
# ═══════════════════════════════════════════════════════════

def is_valid_format(email):
    """Check email format with regex"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


# ═══════════════════════════════════════════════════════════
# MX RECORD LOOKUP
# ═══════════════════════════════════════════════════════════

# Cache MX lookups to avoid repeated DNS queries
mx_cache = {}
mx_cache_lock = threading.Lock()

def get_mx_records(domain):
    """Get MX records for a domain with caching"""
    with mx_cache_lock:
        if domain in mx_cache:
            return mx_cache[domain]

    try:
        records = dns.resolver.resolve(domain, 'MX')
        mx_list = sorted(records, key=lambda r: r.preference)
        result = [str(r.exchange).rstrip('.') for r in mx_list]
    except Exception:
        result = []

    with mx_cache_lock:
        mx_cache[domain] = result

    return result


# ═══════════════════════════════════════════════════════════
# CATCH-ALL DETECTION
# ═══════════════════════════════════════════════════════════

# Cache catch-all results per domain
catchall_cache = {}
catchall_cache_lock = threading.Lock()

def is_catch_all(domain, mx_servers):
    """
    Detect if domain accepts all emails (catch-all).
    Tests with a random impossible email address.
    If it returns 250 → catch-all domain.
    """
    with catchall_cache_lock:
        if domain in catchall_cache:
            return catchall_cache[domain]

    random_email = generate_random_email(domain)
    result = _smtp_check(random_email, mx_servers, max_retries=1)

    # If random email is "valid" → catch-all
    catch_all = result["smtpValid"] is True

    with catchall_cache_lock:
        catchall_cache[domain] = catch_all

    return catch_all


# ═══════════════════════════════════════════════════════════
# CORE SMTP CHECK (low-level with retry + greylist handling)
# ═══════════════════════════════════════════════════════════

GREYLIST_CODES = {421, 450, 451, 452}
INVALID_CODES = {550, 551, 552, 553, 554}
VALID_CODES = {250, 251}

def _smtp_check(email, mx_servers, timeout=10, max_retries=2):
    """
    Low-level SMTP check with:
    - Per-domain throttling
    - Greylist retry logic (421/450/451/452)
    - STARTTLS support
    - Proper HELO hostname
    
    Returns dict with smtpValid (True/False/None) and details
    """
    sender = "verify@mail-checker.net"
    helo_host = "mail-checker.net"  # Use consistent HELO hostname

    for mx in mx_servers[:3]:
        throttle_domain(mx)  # Per-domain rate control

        for attempt in range(max_retries):
            try:
                with smtplib.SMTP(timeout=timeout) as smtp:
                    smtp.connect(mx, 25)
                    smtp.ehlo(helo_host)

                    # STARTTLS if available
                    try:
                        if smtp.has_extn('STARTTLS'):
                            smtp.starttls()
                            smtp.ehlo(helo_host)
                    except Exception:
                        pass

                    smtp.mail(sender)
                    code, message = smtp.rcpt(email)

                    try:
                        smtp.quit()
                    except Exception:
                        pass

                    msg_str = message.decode('utf-8', errors='ignore') if isinstance(message, bytes) else str(message)

                    # Valid response
                    if code in VALID_CODES:
                        return {
                            "smtpValid": True,
                            "smtp_message": f"Accepted by {mx} (code {code}): {msg_str}",
                            "mx_server_used": mx,
                            "code": code
                        }

                    # Definitive invalid
                    if code in INVALID_CODES:
                        return {
                            "smtpValid": False,
                            "smtp_message": f"Rejected by {mx} (code {code}): {msg_str}",
                            "mx_server_used": mx,
                            "code": code
                        }

                    # Greylist / temp failure — wait and retry
                    if code in GREYLIST_CODES:
                        if attempt < max_retries - 1:
                            wait_time = random.randint(20, 45)
                            time.sleep(wait_time)
                            continue  # Retry same MX
                        else:
                            return {
                                "smtpValid": None,
                                "smtp_message": f"Greylisted by {mx} (code {code}): {msg_str}",
                                "mx_server_used": mx,
                                "code": code
                            }

                    # Unknown code — ambiguous
                    return {
                        "smtpValid": None,
                        "smtp_message": f"Ambiguous response from {mx} (code {code}): {msg_str}",
                        "mx_server_used": mx,
                        "code": code
                    }

            except smtplib.SMTPConnectError:
                break  # Try next MX
            except smtplib.SMTPServerDisconnected:
                break
            except socket.timeout:
                break
            except ConnectionRefusedError:
                break
            except Exception:
                break

    return {
        "smtpValid": False,
        "smtp_message": "Could not connect to any MX server",
        "mx_server_used": None,
        "code": None
    }


# ═══════════════════════════════════════════════════════════
# KNOWN CATCH-ALL / UNRELIABLE PROVIDERS
# SMTP verification is meaningless for these
# ═══════════════════════════════════════════════════════════

UNRELIABLE_PROVIDERS = {
    'gmail.com', 'googlemail.com',
    'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
    'yahoo.com', 'yahoo.co.uk', 'yahoo.fr',
    'icloud.com', 'me.com', 'mac.com',
    'protonmail.com', 'proton.me'
}

def is_unreliable_provider(domain):
    """Check if domain is a known unreliable provider for SMTP verification"""
    return domain.lower() in UNRELIABLE_PROVIDERS


# ═══════════════════════════════════════════════════════════
# FULL EMAIL VERIFICATION PIPELINE
# ═══════════════════════════════════════════════════════════

def verify_email(email, mx_servers=None, skip_catchall=False):
    """
    Full email verification:
    1. Format check
    2. MX record lookup
    3. Disposable check
    4. Unreliable provider check
    5. Catch-all detection
    6. SMTP verification with retry
    """
    result = {
        "email": email,
        "valid": False,
        "formatValid": False,
        "mxValid": False,
        "smtpValid": False,
        "status": "Invalid",
        "error": None,
        "details": "",
        "mx_servers": [],
        "smtp_message": "",
        "is_disposable": False,
        "is_catch_all": False,
        "is_unreliable_provider": False
    }

    # Step 1: Format
    if not is_valid_format(email):
        result["error"] = "Invalid email format"
        result["details"] = "Invalid email format"
        return result

    result["formatValid"] = True
    domain = email.split('@')[1].lower()

    # Step 2: MX records
    if mx_servers is None:
        mx_servers = get_mx_records(domain)

    if not mx_servers:
        result["error"] = f"No MX records for {domain}"
        result["details"] = f"Domain {domain} has no mail server"
        return result

    result["mxValid"] = True
    result["mx_servers"] = mx_servers

    # Step 3: Disposable check
    if domain in DISPOSABLE_DOMAINS:
        result["is_disposable"] = True
        result["status"] = "Disposable"
        result["details"] = "Disposable email domain"
        return result

    # Step 4: Unreliable provider check
    if is_unreliable_provider(domain):
        result["is_unreliable_provider"] = True
        result["status"] = "Unverifiable"
        result["details"] = f"{domain} does not allow SMTP verification"
        result["valid"] = False
        return result

    # Step 5: Catch-all detection
    if not skip_catchall:
        catch_all = is_catch_all(domain, mx_servers)
        if catch_all:
            result["is_catch_all"] = True
            result["status"] = "Catch-All"
            result["details"] = f"Domain {domain} accepts all emails (catch-all)"
            result["valid"] = False  # Can't confirm specific mailbox
            return result

    # Step 6: SMTP verification
    smtp_result = _smtp_check(email, mx_servers)
    result["smtp_message"] = smtp_result["smtp_message"]

    if smtp_result["smtpValid"] is True:
        result["smtpValid"] = True
        result["valid"] = True
        result["status"] = "Valid"
        result["details"] = smtp_result["smtp_message"]
    elif smtp_result["smtpValid"] is None:
        result["status"] = "Risky"
        result["details"] = smtp_result["smtp_message"]
    else:
        result["status"] = "Invalid"
        result["details"] = smtp_result["smtp_message"]

    return result


# ═══════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        "status": "healthy",
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S')
    })


@app.route('/api/validate-single', methods=['POST'])
def validate_single():
    """Validate a single email"""
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({"detail": "Missing email field"}), 400

        email = data['email'].strip()
        result = verify_email(email)
        return jsonify(result)

    except Exception as e:
        return jsonify({"detail": str(e)}), 500


@app.route('/api/validate-bulk', methods=['POST'])
def validate_bulk():
    """Validate up to 1000 emails in parallel"""
    try:
        emails = []

        if request.is_json:
            data = request.get_json()
            emails = data.get('emails', [])
            if isinstance(emails, str):
                emails = [e.strip() for e in emails.split('\n') if e.strip()]
        else:
            emails_raw = request.form.get('emails', '')
            emails = [e.strip() for e in emails_raw.split('\n') if e.strip()]

        if not emails:
            return jsonify({"detail": "No emails provided"}), 400

        if len(emails) > 1000:
            return jsonify({"detail": "Maximum 1000 emails per request"}), 400

        # Group emails by domain to reuse MX lookups and catch-all checks
        domain_groups = defaultdict(list)
        for email in emails:
            if '@' in email:
                domain = email.split('@')[1].lower()
                domain_groups[domain].append(email)

        results = []

        # Process with thread pool — limit to 10 concurrent threads
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for domain, domain_emails in domain_groups.items():
                mx = get_mx_records(domain)
                catch_all = is_catch_all(domain, mx) if mx else False
                for email in domain_emails:
                    future = executor.submit(verify_email, email, mx, catch_all)
                    futures[future] = email

            for future in as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as e:
                    results.append({
                        "email": futures[future],
                        "valid": False,
                        "status": "Error",
                        "error": str(e)
                    })

        # Restore original order
        email_order = {email: i for i, email in enumerate(emails)}
        results.sort(key=lambda r: email_order.get(r['email'], 999))

        return jsonify({
            "total": len(results),
            "valid_count": sum(1 for r in results if r.get('valid')),
            "invalid_count": sum(1 for r in results if not r.get('valid')),
            "results": results
        })

    except Exception as e:
        return jsonify({"detail": str(e)}), 500


@app.route('/api/find-email', methods=['POST'])
def find_email():
    """
    MAIN ENDPOINT FOR SERPHARVEST PRO
    
    Single:
    { "domain": "company.com", "first": "John", "last": "Smith" }
    
    Bulk:
    { "contacts": [
        {"domain": "company.com", "first": "John", "last": "Smith"},
        {"domain": "agency.io", "first": "Sarah", "last": "Jones"}
    ]}
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"detail": "No data provided"}), 400

        contacts = [data] if 'domain' in data else data.get('contacts', [])

        if len(contacts) > 100:
            return jsonify({"detail": "Maximum 100 contacts per request"}), 400

        results = []

        for contact in contacts:
            domain = contact.get('domain', '').strip().lower()
            first = contact.get('first', '').strip()
            last = contact.get('last', '').strip()

            # Clean domain
            domain = domain.replace('https://', '').replace('http://', '').replace('www.', '').split('/')[0]

            if not domain or not first or not last:
                results.append({
                    "domain": domain, "first": first, "last": last,
                    "valid_email": None, "status": "Error",
                    "error": "Missing domain, first, or last name",
                    "permutations_tried": 0
                })
                continue

            # MX lookup once for the domain
            mx_servers = get_mx_records(domain)
            if not mx_servers:
                results.append({
                    "domain": domain, "first": first, "last": last,
                    "valid_email": None, "status": "No MX Records",
                    "error": f"No MX records for {domain}",
                    "permutations_tried": 0
                })
                continue

            # Unreliable provider check
            if is_unreliable_provider(domain):
                results.append({
                    "domain": domain, "first": first, "last": last,
                    "valid_email": None, "status": "Unverifiable",
                    "error": f"{domain} does not allow SMTP verification",
                    "permutations_tried": 0
                })
                continue

            # Catch-all detection FIRST
            catch_all = is_catch_all(domain, mx_servers)
            if catch_all:
                # For catch-all domains, return most likely permutation without SMTP
                permutations = generate_permutations(first, last, domain)
                results.append({
                    "domain": domain, "first": first, "last": last,
                    "valid_email": permutations[2] if len(permutations) > 2 else permutations[0],
                    "status": "Catch-All (Guessed)",
                    "error": None,
                    "is_catch_all": True,
                    "permutations_tried": 0,
                    "note": "Domain accepts all emails - returned most likely pattern"
                })
                continue

            # Generate permutations and verify one by one
            permutations = generate_permutations(first, last, domain)
            valid_email = None
            risky_email = None
            tried = 0

            for email in permutations:
                tried += 1
                smtp_result = _smtp_check(email, mx_servers)

                if smtp_result["smtpValid"] is True:
                    valid_email = email
                    break
                elif smtp_result["smtpValid"] is None and not risky_email:
                    risky_email = email  # Save first risky as fallback

            final_email = valid_email or risky_email
            status = "Found" if valid_email else ("Risky" if risky_email else "Not Found")

            results.append({
                "domain": domain,
                "first": first,
                "last": last,
                "valid_email": final_email,
                "status": status,
                "error": None,
                "is_catch_all": False,
                "permutations_tried": tried,
                "all_permutations": permutations
            })

        if 'domain' in data:
            return jsonify(results[0])
        else:
            return jsonify({
                "total": len(results),
                "found_count": sum(1 for r in results if r.get('status') == 'Found'),
                "results": results
            })

    except Exception as e:
        return jsonify({"detail": str(e)}), 500


# ═══════════════════════════════════════════════════════════
# RUN
# ═══════════════════════════════════════════════════════════

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
