from fastapi import FastAPI, File, UploadFile, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import email
from email.policy import default
import re
import dns.resolver
import ipaddress
import requests
import extract_msg
import io
import os
import json
import feedparser
import hashlib
import base64
import zipfile
import email.utils
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from urllib.parse import urlparse

app = FastAPI()

# Security Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict to actual domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://unpkg.com; "
        "script-src 'self' https://unpkg.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:;"
    )
    # Disable caching globally to ensure updates to code and threat feed are immediately visible
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

class RawHeadersInput(BaseModel):
    raw: str

@app.get("/")
def read_root():
    return FileResponse("index.html")

@app.get("/style.css")
def read_style():
    return FileResponse("style.css")

@app.get("/script.js")
def read_script():
    return FileResponse("script.js")

@app.get("/threatscope_logo.svg")
def read_logo():
    return FileResponse("threatscope_logo.svg")

@app.get("/threatscope_logo.png")
def read_png_logo():
    return FileResponse("threatscope_logo.png")

def parse_auth_results(auth_header):
    results = {'spf': 'none', 'dkim': 'none', 'dmarc': 'none'}
    if not auth_header:
        return results
    auth_lower = auth_header.lower()
    if 'spf=pass' in auth_lower: results['spf'] = 'pass'
    elif 'spf=fail' in auth_lower or 'spf=softfail' in auth_lower: results['spf'] = 'fail'
    
    if 'dkim=pass' in auth_lower: results['dkim'] = 'pass'
    elif 'dkim=fail' in auth_lower: results['dkim'] = 'fail'
    
    if 'dmarc=pass' in auth_lower: results['dmarc'] = 'pass'
    elif 'dmarc=fail' in auth_lower: results['dmarc'] = 'fail'
    
    return results

def extract_hops(received_headers):
    hops = []
    for i, header in enumerate(received_headers):
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', header)
        ip = ip_match.group(0) if ip_match else None
        
        parts = header.split(';')
        time_str = parts[-1].strip() if len(parts) > 1 else "Unknown Time"
        
        hops.append({
            'id': i + 1,
            'raw': header,
            'ip': ip,
            'time': time_str
        })
    return hops

def unpack_mime(msg):
    bodies = {'text': [], 'html': []}
    attachments = []
    
    def _walk(part):
        content_type = part.get_content_type()
        content_disposition = part.get_content_disposition() or ''
        
        if content_type == 'message/rfc822':
            payload = part.get_payload()
            if isinstance(payload, list):
                for sub_msg in payload:
                    _walk(sub_msg)
            elif isinstance(payload, email.message.Message):
                _walk(payload)
            return

        filename = part.get_filename()
        if 'attachment' in content_disposition.lower() or filename:
            payload = part.get_payload(decode=True)
            if payload is not None:
                attachments.append({
                    'filename': filename or 'unnamed_attachment',
                    'content': payload,
                    'content_type': content_type
                })
        else:
            if content_type == 'text/plain':
                payload = part.get_payload(decode=True)
                if payload:
                    try:
                        bodies['text'].append(payload.decode(part.get_content_charset() or 'utf-8', errors='replace'))
                    except Exception:
                        bodies['text'].append(payload.decode('utf-8', errors='replace'))
            elif content_type == 'text/html':
                payload = part.get_payload(decode=True)
                if payload:
                    try:
                        bodies['html'].append(payload.decode(part.get_content_charset() or 'utf-8', errors='replace'))
                    except Exception:
                        bodies['html'].append(payload.decode('utf-8', errors='replace'))
            
            if part.is_multipart():
                payload = part.get_payload()
                if isinstance(payload, list):
                    for sub_part in payload:
                        if isinstance(sub_part, email.message.Message):
                            _walk(sub_part)

    _walk(msg)
    return bodies, attachments

def unpack_msg(msg_obj):
    bodies = {'text': [], 'html': []}
    attachments = []
    
    if msg_obj.body:
        bodies['text'].append(msg_obj.body)
    if msg_obj.htmlBody:
        bodies['html'].append(msg_obj.htmlBody.decode('utf-8', errors='replace') if isinstance(msg_obj.htmlBody, bytes) else msg_obj.htmlBody)
        
    for att in msg_obj.attachments:
        if att.type == 'msg':
            nested_msg = att.data
            nested_bodies, nested_atts = unpack_msg(nested_msg)
            bodies['text'].extend(nested_bodies['text'])
            bodies['html'].extend(nested_bodies['html'])
            attachments.extend(nested_atts)
        else:
            attachments.append({
                'filename': att.longFilename or att.filename or 'unnamed_attachment',
                'content': att.data,
                'content_type': att.mimetype or 'application/octet-stream'
            })
            
    return bodies, attachments

def parse_date_header(date_str):
    if not date_str:
        return None
    try:
        return email.utils.parsedate_to_datetime(date_str)
    except Exception:
        return None

def parse_received_time(time_str):
    if not time_str:
        return None
    try:
        clean_time = re.sub(r'\s*\([^)]*\)\s*', ' ', time_str).strip()
        return email.utils.parsedate_to_datetime(clean_time)
    except Exception:
        return None

def get_datetime_diff(dt1, dt2):
    if dt1 is None or dt2 is None:
        return None
    try:
        if dt1.tzinfo is not None:
            dt1 = dt1.astimezone(timezone.utc)
        if dt2.tzinfo is not None:
            dt2 = dt2.astimezone(timezone.utc)
        if (dt1.tzinfo is None) != (dt2.tzinfo is None):
            dt1 = dt1.replace(tzinfo=None)
            dt2 = dt2.replace(tzinfo=None)
        return (dt1 - dt2).total_seconds()
    except Exception:
        return None
def check_reply_to_mismatch(from_raw, reply_to_raw):
    if not from_raw or not reply_to_raw:
        return False, "No Reply-To or From header to compare."
    
    from_name, from_email = email.utils.parseaddr(from_raw)
    reply_name, reply_email = email.utils.parseaddr(reply_to_raw)
    
    if not from_email or not reply_email:
        return False, "Malformed From or Reply-To address."
    
    from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
    reply_domain = reply_email.split('@')[-1].lower() if '@' in reply_email else ''
    
    if not from_domain or not reply_domain:
        return False, "Could not determine domains."
        
    if from_domain != reply_domain:
        return True, f"Reply-To domain '{reply_domain}' does not match From domain '{from_domain}'."
    return False, "Reply-To and From domains align."

def check_message_id_anomaly(message_id, from_raw, hops):
    if not message_id:
        return True, "Message-ID header is missing from the email."
    
    mid_str = message_id.strip()
    if not mid_str.startswith('<') or not mid_str.endswith('>') or '@' not in mid_str:
        return True, "Message-ID is malformed (missing brackets or '@' symbol)."
    
    mid_core = mid_str[1:-1]
    mid_domain = mid_core.split('@')[-1].lower()
    
    if not mid_domain:
        return True, "Message-ID has empty domain."
        
    from_name, from_email = email.utils.parseaddr(from_raw) if from_raw else ('', '')
    from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
    
    if from_domain and mid_domain == from_domain:
        return False, "Message-ID aligns with sender domain."
        
    hop_aligned = False
    for hop in hops:
        raw_hop = hop.get('raw', '').lower()
        if mid_domain in raw_hop:
            hop_aligned = True
            break
            
    if hop_aligned:
        return False, "Message-ID aligns with originating mail servers."
        
    return True, f"Message-ID domain '{mid_domain}' does not align with From domain '{from_domain}' or any hop servers."

def check_zero_width_obfuscation(bodies, urls):
    combined_text = " ".join(bodies.get('text', [])) + " " + "".join(bodies.get('html', [])) + " " + " ".join(urls)
    invisible_chars = re.compile(r'[\u200b\u200c\u200d\ufeff\u200e\u200f\u202a-\u202e]')
    matches = invisible_chars.findall(combined_text)
    return len(matches) > 0

def check_envelope_to_header(return_path_raw, from_raw):
    if not return_path_raw or not from_raw:
        return False, "Missing Return-Path or From header."
    from_name, from_email = email.utils.parseaddr(from_raw)
    rp_name, rp_email = email.utils.parseaddr(return_path_raw)
    
    if not from_email or not rp_email:
        return False, f"Could not parse email addresses. From: '{from_email}', Return-Path: '{rp_email}'."
        
    from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
    rp_domain = rp_email.split('@')[-1].lower() if '@' in rp_email else ''
    
    if not from_domain or not rp_domain:
        return False, f"Could not extract domains. From Domain: '{from_domain}', Return-Path Domain: '{rp_domain}'."
        
    if from_domain != rp_domain:
        return True, f"Return-Path domain ({rp_domain}) does not match From domain ({from_domain})."
    return False, "Return-Path and From domains match."

def check_hidden_destinations(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    mismatches = []
    
    for a in soup.find_all('a', href=True):
        href = a['href'].strip()
        text = a.get_text().strip()
        
        url_pattern = re.compile(
            r'^(https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(/.*)?$', re.IGNORECASE
        )
        text_match = url_pattern.match(text)
        if text_match:
            text_domain = text_match.group(2).lower()
            try:
                href_to_parse = href
                if not href_to_parse.startswith(('http://', 'https://')):
                    href_to_parse = 'http://' + href_to_parse
                    
                href_parsed = urlparse(href_to_parse)
                href_domain = href_parsed.netloc.lower()
                
                text_domain_clean = text_domain.replace('www.', '')
                href_domain_clean = href_domain.replace('www.', '')
                
                if text_domain_clean and href_domain_clean and text_domain_clean != href_domain_clean:
                    mismatches.append({
                        'text': text,
                        'href': href,
                        'text_domain': text_domain_clean,
                        'href_domain': href_domain_clean
                    })
            except Exception:
                pass
    return mismatches

def check_homoglyphs(urls):
    flagged = []
    for url in urls:
        if 'xn--' in url.lower():
            flagged.append(url)
    return flagged

def extract_all_urls(bodies):
    urls = set()
    url_regex = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<>"]*', re.IGNORECASE)
    for text in bodies['text']:
        for match in url_regex.finditer(text):
            urls.add(match.group(0))
    for html in bodies['html']:
        soup = BeautifulSoup(html, 'html.parser')
        for a in soup.find_all('a', href=True):
            urls.add(a['href'].strip())
        for match in url_regex.finditer(html):
            urls.add(match.group(0))
    return list(urls)

def sanitize_zero_width(text):
    if not text:
        return ''
    invisible_chars = re.compile(r'[\u200b\u200c\u200d\ufeff\u200e\u200f\u202a-\u202e]')
    return invisible_chars.sub('', text)

def check_bec_nlp(text):
    sanitized_text = sanitize_zero_width(text)
    text_lower = sanitized_text.lower()
    
    financial_keywords = [
        'wire transfer', 'ach', 'gift card', 'bank details', 'routing number',
        'invoice payment', 'transfer funds', 'western union', 'moneygram', 'direct deposit',
        'payment request', 'purchase order', 'bank account'
    ]
    
    urgency_keywords = [
        'urgent', 'immediate', 'asap', 'right away', 'quick task', 'confidential',
        'handle quietly', 'secretly', 'strictly confidential', 'promptly', 'without delay',
        'critical', 'need this done'
    ]
    
    matched_financial = [kw for kw in financial_keywords if kw in text_lower]
    matched_urgency = [kw for kw in urgency_keywords if kw in text_lower]
    
    if matched_financial and matched_urgency:
        return {
            'detected': True,
            'financial_terms': matched_financial,
            'urgency_terms': matched_urgency
        }
    return {'detected': False}

def check_double_extension(filename):
    if not filename:
        return False
    parts = filename.split('.')
    if len(parts) >= 3:
        dangerous_exts = {'exe', 'bat', 'scr', 'cmd', 'vbs', 'js', 'pif', 'msi', 'jar', 'ps1', 'lnk', 'hta'}
        safe_exts = {'pdf', 'docx', 'xlsx', 'txt', 'jpg', 'png', 'zip', 'rar', 'mp4', 'csv'}
        final_ext = parts[-1].lower()
        middle_exts = [p.lower() for p in parts[1:-1]]
        if final_ext in dangerous_exts and any(me in safe_exts for me in middle_exts):
            return True
    return False

def detect_magic_bytes(content):
    if len(content) < 4:
        return 'unknown'
    header = content[:4]
    if header.startswith(b'%PDF'):
        return 'pdf'
    elif header.startswith(b'PK\x03\x04'):
        return 'zip/office'
    elif header.startswith(b'MZ'):
        return 'exe'
    elif header.startswith(b'\x89PNG'):
        return 'png'
    elif header.startswith(b'\xFF\xD8\xFF'):
        return 'jpeg'
    elif header.startswith(b'GIF8'):
        return 'gif'
    return 'unknown'

def check_magic_bytes_mismatch(filename, content):
    if not filename or not content:
        return None
    ext = filename.split('.')[-1].lower() if '.' in filename else ''
    true_fmt = detect_magic_bytes(content)
    if ext == 'pdf' and true_fmt != 'pdf':
        return f"File claims to be PDF but magic bytes identify it as {true_fmt}."
    if ext in ['docx', 'xlsx', 'xlsm', 'zip'] and true_fmt != 'zip/office':
        return f"File claims to be Office/Zip archive but magic bytes identify it as {true_fmt}."
    non_exe_exts = {'pdf', 'docx', 'xlsx', 'txt', 'jpg', 'png', 'gif', 'mp4', 'csv', 'zip', 'rar'}
    if ext in non_exe_exts and true_fmt == 'exe':
        return f"File has a safe extension (.{ext}) but contains executable magic bytes (MZ)."
    return None

def scan_office_macros(content):
    if not content.startswith(b'PK\x03\x04'):
        return {'has_macros': False}
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            file_list = z.namelist()
            vba_files = [f for f in file_list if 'vbaProject.bin' in f or 'vbaProject' in f]
            dangerous_keywords = [
                b'WScript.Shell', b'Shell.Application', b'AutoOpen', b'Workbook_Open',
                b'Document_Open', b'powershell', b'cmd.exe', b'certutil', b'scrrun.dll'
            ]
            found_keywords = []
            total_unpacked_size = 0
            MAX_TOTAL_UNPACKED_SIZE = 50 * 1024 * 1024 # 50 MB limit
            for f in file_list:
                info = z.getinfo(f)
                total_unpacked_size += info.file_size
                if total_unpacked_size > MAX_TOTAL_UNPACKED_SIZE:
                    break
                if info.file_size < 5 * 1024 * 1024:
                    try:
                        file_content = z.read(f)
                        for kw in dangerous_keywords:
                            if kw in file_content:
                                decoded_kw = kw.decode('utf-8', errors='replace')
                                if decoded_kw not in found_keywords:
                                    found_keywords.append(decoded_kw)
                    except Exception:
                        pass
            if vba_files or found_keywords:
                return {
                    'has_macros': True,
                    'vba_files': vba_files,
                    'dangerous_keywords': found_keywords
                }
    except Exception:
        pass
    return {'has_macros': False}

def get_domain_creation_date(domain):
    if not domain:
        return None
    # Validate domain to prevent SSRF and path traversal
    domain_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$')
    if not domain_pattern.match(domain):
        return None
    try:
        resp = requests.get(f"https://rdap.org/domain/{domain}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            events = data.get('events', [])
            for event in events:
                action = event.get('eventAction', '').lower()
                if action in ['registration', 'creation']:
                    date_str = event.get('eventDate')
                    if date_str:
                        date_str_clean = date_str.replace('Z', '+00:00')
                        return datetime.fromisoformat(date_str_clean)
    except Exception as e:
        print(f"RDAP lookup failed for {domain}: {e}")
    return None

def check_domain_age_rule(domain):
    if not domain:
        return {'triggered': False, 'error': 'No domain provided'}
    creation_date = get_domain_creation_date(domain)
    if creation_date:
        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days
        if age_days < 30:
            return {
                'triggered': True,
                'age_days': age_days,
                'creation_date': creation_date.isoformat(),
                'description': f"Domain is newly registered ({age_days} days old)."
            }
        else:
            return {
                'triggered': False,
                'age_days': age_days,
                'creation_date': creation_date.isoformat(),
                'description': f"Domain age is {age_days} days."
            }
    return {'triggered': False, 'error': 'Could not retrieve domain age'}

def check_virustotal(url_list, file_hashes, api_key):
    results = {
        'triggered': False,
        'malicious_urls': [],
        'malicious_files': []
    }
    if not api_key:
        return results
    headers = {
        'x-apikey': api_key
    }
    for url in url_list[:5]:
        try:
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                if malicious > 0 or suspicious > 0:
                    results['malicious_urls'].append({
                        'url': url,
                        'malicious_count': malicious,
                        'suspicious_count': suspicious
                    })
                    results['triggered'] = True
        except Exception as e:
            print(f"VT URL lookup failed for {url}: {e}")
    for file_hash in file_hashes:
        try:
            resp = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                if malicious > 0 or suspicious > 0:
                    results['malicious_files'].append({
                        'hash': file_hash,
                        'malicious_count': malicious,
                        'suspicious_count': suspicious
                    })
                    results['triggered'] = True
        except Exception as e:
            print(f"VT File Hash lookup failed for {file_hash}: {e}")
    return results

def analyze_message(msg, vt_key=None, msg_obj=None):
    metadata = {}
    fields = ['Subject', 'From', 'To', 'Date', 'Message-ID', 'Return-Path', 'MIME-Version', 'References', 'In-Reply-To', 'Content-Type', 'Reply-To']
    for f in fields:
        val = msg.get(f)
        if val:
            metadata[f] = str(val)

    antispam_header = msg.get('X-Microsoft-Antispam-Mailbox-Delivery')
    if antispam_header:
        metadata['X-Microsoft-Antispam-Mailbox-Delivery'] = str(antispam_header)
    else:
        metadata['X-Microsoft-Antispam-Mailbox-Delivery'] = 'Missing'

    domain = None
    if msg.get('From'):
        domain_match = re.search(r'@([\w.-]+)', str(msg.get('From')))
        if domain_match:
            domain = domain_match.group(1)

    dns_valid = False
    if domain:
        try:
            answers = dns.resolver.resolve(domain, 'MX')
            if len(answers) > 0:
                dns_valid = True
        except Exception:
            dns_valid = False
            
    if domain:
        metadata['Domain DNS (MX)'] = 'Valid' if dns_valid else 'Missing/Invalid'

    auth_header = msg.get('Authentication-Results', '')
    auth = parse_auth_results(str(auth_header))

    received_headers = msg.get_all('Received', [])
    hops = extract_hops([str(h) for h in received_headers])

    if msg_obj:
        bodies, attachments = unpack_msg(msg_obj)
    else:
        bodies, attachments = unpack_mime(msg)

    score = 0
    checkpoint_a_rules = []
    
    # SPF
    spf_score = 0
    spf_desc = f"SPF status is '{auth['spf']}'."
    if auth['spf'] == 'fail':
        spf_score = 30
        spf_desc = "SPF validation failed, meaning the sender is not authorized by the domain."
    elif auth['spf'] == 'none':
        spf_score = 10
        spf_desc = "SPF record is missing."
    checkpoint_a_rules.append({
        'id': 'spf_status',
        'name': 'SPF Authentication',
        'triggered': auth['spf'] in ['fail', 'none'],
        'status': auth['spf'],
        'penalty': spf_score,
        'description': spf_desc
    })
    score += spf_score

    # DKIM
    dkim_score = 0
    dkim_desc = f"DKIM status is '{auth['dkim']}'."
    if auth['dkim'] == 'fail':
        dkim_score = 30
        dkim_desc = "DKIM validation failed, indicating the message may have been tampered with."
    checkpoint_a_rules.append({
        'id': 'dkim_status',
        'name': 'DKIM Authentication',
        'triggered': auth['dkim'] == 'fail',
        'status': auth['dkim'],
        'penalty': dkim_score,
        'description': dkim_desc
    })
    score += dkim_score

    # DMARC
    dmarc_score = 0
    dmarc_desc = f"DMARC status is '{auth['dmarc']}'."
    if auth['dmarc'] == 'fail':
        dmarc_score = 40
        dmarc_desc = "DMARC policy failed, a strong indicator of spoofing."
    elif auth['dmarc'] == 'none':
        dmarc_score = 10
        dmarc_desc = "DMARC record is missing."
    checkpoint_a_rules.append({
        'id': 'dmarc_status',
        'name': 'DMARC Authentication',
        'triggered': auth['dmarc'] in ['fail', 'none'],
        'status': auth['dmarc'],
        'penalty': dmarc_score,
        'description': dmarc_desc
    })
    score += dmarc_score

    # Dual Absence
    dual_absent = (auth['spf'] == 'none' and auth['dkim'] == 'none')
    checkpoint_a_rules.append({
        'id': 'dual_absence',
        'name': 'Dual Absence Warning',
        'triggered': dual_absent,
        'status': 'triggered' if dual_absent else 'passed',
        'penalty': 0,
        'description': "Missing essential authentication records (SPF and DKIM simultaneously)." if dual_absent else "Essential records present."
    })

    # Envelope-to-Header
    return_path = metadata.get('Return-Path')
    from_header = metadata.get('From')
    env_mismatch, env_desc = check_envelope_to_header(return_path, from_header)
    checkpoint_a_rules.append({
        'id': 'envelope_mismatch',
        'name': 'Envelope-to-Header Alignment',
        'triggered': env_mismatch,
        'status': 'mismatch' if env_mismatch else 'match',
        'penalty': 20 if env_mismatch else 0,
        'description': env_desc
    })
    if env_mismatch:
        score += 20

    # Time-Zone Anomaly
    date_header = metadata.get('Date')
    first_received_time = hops[-1]['time'] if hops else None
    date_dt = parse_date_header(date_header)
    received_dt = parse_received_time(first_received_time)
    time_diff = get_datetime_diff(received_dt, date_dt)
    
    tz_anomaly = False
    tz_desc = "Timestamps align within acceptable limits."
    if time_diff is not None:
        if abs(time_diff) > 3600:
            tz_anomaly = True
            tz_desc = f"Time-Zone anomaly detected. Difference between Date header and first Received hop is {int(abs(time_diff))} seconds (exceeds 1 hour)."
    else:
        tz_desc = "Could not parse Date or Received timestamps for timezone check."
        
    checkpoint_a_rules.append({
        'id': 'timezone_anomaly',
        'name': 'Time-Zone Anomaly Check',
        'triggered': tz_anomaly,
        'status': 'anomaly' if tz_anomaly else 'normal',
        'penalty': 15 if tz_anomaly else 0,
        'description': tz_desc
    })
    if tz_anomaly:
        score += 15

    # Domain DNS MX Check
    checkpoint_a_rules.append({
        'id': 'domain_dns',
        'name': 'Sender Domain DNS (MX) Validation',
        'triggered': not dns_valid,
        'status': 'valid' if dns_valid else 'missing_or_invalid',
        'penalty': 10 if not dns_valid else 0,
        'description': "Sender's domain has valid MX records." if dns_valid else "Sender's domain lacks valid MX records, representing a high chance of fake domain."
    })
    if not dns_valid:
        score += 10

    # Reply-To Mismatch
    reply_to_header = metadata.get('Reply-To')
    rt_mismatch, rt_desc = check_reply_to_mismatch(from_header, reply_to_header)
    checkpoint_a_rules.append({
        'id': 'reply_to_mismatch',
        'name': 'Reply-To Domain Mismatch Check',
        'triggered': rt_mismatch,
        'status': 'triggered' if rt_mismatch else ('passed' if reply_to_header else 'skipped'),
        'penalty': 30 if rt_mismatch else 0,
        'description': rt_desc if reply_to_header else "No Reply-To header present."
    })
    if rt_mismatch:
        score += 30

    # Message-ID Anomaly
    msg_id_header = metadata.get('Message-ID')
    mid_anomaly, mid_desc = check_message_id_anomaly(msg_id_header, from_header, hops)
    checkpoint_a_rules.append({
        'id': 'message_id_anomaly',
        'name': 'Message-ID Domain Alignment Check',
        'triggered': mid_anomaly,
        'status': 'triggered' if mid_anomaly else 'passed',
        'penalty': 10 if mid_anomaly else 0,
        'description': mid_desc
    })
    if mid_anomaly:
        score += 10

    # Checkpoint B: Content & URLs
    checkpoint_b_rules = []
    
    # Hidden Destination
    html_content = "".join(bodies['html'])
    hidden_mismatches = check_hidden_destinations(html_content) if html_content else []
    b1_triggered = len(hidden_mismatches) > 0
    b1_desc = "No spoofed links detected."
    if b1_triggered:
        mismatch_details = ", ".join([f"'{m['text']}' -> {m['href']}" for m in hidden_mismatches[:3]])
        b1_desc = f"Spoofed/hidden link destinations detected: {mismatch_details}"
        if len(hidden_mismatches) > 3:
            b1_desc += f" (+{len(hidden_mismatches)-3} more)"
            
    checkpoint_b_rules.append({
        'id': 'hidden_destination',
        'name': 'Hidden Link Destination Check',
        'triggered': b1_triggered,
        'status': 'triggered' if b1_triggered else 'passed',
        'penalty': 25 if b1_triggered else 0,
        'description': b1_desc,
        'details': hidden_mismatches
    })
    if b1_triggered:
        score += 25

    # Extract URLs
    all_urls = extract_all_urls(bodies)
    
    # Homoglyphs
    homoglyphs = check_homoglyphs(all_urls)
    b2_triggered = len(homoglyphs) > 0
    b2_desc = "No Punycode (homoglyph) URLs detected."
    if b2_triggered:
        b2_desc = f"Punycode/homoglyph URLs detected: {', '.join(homoglyphs[:3])}"
        if len(homoglyphs) > 3:
            b2_desc += f" (+{len(homoglyphs)-3} more)"
            
    checkpoint_b_rules.append({
        'id': 'homoglyph_urls',
        'name': 'Homoglyph (Punycode) Check',
        'triggered': b2_triggered,
        'status': 'triggered' if b2_triggered else 'passed',
        'penalty': 30 if b2_triggered else 0,
        'description': b2_desc,
        'details': homoglyphs
    })
    if b2_triggered:
        score += 30

    # BEC NLP Check
    plain_text_combined = " ".join(bodies['text']) + " " + BeautifulSoup(html_content, 'html.parser').get_text() if html_content else " ".join(bodies['text'])
    bec_result = check_bec_nlp(plain_text_combined)
    b3_triggered = bec_result['detected']
    b3_desc = "No business email compromise (BEC) triggers detected."
    if b3_triggered:
        b3_desc = f"Potential BEC attempt detected. Found urgency indicator(s) {bec_result['urgency_terms']} alongside financial terms {bec_result['financial_terms']}."
        
    checkpoint_b_rules.append({
        'id': 'bec_nlp',
        'name': 'Business Email Compromise (BEC) NLP Check',
        'triggered': b3_triggered,
        'status': 'triggered' if b3_triggered else 'passed',
        'penalty': 40 if b3_triggered else 0,
        'description': b3_desc,
        'details': bec_result
    })
    if b3_triggered:
        score += 40

    # Zero-Width Character Obfuscation
    zw_triggered = check_zero_width_obfuscation(bodies, all_urls)
    checkpoint_b_rules.append({
        'id': 'zero_width_obfuscation',
        'name': 'Zero-Width Character Obfuscation Check',
        'triggered': zw_triggered,
        'status': 'triggered' if zw_triggered else 'passed',
        'penalty': 20 if zw_triggered else 0,
        'description': "Zero-width Unicode obfuscation characters (e.g. U+200B) were detected in email body/URLs." if zw_triggered else "No hidden zero-width characters detected."
    })
    if zw_triggered:
        score += 20

    # Checkpoint C: Attachments
    checkpoint_c_rules = []
    analyzed_attachments = []
    c1_triggered = False
    c2_triggered = False
    c3_triggered = False
    c1_details = []
    c2_details = []
    c3_details = []
    
    for att in attachments:
        filename = att['filename']
        content = att['content']
        sha256_hash = hashlib.sha256(content).hexdigest()
        
        double_ext = check_double_extension(filename)
        if double_ext:
            c1_triggered = True
            c1_details.append(filename)
            
        mismatch_msg = check_magic_bytes_mismatch(filename, content)
        if mismatch_msg:
            c2_triggered = True
            c2_details.append(f"{filename}: {mismatch_msg}")
            
        macro_res = scan_office_macros(content)
        has_macros = macro_res['has_macros']
        if has_macros:
            c3_triggered = True
            macro_desc = f"{filename} contains VBA projects"
            if macro_res.get('dangerous_keywords'):
                macro_desc += f" and dangerous terms: {macro_res['dangerous_keywords']}"
            c3_details.append(macro_desc)
            
        analyzed_attachments.append({
            'filename': filename,
            'size': len(content),
            'sha256': sha256_hash,
            'magic_bytes_type': detect_magic_bytes(content),
            'double_extension': double_ext,
            'magic_bytes_mismatch': mismatch_msg,
            'has_macros': has_macros,
            'macro_details': macro_res if has_macros else None
        })
        
    checkpoint_c_rules.append({
        'id': 'double_extension',
        'name': 'Double File Extension Check',
        'triggered': c1_triggered,
        'status': 'triggered' if c1_triggered else 'passed',
        'penalty': 30 if c1_triggered else 0,
        'description': f"Dangerous double extensions detected: {', '.join(c1_details)}" if c1_triggered else "No double extensions detected."
    })
    if c1_triggered:
        score += 30
        
    checkpoint_c_rules.append({
        'id': 'magic_bytes_mismatch',
        'name': 'File Magic Bytes Mismatch Check',
        'triggered': c2_triggered,
        'status': 'triggered' if c2_triggered else 'passed',
        'penalty': 40 if c2_triggered else 0,
        'description': f"Magic bytes discrepancies detected: {'; '.join(c2_details)}" if c2_triggered else "All attachment formats match their claims."
    })
    if c2_triggered:
        score += 40
        
    checkpoint_c_rules.append({
        'id': 'office_macros',
        'name': 'Office VBA Macro Scan',
        'triggered': c3_triggered,
        'status': 'triggered' if c3_triggered else 'passed',
        'penalty': 35 if c3_triggered else 0,
        'description': f"Active macros/VBA project threats: {'; '.join(c3_details)}" if c3_triggered else "No hidden Office macros detected."
    })
    if c3_triggered:
        score += 35

    # Checkpoint D: Threat Intelligence (Offline Heuristics + Optional VirusTotal)
    checkpoint_d_rules = []
    
    # 1. Local Domain Reputation Heuristics Check
    domain_heuristic_triggered = False
    domain_heuristic_desc = "Sender domain has no suspicious reputation patterns."
    domain_penalty = 0
    if domain:
        d_score, d_flags = check_domain_heuristics(domain)
        if d_score > 0:
            domain_heuristic_triggered = True
            domain_heuristic_desc = f"Suspicious sender domain: {', '.join(d_flags)}"
            domain_penalty = min(d_score, 40) # cap penalty at 40
            
    checkpoint_d_rules.append({
        'id': 'domain_age',
        'name': 'Local Domain Reputation Heuristics',
        'triggered': domain_heuristic_triggered,
        'status': 'triggered' if domain_heuristic_triggered else 'passed',
        'penalty': domain_penalty,
        'description': domain_heuristic_desc
    })
    score += domain_penalty
    
    # 2. Local IOC Heuristics Check
    ioc_heuristic_triggered = False
    ioc_heuristic_desc = "All extracted links and attachments passed reputation heuristics."
    ioc_penalty = 0
    ioc_flags = []
    
    for url in all_urls:
        u_score, u_flags = check_url_heuristics(url)
        if u_score > 0:
            ioc_flags.extend(u_flags)
            
    for att in analyzed_attachments:
        att_name = att.get('filename', '')
        if '.' in att_name:
            att_domain = att_name.split('.')[0] + ".com"
            is_typo, brand = check_typosquatting(att_domain)
            if is_typo:
                ioc_flags.append(f"Attachment name '{att_name}' mimics brand '{brand}'")
                
    if ioc_flags:
        ioc_heuristic_triggered = True
        ioc_flags = list(set(ioc_flags))
        ioc_heuristic_desc = f"Extracted IOC threat flags: {', '.join(ioc_flags)}"
        ioc_penalty = 40
        
    checkpoint_d_rules.append({
        'id': 'local_ioc_heuristics',
        'name': 'Local IOC Reputation Heuristics',
        'triggered': ioc_heuristic_triggered,
        'status': 'triggered' if ioc_heuristic_triggered else 'passed',
        'penalty': ioc_penalty,
        'description': ioc_heuristic_desc
    })
    score += ioc_penalty
    
    # 3. VirusTotal Reputation Check (optional, runs only if vt_key is provided)
    vt_triggered = False
    vt_desc = "VirusTotal lookup was skipped (API key not provided)."
    vt_details = None
    if vt_key:
        file_hashes = [att['sha256'] for att in analyzed_attachments]
        vt_res = check_virustotal(all_urls, file_hashes, vt_key)
        vt_details = vt_res
        if vt_res['triggered']:
            vt_triggered = True
            m_urls = [u['url'] for u in vt_res['malicious_urls']]
            m_files = [f['hash'] for f in vt_res['malicious_files']]
            desc_parts = []
            if m_urls:
                desc_parts.append(f"Malicious URLs: {', '.join(m_urls)}")
            if m_files:
                desc_parts.append(f"Malicious attachment hashes: {', '.join(m_files)}")
            vt_desc = f"VirusTotal flagged IOCs! " + " | ".join(desc_parts)
        else:
            vt_desc = "VirusTotal checked URLs and files; no detections found."
            
    checkpoint_d_rules.append({
        'id': 'virustotal_lookup',
        'name': 'VirusTotal IOC Reputation Check',
        'triggered': vt_triggered,
        'status': 'triggered' if vt_triggered else ('passed' if vt_key else 'skipped'),
        'penalty': 50 if vt_triggered else 0,
        'description': vt_desc,
        'details': vt_details
    })
    if vt_triggered:
        score += 50

    origin_ip = None
    ip_data = None
    if hops:
        origin_ip = hops[-1]['ip']
        if origin_ip:
            try:
                ip_obj = ipaddress.ip_address(origin_ip)
                if ip_obj.is_global:
                    resp = requests.get(f"https://ipwho.is/{origin_ip}", timeout=5)
                    if resp.status_code == 200:
                        ip_data = resp.json()
            except Exception as e:
                print(f"IP lookup failed for {origin_ip}: {e}")

    all_headers = []
    for key, val in msg.items():
        all_headers.append({
            "name": key,
            "value": str(val)
        })

    reasons = []
    for cp in [checkpoint_a_rules, checkpoint_b_rules, checkpoint_c_rules, checkpoint_d_rules]:
        for rule in cp:
            if rule['triggered'] and rule['penalty'] > 0:
                reasons.append(rule['description'])
                
    final_score = min(score, 100)
    
    if final_score < 20:
        threat_level = "Safe"
    elif final_score < 60:
        threat_level = "Suspicious"
    else:
        threat_level = "High Risk"

    if not reasons:
        if final_score == 0:
            ai_explanation = "This email appears to be fully authenticated and safe. All checks (SPF, DKIM, DMARC) passed, and no anomalies or dangerous attachments were detected."
        else:
            ai_explanation = "The email triggered minor warnings but is likely safe. Exercise normal caution."
    else:
        ai_explanation = "This email is suspicious or represents a threat because:\n- " + "\n- ".join(reasons)

    from_name, from_email = email.utils.parseaddr(from_header) if from_header else ('', '')
    rp_name, rp_email = email.utils.parseaddr(return_path) if return_path else ('', '')
    from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
    rp_domain = rp_email.split('@')[-1].lower() if '@' in rp_email else ''
    domains_list = list(set(filter(None, [domain, from_domain, rp_domain])))

    iocs = {
        'ips': [hop['ip'] for hop in hops if hop.get('ip')],
        'domains': domains_list,
        'urls': all_urls,
        'attachments': [
            {
                'filename': att['filename'],
                'size': att['size'],
                'sha256': att['sha256'],
                'magic_bytes_type': att['magic_bytes_type'],
                'double_extension': att['double_extension'],
                'magic_bytes_mismatch': att['magic_bytes_mismatch'],
                'has_macros': att['has_macros']
            } for att in analyzed_attachments
        ]
    }

    return {
        "metadata": metadata,
        "auth": auth,
        "hops": hops,
        "score": final_score,
        "threat_level": threat_level,
        "origin_ip": origin_ip,
        "ip_data": ip_data,
        "ai_explanation": ai_explanation,
        "all_headers": all_headers,
        "checkpoints": {
            "A": {
                "name": "Identity & Authentication",
                "triggered": any(r['triggered'] for r in checkpoint_a_rules),
                "rules": checkpoint_a_rules
            },
            "B": {
                "name": "Content & URLs",
                "triggered": any(r['triggered'] for r in checkpoint_b_rules),
                "rules": checkpoint_b_rules
            },
            "C": {
                "name": "Attachments",
                "triggered": any(r['triggered'] for r in checkpoint_c_rules),
                "rules": checkpoint_c_rules
            },
            "D": {
                "name": "Threat Intelligence",
                "triggered": any(r['triggered'] for r in checkpoint_d_rules),
                "rules": checkpoint_d_rules
            }
        },
        "iocs": iocs
    }

@app.post("/api/analyze/raw")
async def analyze_raw(input_data: RawHeadersInput, request: Request):
    raw_headers = input_data.raw
    if not raw_headers:
        raise HTTPException(status_code=400, detail="No raw headers provided")
    if len(raw_headers) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Raw headers string too large. Maximum size is 5MB.")
    vt_key = request.headers.get("X-VT-API-Key")
    if vt_key:
        vt_key = vt_key.strip()
        if not re.match(r'^[a-fA-F0-9]{64}$', vt_key):
            raise HTTPException(status_code=400, detail="Invalid VirusTotal API key format")
    try:
        msg = email.message_from_string(raw_headers, policy=default)
        result = analyze_message(msg, vt_key=vt_key)
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/analyze/file")
async def analyze_file(request: Request, file: UploadFile = File(...)):
    if file.size and file.size > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="File too large. Maximum size is 10MB.")
    vt_key = request.headers.get("X-VT-API-Key")
    if vt_key:
        vt_key = vt_key.strip()
        if not re.match(r'^[a-fA-F0-9]{64}$', vt_key):
            raise HTTPException(status_code=400, detail="Invalid VirusTotal API key format")
    try:
        content = await file.read()
        if len(content) > 10 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="File too large. Maximum size is 10MB.")
        if file.filename.endswith('.eml'):
            msg = email.message_from_bytes(content, policy=default)
            result = analyze_message(msg, vt_key=vt_key)
            return JSONResponse(content=result)
        elif file.filename.endswith('.msg'):
            with extract_msg.Message(io.BytesIO(content)) as msg_obj:
                header_str = msg_obj.header.as_string()
                msg = email.message_from_string(header_str, policy=default)
                result = analyze_message(msg, vt_key=vt_key, msg_obj=msg_obj)
            return JSONResponse(content=result)
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/intel/feed")
def get_intel_feed():
    feed_urls = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://www.bleepingcomputer.com/feed/",
        "https://www.cisa.gov/cybersecurity-advisories/all.xml"
    ]
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    all_entries = []
    errors = []
    
    for feed_url in feed_urls:
        try:
            resp = requests.get(feed_url, headers=headers, timeout=5)
            if resp.status_code != 200:
                errors.append(f"{feed_url} status {resp.status_code}")
                continue
            
            feed = feedparser.parse(resp.content)
            if not feed.entries:
                errors.append(f"{feed_url} empty entries (bozo={feed.bozo})")
                continue
                
            for entry in feed.entries:
                summary_text = "No summary available."
                if hasattr(entry, 'summary'):
                    summary_text = re.sub(r'<[^>]+>', '', entry.summary)
                    if len(summary_text) > 150:
                        summary_text = summary_text[:150] + "..."
                
                all_entries.append({
                    "title": entry.title,
                    "link": entry.link,
                    "published": entry.published if hasattr(entry, 'published') else "Unknown date",
                    "published_parsed": entry.published_parsed if hasattr(entry, 'published_parsed') and entry.published_parsed else (0,0,0,0,0,0,0,0,0),
                    "summary": summary_text
                })
        except Exception as e:
            errors.append(f"{feed_url} error: {str(e)}")
            
    if all_entries:
        # Sort by date (newest first) across all feeds
        all_entries.sort(key=lambda x: x["published_parsed"], reverse=True)
        # Drop the sorting-only key to keep the JSON output clean
        for entry in all_entries:
            entry.pop("published_parsed", None)
        return JSONResponse(content={"success": True, "feed": all_entries[:6]})
        
    return JSONResponse(content={"success": False, "error": "; ".join(errors)}, status_code=500)

@app.get("/api/intel/ip/{ip}")
def check_ip_intel(ip: str):
    try:
        ip_obj = ipaddress.ip_address(ip)
        if not ip_obj.is_global:
            raise HTTPException(status_code=400, detail="IP address must be a public/global IP address")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    try:
        resp = requests.get(f"https://ipwho.is/{ip}", timeout=5)
        if resp.status_code == 200:
            return JSONResponse(content={"success": True, "data": resp.json()})
        else:
            return JSONResponse(content={"success": False, "error": "API returned non-200"}, status_code=500)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)

@app.get("/api/intel/geo/{host:path}")
def check_geo_intel(host: str):
    """Accepts an IP address OR a hostname — resolves hostname → IP via DNS, then does geo lookup."""
    import socket
    resolved_ip = host.strip()
    # If it's not a valid IP, try resolving it as a hostname
    try:
        ipaddress.ip_address(resolved_ip)
    except ValueError:
        try:
            resolved_ip = socket.gethostbyname(host.strip())
        except socket.gaierror:
            return JSONResponse(content={"success": False, "error": f"Could not resolve hostname: {host}"}, status_code=400)
    # Validate it's a public IP
    try:
        ip_obj = ipaddress.ip_address(resolved_ip)
        if not ip_obj.is_global:
            return JSONResponse(content={"success": False, "error": "Resolved to a private/reserved IP"}, status_code=400)
    except ValueError:
        return JSONResponse(content={"success": False, "error": "Invalid resolved IP"}, status_code=400)
    try:
        resp = requests.get(f"https://ipwho.is/{resolved_ip}", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            data["resolved_from"] = host  # tag with original input
            return JSONResponse(content={"success": True, "data": data})
        else:
            return JSONResponse(content={"success": False, "error": "Geo API returned non-200"}, status_code=500)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)

@app.get("/api/intel/domain/{domain}")
def check_domain_intel(domain: str, request: Request):
    domain_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,63}$')
    if not domain_pattern.match(domain):
        raise HTTPException(status_code=400, detail="Invalid domain name format")
        
    vt_key = request.headers.get("X-VT-API-Key")
    results = {}
    
    # 1. Keyless RDAP Age Lookup
    age_res = check_domain_age_rule(domain)
    results['rdap'] = age_res
    
    # 2. VirusTotal Domain Lookup (if API Key present)
    if vt_key:
        vt_key = vt_key.strip()
        if re.match(r'^[a-fA-F0-9]{64}$', vt_key):
            headers = {'x-apikey': vt_key}
            try:
                resp = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers, timeout=5)
                if resp.status_code == 200:
                    results['virustotal'] = resp.json()
            except Exception as e:
                print(f"VT domain lookup failed for {domain}: {e}")
                
    return JSONResponse(content={"success": True, "data": results})

@app.get("/api/intel/url")
def check_url_intel(url: str, request: Request):
    vt_key = request.headers.get("X-VT-API-Key")
    if not vt_key:
        raise HTTPException(status_code=400, detail="VirusTotal API Key is required for URL lookup.")
        
    vt_key = vt_key.strip()
    if not re.match(r'^[a-fA-F0-9]{64}$', vt_key):
        raise HTTPException(status_code=400, detail="Invalid VirusTotal API key format")
        
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {'x-apikey': vt_key}
        resp = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        if resp.status_code == 200:
            return JSONResponse(content={"success": True, "data": resp.json()})
        else:
            return JSONResponse(content={"success": False, "error": f"VirusTotal returned status {resp.status_code}"}, status_code=resp.status_code)
    except Exception as e:
        return JSONResponse(content={"success": False, "error": str(e)}, status_code=500)

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]

def calculate_entropy(text: str) -> float:
    import math
    if not text:
        return 0.0
    length = len(text)
    frequencies = {}
    for char in text:
        frequencies[char] = frequencies.get(char, 0) + 1
    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    except ValueError:
        return False

def check_typosquatting(domain: str) -> tuple[bool, str]:
    if not domain:
        return False, ""
    
    parts = domain.lower().split('.')
    if len(parts) < 2:
        return False, ""
    
    sld = parts[-2]
    
    BRANDS = [
        'paypal', 'amazon', 'microsoft', 'apple', 'google', 'netflix', 
        'facebook', 'instagram', 'linkedin', 'chase', 'wellsfargo', 
        'bankofamerica', 'yahoo', 'outlook', 'office365', 'twitter',
        'github', 'binance', 'coinbase', 'adobe'
    ]
    
    OFFICIAL_DOMAINS = {
        'paypal.com', 'paypal.co.uk', 'paypal.in',
        'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.in', 'amazon.co.jp',
        'microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'msn.com',
        'apple.com', 'icloud.com',
        'google.com', 'gmail.com', 'youtube.com', 'blogspot.com',
        'netflix.com',
        'facebook.com', 'instagram.com', 'messenger.com',
        'linkedin.com',
        'chase.com',
        'wellsfargo.com',
        'bankofamerica.com',
        'yahoo.com', 'yahoo.co.in',
        'twitter.com', 'x.com',
        'github.com',
        'binance.com',
        'coinbase.com',
        'adobe.com'
    }
    
    clean_domain = '.'.join(parts[-2:])
    if clean_domain in OFFICIAL_DOMAINS:
        return False, ""
        
    for brand in BRANDS:
        if brand in sld and sld != brand:
            return True, brand
            
        dist = levenshtein_distance(sld, brand)
        if 0 < dist <= 2 and len(sld) >= 4:
            return True, brand
            
    return False, ""

def check_domain_heuristics(domain: str) -> tuple[int, list[str]]:
    score = 0
    flags = []
    
    if not domain:
        return 0, flags
        
    domain = domain.lower()
    
    is_typo, brand = check_typosquatting(domain)
    if is_typo:
        score += 40
        flags.append(f"Brand impersonation/typosquatting of '{brand}'")
        
    parts = domain.split('.')
    sld = parts[-2] if len(parts) >= 2 else domain
    entropy = calculate_entropy(sld)
    
    digit_count = sum(1 for c in sld if c.isdigit())
    digit_ratio = digit_count / len(sld) if len(sld) > 0 else 0
    
    is_dga = False
    if len(sld) >= 8:
        if digit_ratio > 0.35:
            is_dga = True
        elif entropy > 3.4 and digit_ratio > 0.15:
            is_dga = True
        elif entropy > 3.8:
            is_dga = True
            
    if is_dga:
        score += 30
        flags.append(f"High name randomness / digit ratio (Entropy: {entropy:.2f}, Digits: {digit_ratio*100:.1f}%), likely DGA")
        
    if 'xn--' in domain:
        score += 30
        flags.append("Punycode/homoglyph character encoding")
        
    SUSPICIOUS_TLDS = {
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'loan', 'work', 
        'date', 'racing', 'win', 'download', 'stream', 'club', 'info', 'support',
        'security', 'account', 'verify', 'update', 'login', 'billing'
    }
    tld = parts[-1] if len(parts) >= 1 else ''
    if tld in SUSPICIOUS_TLDS:
        score += 20
        flags.append(f"Suspicious/low-reputation TLD (.{tld})")
        
    if len(parts) > 4:
        score += 15
        flags.append(f"Excessive subdomains ({len(parts) - 2} levels)")
        
    return min(score, 100), flags

def check_url_heuristics(url: str) -> tuple[int, list[str]]:
    score = 0
    flags = []
    
    try:
        parsed = urlparse(url)
        domain = parsed.hostname or ""
    except Exception:
        return 20, ["Malformed URL structure"]
        
    domain_score, domain_flags = check_domain_heuristics(domain)
    score += domain_score
    flags.extend(domain_flags)
    
    path_lower = parsed.path.lower()
    query_lower = parsed.query.lower()
    full_path = path_lower + "?" + query_lower
    
    try:
        ipaddress.ip_address(domain)
        score += 35
        flags.append("IP-based URL (bypasses domain DNS checks)")
    except ValueError:
        pass
        
    PHISHING_KEYWORDS = [
        'login', 'signin', 'secure', 'verify', 'update', 'account', 
        'billing', 'banking', 'wallet', 'credential', 'recover'
    ]
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in full_path]
    if matched_keywords:
        score += 15
        flags.append(f"Phishing keywords in URL path/query: {', '.join(matched_keywords)}")
        
    DANGEROUS_EXTS = ['.exe', '.scr', '.vbs', '.js', '.zip', '.rar', '.cmd', '.bat', '.ps1']
    if any(path_lower.endswith(ext) for ext in DANGEROUS_EXTS):
        score += 25
        flags.append("URL points directly to an executable/archive file download")
        
    encoding_count = len(re.findall(r'%[0-9a-f]{2}', path_lower))
    if encoding_count > 4:
        score += 15
        flags.append(f"Excessive percent-encoding in URL ({encoding_count} patterns)")
        
    return min(score, 100), flags

@app.get("/api/ioc/check")
def check_ioc_reputation(ioc: str):
    """
    Offline/Keyless IOC reputation check combining:
    1. Local structural heuristics (DGA entropy, typosquatting brand checks, private/reserved IP checks)
    2. Optional fail-safe DNSBL lookups for public IPs (keyless and offline-resilient)
    """
    import socket
    from urllib.parse import urlparse

    ioc = ioc.strip()
    ioc_type = "Domain"
    score = 0
    flags = []
    details = {}
    dnsbl_results = []

    is_ip = False
    try:
        ipaddress.ip_address(ioc)
        is_ip = True
        ioc_type = "IP"
    except ValueError:
        pass

    is_url = False
    if ioc.startswith(("http://", "https://")):
        is_url = True
        ioc_type = "URL"

    if is_ip:
        is_private = is_private_ip(ioc)
        details["is_private"] = is_private
        if is_private:
            score = 0
            flags.append("Internal/Private IP address (non-routable)")
        else:
            pass
    elif is_url:
        score, flags = check_url_heuristics(ioc)
    else:
        score, flags = check_domain_heuristics(ioc)

    domain = None
    ip = ioc if (is_ip and not is_private_ip(ioc)) else None

    if is_url:
        try:
            parsed = urlparse(ioc)
            domain = parsed.hostname or ""
        except Exception:
            pass
    elif not is_ip:
        domain = ioc

    if domain and not ip:
        try:
            resolved_ip = socket.gethostbyname(domain)
            if not is_private_ip(resolved_ip):
                ip = resolved_ip
        except Exception:
            pass

    if ip:
        DNSBLS = [
            ("Spamhaus ZEN",      "zen.spamhaus.org"),
            ("SURBL MultiSBL",    "multi.surbl.org"),
            ("Barracuda BRBL",    "b.barracudacentral.org"),
            ("SpamCop",           "bl.spamcop.net"),
        ]
        reversed_ip = ".".join(reversed(ip.split(".")))
        for label, dnsbl in DNSBLS:
            query = f"{reversed_ip}.{dnsbl}"
            try:
                socket.getaddrinfo(query, None)
                dnsbl_results.append({"list": label, "listed": True})
                score += 30
                flags.append(f"Listed on DNSBL {label}")
            except Exception:
                dnsbl_results.append({"list": label, "listed": False})

    score = min(score, 100)

    result = {
        "ioc": ioc,
        "type": ioc_type,
        "score": score,
        "flags": flags,
        "dnsbl": dnsbl_results,
        "details": details
    }

    return JSONResponse(content={"success": True, "data": result})


if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "127.0.0.1")
    uvicorn.run("main:app", host=host, port=port)

