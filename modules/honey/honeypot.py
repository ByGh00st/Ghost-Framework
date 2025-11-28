# Chimera Hardened v3.2 - Replay + PCAP logs + SMB realism + SIEM webhook
# Purpose: enhance deception with multi-stage terminal replays, fake network traffic (pcap-like logs),
# more credible SMB/file-share bait (NTLM-like hashes & file listings), and a configurable
# SIEM webhook/dashboard output. Still simulation-first; no real outbound callbacks unless
# explicitly enabled in config (ENABLE_REAL_CONNECTBACK).

"""
v3.2 additions:
- ReplayEngine: extended multi-stage sequences, network-phase entries, and generation of
  pcap-like textual logs saved under ./pcap_logs/ for forensic realism.
- SMB sim: supports simple LIST and GET commands, returns fake file listings and can return
  files that contain NTLM-hash-looking bait strings to entice credential-harvesters.
- SIEM/Webhook: every high-value detection (reverse-shell, suspicious exec, SMB access)
  emits a structured JSON event. If WEBHOOK_URL is configured and ENABLE_REAL_CONNECTBACK is
  True, Chimera will attempt to POST events; otherwise events are written to ./siem_events/.

Safety: This is *simulation-only* by default. Review `ENABLE_REAL_CONNECTBACK` before enabling.
"""

import os
import sys
import time
import socket
import threading
import logging
import json
import random
import pathlib
import secrets
import string
import re
import signal
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from queue import Queue, Empty

# Helper for UTC timestamps with 'Z' suffix using timezone-aware datetimes
def utc_now_iso_z():
    return datetime.now(timezone.utc).isoformat().replace('+00:00','Z')

# ---------------- Web command handlers ----------------
def _lab_list_dir(path: str) -> list:
    path = path.rstrip('/') or '/'
    return [p.split('/')[-1] for p in LAB.fs.keys() if p.startswith(path + '/') and p.count('/')==path.count('/')+1]

def _web_list_directory(args: list) -> str:
    # Virtual, unbounded listing generator (does not hit disk)
    show_all = any(a in ('-a','-la','-al','--all') for a in args)
    long = any(a in ('-l','-la','-al','--long') for a in args)
    paths = [a for a in args if not a.startswith('-')]
    target = '/home/devops' if not paths else (paths[0] if paths[0].startswith('/') else f"/home/devops/{paths[0]}")
    rng = random.Random(hash(target) & 0xffffffff)
    entries = []
    # seed some realistic names
    common_dirs = ['etc','var','opt','srv','bin','lib','include','src','conf','logs','tmp','backups','ssh','nginx','apache2']
    common_files = ['README.md','config.yml','settings.conf','authorized_keys','id_rsa','id_rsa.pub','index.html','app.py','server.js','data.db','passwd','shadow']
    count = 200
    for i in range(count):
        if rng.random() < 0.35:
            name = rng.choice(common_dirs) + '_' + secrets.token_hex(2)
            entries.append((name,'dir'))
        else:
            base = rng.choice(common_files) if rng.random() < 0.2 else (secrets.token_hex(rng.randint(2,5)) + rng.choice(['.log','.txt','.conf','.sh','.py','.js','.bin','.dat']))
            entries.append((base,'file'))
    if show_all:
        entries = [('.', 'dir'), ('..','dir')] + entries
    if long:
        lines = []
        for name, kind in entries:
            mode = 'drwxr-xr-x' if kind=='dir' else rng.choice(['-rw-r--r--','-rwxr-xr-x','-rw-------'])
            owner = rng.choice(['root','devops','admin','www-data'])
            group = 'root' if owner=='root' else rng.choice(['staff','devops','www-data'])
            size = rng.randint(64, 5_000_000) if kind=='file' else rng.randint(0, 4096)
            mtime = datetime.fromtimestamp(time.time()-rng.randint(0,90)*86400, tz=timezone.utc).strftime('%b %d %H:%M')
            lines.append(f"{mode} 1 {owner} {group} {size} {mtime} {name}")
        return '\n'.join(lines)
    else:
        return '  '.join([n for n,_ in entries])

def _web_generate_ps() -> str:
    header = 'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND'
    lines = [header]
    base = [
        ('root', 1, '0.2', '0.1', '2256', '1440', '?', 'Ss', '00:00', 'systemd'),
        ('root', 234, '0.0', '0.1', '3420', '980', '?', 'Ss', '00:00', 'sshd: /usr/sbin/sshd -D'),
        ('www-data', 420, '0.1', '0.3', '10240', '2048', '?', 'S', '00:00', 'nginx: worker process'),
    ]
    extra_cmds = ['cron','rsyslogd','dbus-daemon','python3 app.py','redis-server *:6379','node /srv/app/server.js']
    for _ in range(random.randint(12, 30)):
        user = random.choice(['root','devops','www-data','elastic'])
        pid = random.randint(500, 32000)
        cpu = f"{random.random():.1f}"; mem = f"{random.random():.1f}"
        vsz = str(random.randint(3000, 120000)); rss = str(random.randint(500, 80000))
        tty = '?' if random.random() < 0.8 else 'pts/0'
        stat = random.choice(['S','Sl','Ss','R'])
        time_col = f"{random.randint(0,2):02d}:{random.randint(0,59):02d}"
        cmd = random.choice(extra_cmds)
        base.append((user,pid,cpu,mem,vsz,rss,tty,stat,time_col,cmd))
    for u,p,cpu,mem,vsz,rss,tty,st,t,cmd in base:
        lines.append(f"{u:<10}{p:>5} {cpu:>4} {mem:>4} {vsz:>6} {rss:>5} {tty:<7} {st:<4} 00:00 {t:<5} {cmd}")
    return '\n'.join(lines)

def web_execute_command(cmd: str, src_ip: str = "0.0.0.0") -> str:
    s = cmd.strip()
    if not s:
        return ''

    if s.startswith('ls'):
        return _web_list_directory(s.split()[1:])

    if s == 'whoami':
        return 'devops'

    if s == 'id':
        return 'uid=1001(devops) gid=1001(devops) groups=1001(devops),27(sudo)'

    if s == 'env':
        siem_emit({'event': 'web_env_access', 'src': src_ip, 'hint_revealed': WEB_HINT})
        return f'USER=devops\nPATH=/usr/local/bin:/usr/bin:/bin\nWEB_HINT={WEB_HINT}\n# Use this for FTP access'

    if s == 'echo $WEB_HINT':
        siem_emit({'event': 'web_hint_access', 'src': src_ip, 'hint_revealed': WEB_HINT})
        return f'{WEB_HINT}'

    if s == 'cat /proc/version':
        return 'Linux version 5.15.0-91-generic (buildd@lcy02-amd64) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #101-Ubuntu SMP Thu Nov 9 15:48:17 UTC 2023'

    if s.startswith('uname'):
        return 'Linux chimera-lab-node-01 5.15.0-91-generic x86_64 GNU/Linux'

    if s.startswith('ps'):
        return _web_generate_ps()

    if s.startswith('cat '):
        path = s.split(' ', 1)[1]
        p = path if path.startswith('/') else f"/home/devops/{path}"
        if p.startswith('/root'):
            return f"cat: {path}: Permission denied"
        if p == '/etc/passwd':
            return (
                "admin:x:1000:1000:Admin:/home/admin:/bin/bash\n"
                "devops:x:1001:1001:DevOps:/home/devops:/bin/bash\n"
                "backup:x:1002:1002:Backup:/home/backup:/bin/bash\n"
            )
        if p == '/etc/shadow':
            return (
                "admin:$6$ab...$3Mx...:19474:0:99999:7:::\n"
                "devops:$6$cd...$9Qw...:19474:0:99999:7:::\n"
                "backup:$6$ef...$7Rz...:19474:0:99999:7:::\n"
            )
        if p in ('/etc/app/backup.env', '/opt/tools/backup.env'):
            return f"DB_USER=reporter\nDB_PASS={DECOY_PASSWORD}\nSSH_PASS={DECOY_PASSWORD}\n# ref={ESCALATION_HINT}\n"
        if p == '/etc/web/access.conf':
            return f"# Web Access Configuration\nAPI_KEY={WEB_HINT}\n# Use this for FTP access\nFTP_HINT={FTP_HINT}\n# Next stage: SSH\nSSH_HINT={SSH_HINT}\n"
        if p == '/etc/web/escalation.txt':
            return f"# Privilege Escalation Path\n# 1. Web -> {WEB_HINT}\n# 2. FTP -> {FTP_HINT}\n# 3. SSH -> {SSH_HINT}\n# 4. Admin -> {ESCALATION_HINT}\n"
        if p == '/var/www/html/hint.txt':
            return f"# Web Hint\n# Use {WEB_HINT} to access FTP\n# FTP will give you {FTP_HINT}\n# SSH will give you {SSH_HINT}\n"
        if p == '/var/www/html/README.md':
            return f"# Web Application\n\n## Access Information\n- API Key: {WEB_HINT}\n- FTP Server: localhost:2121\n- SSH Server: localhost:2222\n\n## Next Steps\n1. Use {WEB_HINT} for FTP access\n2. FTP will reveal {FTP_HINT}\n3. SSH will reveal {SSH_HINT}\n4. Admin will reveal {ESCALATION_HINT}\n"
        if p == '/var/www/html/config.js':
            return f"// Web Configuration\nconst config = {{\n  apiKey: '{WEB_HINT}',\n  ftpServer: 'localhost:2121',\n  sshServer: 'localhost:2222',\n  hint: 'Use {WEB_HINT} for FTP access'\n}};"
        if p == '/var/www/html/.htaccess':
            return f"# Apache Configuration\n# API Key: {WEB_HINT}\n# FTP Hint: {FTP_HINT}\n# SSH Hint: {SSH_HINT}\n# Admin Hint: {ESCALATION_HINT}"
        if p == '/var/www/html/robots.txt':
            return f"User-agent: *\nDisallow: /admin/\nDisallow: /config/\n# Hint: {WEB_HINT} for FTP access"
        if any(p.startswith(prefix) for prefix in ['/root', '/etc/sudoers', '/etc/shadow', '/var/spool/cron', '/var/log/auth.log']):
            return f"cat: {path}: Permission denied"
        if any(p.startswith(prefix) for prefix in ['/etc/ssh', '/etc/ssl', '/var/log/secure', '/var/log/messages']):
            return f"cat: {path}: Permission denied"
        rng = random.Random(hash(p) & 0xffffffff)
        if rng.random() < 0.2:
            return f"cat: {path}: Permission denied"
        return f"file for {p}\nID={secrets.token_hex(8)}\n"

    # Hiçbir komut eşleşmezse
    return 'Command not recognized'

# ---------------- CONFIG ----------------
LOG_FILE = 'chimera_v3_activity.jsonl'
HOSTNAME = 'chimera-lab-node-01'
WEB_BIND = '0.0.0.0'
WEB_PORT = 8080
SSH_PORT = 2222
FTP_PORT = 2121
SMB_PORT = 14445       #  SMB
SMTP_PORT = 2525       #  SMTP
REDIS_PORT = 16379     #  Redis
ES_PORT = 9209         #  ElasticSearch-like HTTP
MAX_LAB_DEPTH = 6
MAX_FILES = 1500
SESSION_TIMEOUT = 180
RATE_LIMIT_PER_MIN = 120
ENABLE_REAL_CONNECTBACK = False
REVERSE_WHITELIST = {'127.0.0.1'}
TARPIT_ENABLED = True
TARPIT_DELAY_BASE = 1.5  # seconds
WEBHOOK_URL = None  # e.g. 'https://siem.example.com/ingest' - disabled by default
DEBUG_VERBOSE = True

# Escalation hint injected across artifacts to enable believable, but gated, privilege escalation
ESCALATION_HINT = os.environ.get('CHIMERA_ESC_HINT', 'ByGhost-' + secrets.token_hex(4))
# Additional decoy credential that appears across FTP files and can aid escalation
DECOY_PASSWORD = os.environ.get('CHIMERA_DECOY_PW', 'Bg-' + secrets.token_hex(3))
# Çok katmanlı parola zinciri için ek ipuçları
FTP_HINT = os.environ.get('CHIMERA_FTP_HINT', 'FTP-' + secrets.token_hex(3))
SSH_HINT = os.environ.get('CHIMERA_SSH_HINT', 'SSH-' + secrets.token_hex(3))
WEB_HINT = os.environ.get('CHIMERA_WEB_HINT', 'WEB-' + secrets.token_hex(3))
# Aşamalı erişim için parola kombinasyonları
PASSWORD_CHAIN = {
    'web': f"{WEB_HINT}",
    'ftp': f"{FTP_HINT}",
    'ssh': f"{SSH_HINT}",
    'admin': f"{ESCALATION_HINT}",
    'backup': f"{DECOY_PASSWORD}"
}

# Heartbeat settings (can be overridden by config.yaml)
HEARTBEAT_ENABLED = False
HEARTBEAT_INTERVAL = 60  # seconds
HEARTBEAT_VERBOSE = False

# Optional YAML config loader
def load_config_from_yaml(path: str = 'config.yaml') -> dict:
    if not os.path.exists(path):
        return {}
    try:
        import yaml  # type: ignore
    except Exception:
        print('CFG: PyYAML not installed; skipping config.yaml', file=sys.stderr)
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                return {}
            return data
    except Exception as e:
        print(f'CFG: failed to read config.yaml: {e}', file=sys.stderr)
        return {}

def apply_config(cfg: dict) -> None:
    global HOSTNAME, WEB_BIND, WEB_PORT, SSH_PORT, FTP_PORT, SMB_PORT, SMTP_PORT, REDIS_PORT, ES_PORT
    global MAX_LAB_DEPTH, MAX_FILES, SESSION_TIMEOUT, RATE_LIMIT_PER_MIN
    global ENABLE_REAL_CONNECTBACK, REVERSE_WHITELIST, TARPIT_ENABLED, TARPIT_DELAY_BASE, WEBHOOK_URL
    global HEARTBEAT_ENABLED, HEARTBEAT_INTERVAL, HEARTBEAT_VERBOSE, DEBUG_VERBOSE
    if not cfg:
        return
    HOSTNAME = cfg.get('hostname', HOSTNAME)
    WEB_BIND = cfg.get('bind', WEB_BIND)
    WEBHOOK_URL = cfg.get('webhook_url', WEBHOOK_URL)
    ports = cfg.get('ports', {}) if isinstance(cfg.get('ports', {}), dict) else {}
    WEB_PORT = ports.get('web', cfg.get('web_port', WEB_PORT))
    SSH_PORT = ports.get('ssh', cfg.get('ssh_port', SSH_PORT))
    FTP_PORT = ports.get('ftp', cfg.get('ftp_port', FTP_PORT))
    SMB_PORT = ports.get('smb', cfg.get('smb_port', SMB_PORT))
    SMTP_PORT = ports.get('smtp', cfg.get('smtp_port', SMTP_PORT))
    REDIS_PORT = ports.get('redis', cfg.get('redis_port', REDIS_PORT))
    ES_PORT = ports.get('es', cfg.get('es_port', ES_PORT))
    MAX_LAB_DEPTH = cfg.get('max_lab_depth', MAX_LAB_DEPTH)
    MAX_FILES = cfg.get('max_files', MAX_FILES)
    SESSION_TIMEOUT = cfg.get('session_timeout', SESSION_TIMEOUT)
    RATE_LIMIT_PER_MIN = cfg.get('rate_limit_per_min', RATE_LIMIT_PER_MIN)
    ENABLE_REAL_CONNECTBACK = cfg.get('enable_real_connectback', ENABLE_REAL_CONNECTBACK)
    TARPIT_ENABLED = cfg.get('tarpit_enabled', TARPIT_ENABLED)
    TARPIT_DELAY_BASE = cfg.get('tarpit_delay_base', TARPIT_DELAY_BASE)
    HEARTBEAT_ENABLED = cfg.get('heartbeat_enabled', HEARTBEAT_ENABLED)
    HEARTBEAT_INTERVAL = cfg.get('heartbeat_interval', HEARTBEAT_INTERVAL)
    HEARTBEAT_VERBOSE = cfg.get('heartbeat_verbose', HEARTBEAT_VERBOSE)
    DEBUG_VERBOSE = cfg.get('debug_verbose', DEBUG_VERBOSE)
    whit = cfg.get('reverse_whitelist')
    if isinstance(whit, list):
        REVERSE_WHITELIST = set(whit)

# Load config (if present)
APPLIED_CONFIG = load_config_from_yaml()
apply_config(APPLIED_CONFIG)

# ---------------- filesystem helpers ----------------
os.makedirs('pcap_logs', exist_ok=True)
os.makedirs('siem_events', exist_ok=True)

# ---------------- ANSI Colors (admin console & replay) ----------------
class ANSI:
    RESET = '[0m'
    BOLD = '[1m'
    RED = '[31m'
    GREEN = '[32m'
    YELLOW = '[33m'
    BLUE = '[34m'
    MAGENTA = '[35m'
    CYAN = '[36m'
    GRAY = '[90m'

# ---------------- Logging ----------------
class JSONFormatter(logging.Formatter):
    def format(self, record):
        base = {
            'ts': utc_now_iso_z(),
            'level': record.levelname,
            'msg': record.getMessage(),
            'tag': getattr(record, 'tag', 'SYS')
        }
        if hasattr(record, 'meta'):
            base.update(record.meta)
        return json.dumps(base, ensure_ascii=False)

logger = logging.getLogger('chimera_v3')
logger.setLevel(logging.INFO)
if logger.hasHandlers():
    logger.handlers.clear()
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(JSONFormatter())
logger.addHandler(file_handler)
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter('%(message)s'))
# Avoid duplicate console noise; admin console handles stdout rendering
console_handler.setLevel(logging.CRITICAL + 1)
logger.addHandler(console_handler)

# ---------------- Instance & Metrics ----------------
INSTANCE_ID = os.environ.get('CHIMERA_INSTANCE_ID', str(uuid.uuid4()))
START_TIME = time.time()
METRICS_LOCK = threading.Lock()
METRIC_COUNTERS = defaultdict(int)  # keys are tuples, e.g., ('event','smtp_conn')
AUTH_FAILS = defaultdict(int)       # keys: (service, ip)

def metric_inc(key_tuple):
    with METRICS_LOCK:
        METRIC_COUNTERS[key_tuple] += 1

def log(level, msg, tag='APP', meta=None):
    extra = {'tag': tag}
    if meta: extra['meta'] = meta
    if level == 'info': logger.info(msg, extra=extra)
    elif level == 'warn': logger.warning(msg, extra=extra)
    elif level == 'error': logger.error(msg, extra=extra)
    else: logger.debug(msg, extra=extra)

# ---------------- Rate limiter & containment ----------------
class RateLimiter:
    def __init__(self, per_min=RATE_LIMIT_PER_MIN):
        self.limit = per_min
        self.lock = threading.Lock()
        self.buckets = {}

    def allow(self, ip):
        window = int(time.time()) // 60
        key = (ip, window)
        with self.lock:
            self.buckets.setdefault(key, 0)
            if self.buckets[key] >= self.limit:
                return False
            self.buckets[key] += 1
            return True

RATE_LIMIT = RateLimiter()

# Service-specific rate limits
SERVICE_RATE_LIMIT_CONFIG = {
    'WEB': RATE_LIMIT_PER_MIN,
    'NET': RATE_LIMIT_PER_MIN,
    'FTP': RATE_LIMIT_PER_MIN,
    'SMB': RATE_LIMIT_PER_MIN,
    'SMTP': RATE_LIMIT_PER_MIN,
    'REDIS': RATE_LIMIT_PER_MIN,
    'ES': RATE_LIMIT_PER_MIN,
}
SERVICE_RATE_LIMITERS = {}

def get_service_limiter(service_name: str) -> RateLimiter:
    service_name_up = service_name.upper()
    if service_name_up not in SERVICE_RATE_LIMITERS:
        limit = SERVICE_RATE_LIMIT_CONFIG.get(service_name_up, RATE_LIMIT_PER_MIN)
        SERVICE_RATE_LIMITERS[service_name_up] = RateLimiter(per_min=limit)
    return SERVICE_RATE_LIMITERS[service_name_up]

def allow_service(service_name: str, ip: str) -> bool:
    limiter = get_service_limiter(service_name)
    allowed = limiter.allow(ip)
    if not allowed:
        metric_inc(('rate_limited', service_name.upper()))
    return allowed

# simple in-memory blocklist with expiry
class Blocklist:
    def __init__(self):
        self.lock = threading.Lock()
        self.bl = {}  # ip->expiry_ts

    def ban(self, ip, seconds=300):
        with self.lock:
            self.bl[ip] = time.time() + seconds
            log('info', f'IP {ip} banned for {seconds}s', 'SEC')
            siem_emit({'event':'ban','ip':ip,'duration':seconds})

    def allowed(self, ip):
        with self.lock:
            exp = self.bl.get(ip)
            if not exp: return True
            if time.time() > exp:
                del self.bl[ip]
                return True
            return False

BLOCKLIST = Blocklist()

# ---------------- Labyrinth generator ----------------
class LabGenerator:
    COMMON_DIRS = ['etc', 'var', 'srv', 'opt', 'home', 'root', 'usr', 'bin', 'lib']
    SUSPICIOUS_BIN_NAMES = ['runme', 'update_agent', 'svc_manager', 'autoshell', 'priv_up']

    def __init__(self, max_depth=MAX_LAB_DEPTH, max_files=MAX_FILES):
        self.max_depth = max_depth
        self.max_files = max_files
        self.fs = {}  # path -> {type:'dir'|'file'|'suid', content:, meta:}
        self.generate()

    def _randname(self, length=8):
        return ''.join(secrets.choice(string.ascii_lowercase) for _ in range(length))

    def _fake_contents(self, path):
        if path.endswith('.log'):
            lines = [f"{utc_now_iso_z()} INFO startup service={self._randname(5)} key={ESCALATION_HINT}"]
            lines += [f"{random.choice(['WARN','ERROR'])}:  event id={secrets.token_hex(4)}" for _ in range(3)]
            return ''.join(lines)
        if path.endswith('.conf') or 'sudoers' in path:
            return '# generated config' + f"option=true # note:{ESCALATION_HINT}"
        if path.endswith('.sh'):
            return '#!/bin/shecho "Starting service..." # ' + ESCALATION_HINT
        if path.endswith('.pem') or path.endswith('.key'):
            return '-----BEGIN FAKE KEY-----' + secrets.token_hex(64)
        return f"This is a decoy file for {path}. ID={secrets.token_hex(8)}"

    def _fake_meta(self, path, is_dir=False):
        # generate plausible metadata
        now = time.time()
        offset_days = random.randint(0, 120)
        ts = now - offset_days * 86400 - random.randint(0, 86400)
        owner = 'root' if path.startswith('/root') else random.choice(['devops','admin','backup','root'])
        mode = 'drwxr-xr-x' if is_dir else random.choice(['-rw-r--r--','-rwxr-xr-x','-rw-------'])
        size = 0
        return {
            'owner': owner,
            'group': 'root' if owner=='root' else 'staff',
            'mode': mode,
            'ctime': ts,
            'mtime': ts,
            'size': size,
        }

    def _add_file(self, path, kind='file'):
        content = self._fake_contents(path)
        meta = self._fake_meta(path, is_dir=False)
        meta['size'] = len(content.encode())
        self.fs[path] = {'type': kind, 'content': content, 'meta': meta}

    def generate(self):
        self.fs['/'] = {'type': 'dir', 'children': [], 'meta': self._fake_meta('/', is_dir=True)}
        for d in self.COMMON_DIRS:
            p = f'/{d}'
            self.fs[p] = {'type': 'dir', 'children': [], 'meta': self._fake_meta(p, is_dir=True)}
            self.fs['/']['children'].append(d)
        home_users = ['devops', 'admin', 'backup']
        self.fs['/home'] = {'type': 'dir', 'children': home_users, 'meta': self._fake_meta('/home', is_dir=True)}
        for u in home_users:
            up = f'/home/{u}'
            self.fs[up] = {'type': 'dir', 'children': ['.ssh', '.bash_history', 'scripts'], 'meta': self._fake_meta(up, is_dir=True)}
            self.fs[f'{up}/.ssh'] = {'type': 'dir', 'children': ['authorized_keys'], 'meta': self._fake_meta(f'{up}/.ssh', is_dir=True)}
            self.fs[f'{up}/.ssh/authorized_keys'] = {'type': 'file', 'content': 'ssh-rsa AAAAFAKEKEY ' + u}
            self._add_file(f'{up}/.bash_history')
            self._add_file(f'{up}/scripts/deploy.sh')
        created = 0
        def recurse(base, depth):
            nonlocal created
            if depth > self.max_depth or created > self.max_files: return
            files_here = random.randint(1, 6)
            for i in range(files_here):
                fname = self._randname(6)
                if random.random() < 0.06:
                    path = f'{base}/{random.choice(self.SUSPICIOUS_BIN_NAMES)}'
                    self.fs[path] = {'type': 'suid', 'content': '# binary stub', 'meta': {'suid': True, 'owner': 'root'}}
                else:
                    ext = random.choice(['.txt', '.log', '.conf', '.sh', '.pem', '.md'])
                    path = f'{base}/{fname}{ext}'
                    self._add_file(path)
                created += 1
            subdirs = random.randint(1, 4)
            for i in range(subdirs):
                dname = self._randname(5)
                dp = f'{base}/{dname}'
                self.fs[dp] = {'type': 'dir', 'children': [], 'meta': self._fake_meta(dp, is_dir=True)}
                recurse(dp, depth+1)
        recurse('/var', 1)
        recurse('/srv', 1)
        # root-only secrets that are gated
        self.fs['/root'] = {'type': 'dir', 'children': ['.secret_flag.txt', 'backup.tar.gz'], 'meta': self._fake_meta('/root', is_dir=True)}
        self._add_file('/root/.secret_flag.txt')
        self.fs['/etc/sudoers'] = {'type': 'file', 'content': '%admin ALL=(ALL) ALL', 'meta': self._fake_meta('/etc/sudoers', is_dir=False)}
        #  installed packages & cronjobs for escalation bait
        self.fs['/var/log/apt/history.log'] = {'type':'file','content':'Start-Date: 2024-01-01  Installed: openvpn, suspicious-agent'}
        self.fs['/etc/cron.d/backup'] = {'type':'file','content':'0 2 * * * root /opt/backup/backup.sh'}
        # fake process list metadata
        self.fs['/proc_fake'] = {'type':'dir','children':['1','234','420'], 'meta': self._fake_meta('/proc_fake', is_dir=True)}
        self.fs['/proc_fake/1'] = {'type':'file','content':'1 ? 00:00:01 systemd'}
        self.fs['/proc_fake/234'] = {'type':'file','content':'234 ? 00:00:00 sshd'}
        self.fs['/proc_fake/420'] = {'type':'file','content':'420 ? 00:00:00 nginx'}
        # add a shared SMB-like share directory in metadata
        self.fs['/share'] = {'type':'dir','children':['public','secrets'], 'meta': self._fake_meta('/share', is_dir=True)}
        self._add_file('/share/public/README.txt')
        # create bait files with NTLM-like hash strings
        bait_hash = lambda: ':'.join([secrets.token_hex(8), secrets.token_hex(8)])
        self.fs['/share/secrets/credentials.txt'] = {'type':'file','content': f"admin:{bait_hash()}\nroot:{bait_hash()}\n# hint={ESCALATION_HINT}"}

LAB = LabGenerator()
log('info', f'Labyrinth generated: {len(LAB.fs)} metadata entries', 'LAB')

# ---------------- SIEM / Webhook emitter ----------------
import urllib.request
import urllib.error

def siem_emit(event):
    # add metadata
    event['id'] = event.get('id', str(uuid.uuid4()))
    event['ts'] = utc_now_iso_z()
    event.setdefault('schema_version', '1.0')
    event.setdefault('host', HOSTNAME)
    event.setdefault('instance_id', INSTANCE_ID)
    event.setdefault('pid', os.getpid())
    metric_inc(('event', event.get('event','unknown')))
    # write to local events dir always
    fname = os.path.join('siem_events', f"event_{event['id']}.json")
    try:
        with open(fname, 'w') as f:
            json.dump(event, f, ensure_ascii=False, indent=2)
    except Exception as e:
        log('error', f'Failed to write SIEM event: {e}', 'SIEM')
    # if webhook configured and real connectbacks allowed, POST (optional)
    if WEBHOOK_URL and ENABLE_REAL_CONNECTBACK:
        def _post():
            try:
                req = urllib.request.Request(WEBHOOK_URL, data=json.dumps(event).encode(), headers={'Content-Type':'application/json'})
                with urllib.request.urlopen(req, timeout=6) as resp:
                    log('info', f'SIEM webhook posted, status={resp.status}', 'SIEM')
            except Exception as e:
                log('error', f'Webhook post failed: {e}', 'SIEM')
        threading.Thread(target=_post, daemon=True).start()

# ---------------- PCAP-like fake network log generator ----------------

def generate_pcap_like(src_ip, dst_ip, sport, dport, proto='TCP', annotations=None):
    # create a small human-readable pcap-like text file for forensics
    ts = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')
    fname = f"pcap_{src_ip.replace('.','_')}_{dst_ip.replace('.','_')}_{dport}_{ts}.pcap.txt"
    path = os.path.join('pcap_logs', fname)
    lines = []
    for i in range(random.randint(3,8)):
        t = utc_now_iso_z()
        payload = secrets.token_hex(12)
        lines.append(f"{t} {proto} {src_ip}:{sport} -> {dst_ip}:{dport}  len={len(payload)} payload={payload}")
    if annotations:
        lines.append('# ANNOTATIONS: ' + json.dumps(annotations))
    try:
        with open(path, 'w') as f:
            f.write(''.join(lines) + '')
        log('info', f'PCAP-like log written: {path}', 'PCAP')
    except Exception as e:
        log('error', f'Failed to write pcap log: {e}', 'PCAP')
    return path

# ---------------- Terminal Replay & Fake Process Engine (extended) ----------------
class ReplayEngine:
    """Multi-stage replay. Each stage can produce terminal lines and  network phases
    which will generate pcap-like logs for bait.
    """
    SAMPLES = {
        'runme': [
            ("Stage 0: Init", 'CYAN', 0.4, None),
            ("Stage 1: Resolving update.servers...", 'YELLOW', 0.8, {'net':('10.9.8.1',443)}),
            ("Stage 2: Downloading payload () 0%", 'GRAY', 0.3, None),
            ("Stage 2: Downloading payload () 100%", 'GRAY', 0.3, None),
            ("Stage 3: Executing stage 1...", 'MAGENTA', 0.9, {'net':('172.16.0.5',8080)}),
            ("Stage 4: Completed. No real execution performed.", 'GREEN', 0.2, None),
        ],
        'priv_up': [
            ("Check: capabilities...", 'CYAN', 0.4, None),
            ("Exploit: attempt kernel SUID ()", 'YELLOW', 1.2, {'net':('192.0.2.5',4444)}),
            ("Exploit: failed - sandbox detected ()", 'RED', 0.6, None),
            ("Action: logged and reported to system ()", 'GREEN', 0.2, None),
        ]
    }

    @staticmethod
    def play(name, transport, src_ip='127.0.0.1'):
        seq = ReplayEngine.SAMPLES.get(name)
        if not seq:
            transport.sendall(b"Executable ran ()")
            return
        for line, col, delay, net in seq:
            color = getattr(ANSI, col, '')
            try:
                transport.sendall((color + line + ANSI.RESET + "").encode())
            except Exception:
                pass
            # if this stage includes network simulation, write a pcap-like artifact
            if net:
                dst, dport = net
                sport = random.randint(1025, 55000)
                path = generate_pcap_like(src_ip, dst, sport, dport, annotations={'replay':name,'stage':line})
                siem_emit({'event':'replay_net','src':src_ip,'dst':dst,'dport':dport,'artifact':path})
            time.sleep(delay)

# ---------------- Deception Shell Engine (unchanged except calling enhanced ReplayEngine) ----------------
class DeceptionEngine:
    def __init__(self, transport, addr, user='devops'):
        self.transport = transport
        self.addr = addr
        self.ip = addr[0]
        self.user = user
        self.is_root = False
        self.cwd = f'/home/{self.user}'
        self.last_active = time.time()
        self.closed = False
        self.sudo_failures = 0
        self.sudo_locked_until = 0.0
        self.last_command_ts = 0.0
        # Small SSH misconfig bait: allow env var that might hint at weak creds
        self.ssh_banner_hint = f"SSH-2.0-OpenSSH_8.2p1 debug:{ESCALATION_HINT}"

    def _send(self, s):
        if isinstance(s, str): s = s.encode()
        try:
            self.transport.sendall(s)
        except Exception:
            self.close()

    def _recv_line(self, timeout=SESSION_TIMEOUT):
        self.transport.settimeout(timeout)
        try:
            data = self.transport.recv(4096)
            if not data: return None
            s = data.decode(errors='ignore').strip()
            # rich command logging to SIEM and admin
            siem_emit({'event':'shell_input','src':self.ip,'cmd':s})
            admin_post('INFO', f'cmd from {self.ip}: {s}', 'SHELL', ip=self.ip)
            return s
        except Exception:
            return None

    def prompt(self):
        char = '#' if self.is_root else '$'
        return f"{self.user}@{HOSTNAME}:{self.cwd}{char} "

    def _list_dir(self, path):
        entries = [p.split('/')[-1] for p in LAB.fs.keys() if p.startswith(path.rstrip('/') + '/') and p.count('/')==path.count('/')+1]
        return entries

    def _get_entry(self, path):
        return LAB.fs.get(path)

    def _resolve_path(self, maybe_path):
        if maybe_path.startswith('/'):
            return maybe_path
        return (self.cwd.rstrip('/') + '/' + maybe_path) if maybe_path else self.cwd

    def _format_mode(self, meta):
        return meta.get('mode','-rw-r--r--')

    def _format_time(self, ts):
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime('%b %d %H:%M')

    def _ls(self, args):
        show_all = any(a in ('-a','-la','-al','-all','--all') for a in args)
        long = any(a in ('-l','-la','-al','--long') for a in args)
        paths = [a for a in args if not a.startswith('-')]
        target = self.cwd if not paths else self._resolve_path(paths[0])
        ent = self._get_entry(target)
        if not ent:
            return f"ls: cannot access '{paths[0] if paths else target}': No such file or directory"
        if ent['type'] == 'file':
            name = target.split('/')[-1]
            if long:
                m = ent.get('meta', {})
                return f"{self._format_mode(m)} 1 {m.get('owner','root')} {m.get('group','root')} {m.get('size',0)} {self._format_time(m.get('mtime',time.time()))} {name}"
            return name
        # directory
        children = self._list_dir(target)
        if show_all:
            children = ['.','..'] + children
        if long:
            lines = []
            for c in children:
                p = target.rstrip('/') + '/' + c if c not in ('.','..') else target
                e = self._get_entry(p) or {}
                m = e.get('meta', {})
                mode = 'drwxr-xr-x' if e.get('type')=='dir' or c in ('.','..') else self._format_mode(m)
                size = m.get('size', 0)
                lines.append(f"{mode} 1 {m.get('owner','root')} {m.get('group','root')} {size} {self._format_time(m.get('mtime',time.time()))} {c}")
            return '\n'.join(lines)
        return '  '.join(children)

    def _generate_ps(self, full=False):
        # dynamic fake process list
        base_procs = [
            ('root', 1, '0.2', '0.1', '2256', '1440', '?', 'Ss', '00:00', 'systemd'),
            ('root', 234, '0.0', '0.1', '3420', '980', '?', 'Ss', '00:00', 'sshd: /usr/sbin/sshd -D'),
            ('www-data', 420, '0.1', '0.3', '10240', '2048', '?', 'S', '00:00', 'nginx: worker process'),
        ]
        extra_cmds = ['cron','rsyslogd','dbus-daemon','containerd','python3 app.py','redis-server *:6379','node /srv/app/server.js']
        count = random.randint(15, 45)
        for i in range(count):
            user = random.choice(['root','devops','www-data','elastic'])
            pid = random.randint(500, 32000)
            cpu = f"{random.random():.1f}"
            mem = f"{random.random():.1f}"
            vsz = str(random.randint(3000, 120000))
            rss = str(random.randint(500, 80000))
            tty = '?' if random.random() < 0.8 else 'pts/0'
            stat = random.choice(['S','Sl','Ss','R'])
            time_col = f"{random.randint(0,2):02d}:{random.randint(0,59):02d}"
            cmd = random.choice(extra_cmds)
            base_procs.append((user, pid, cpu, mem, vsz, rss, tty, stat, time_col, cmd))
        if full:
            header = 'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND'
            lines = [header]
            for u,p,cpu,mem,vsz,rss,tty,st,t,cmd in base_procs:
                lines.append(f"{u:<10}{p:>5} {cpu:>4} {mem:>4} {vsz:>6} {rss:>5} {tty:<7} {st:<4} 00:00 {t:<5} {cmd}")
            return '\n'.join(lines)
        else:
            return '\n'.join([f"{p} {tty} {t} {cmd}" for _,p,_,_,_,_,tty,_,t,cmd in base_procs])

    def _grep_file(self, pattern, path):
        ent = self._get_entry(path)
        if not ent or ent.get('type') != 'file':
            return f"grep: {path}: No such file or directory"
        out = []
        for line in ent.get('content','').splitlines():
            if re.search(pattern, line):
                out.append(line)
        return '\n'.join(out)

    def handle_command(self, cmd):
        parts = cmd.split()
        if len(parts) == 0: return
        base = parts[0]
        # Slow brute-force: if too fast, tarpit
        now = time.time()
        if (now - self.last_command_ts) < 0.15:
            time.sleep(0.3 + random.random()*0.7)
        self.last_command_ts = now
        if base in ('exit','quit'):
            self._send('logout')
            self.close(); return
        if base == 'ls':
            output = self._ls(parts[1:])
            self._send(output)
            return
        if base == 'ps':
            full = any(a in ('aux','-ef') for a in parts[1:])
            self._send(self._generate_ps(full=full))
            return
        if base == 'top':
            self._send(self._generate_ps(full=True))
            return
        if base == 'cat':
            if len(parts) < 2:
                self._send('cat: missing operand'); return
            targ = parts[1] if parts[1].startswith('/') else self.cwd + '/' + parts[1]
            ent = LAB.fs.get(targ)
            if not ent:
                self._send(f'cat: {parts[1]}: No such file or directory'); return
            if targ.startswith('/root') and not self.is_root:
                self._send(f'cat: {parts[1]}: Permission denied'); return
            self._send(ent.get('content','') + ''); return
        if base == 'grep':
            if len(parts) < 3:
                self._send('usage: grep <pattern> <file>'); return
            pattern = parts[1]
            target = self._resolve_path(parts[2])
            self._send(self._grep_file(pattern, target))
            return
        if base in ('less','more'):
            if len(parts) < 2:
                self._send('usage: less <file>'); return
            target = self._resolve_path(parts[1])
            ent = self._get_entry(target)
            if not ent or ent.get('type') != 'file':
                self._send(f'{base}: {parts[1]}: No such file or directory'); return
            content = ent.get('content','')
            self._send(content[:2000])
            return
        if base == 'find':
            start = self._resolve_path(parts[1]) if len(parts)>1 else self.cwd
            results = [p for p in LAB.fs.keys() if p.startswith(start.rstrip('/') + '/')]
            self._send('\n'.join(results[:200]))
            return
        if base in ('curl','wget'):
            body = 'Resolving host... 200 OK ()\n'
            if random.random() < 0.15:
                body += f"<!-- debug:{ESCALATION_HINT} -->\n"
            self._send(body)
            siem_emit({'event':'web_fetch_attempt','src':self.ip,'tool':base,'args':' '.join(parts[1:])})
            return
        if base in ('ssh','sshpass'):
            # Simulate a weak SSH target on internal net
            dst = parts[1] if len(parts) > 1 else '10.0.0.12'
            self._send(self.ssh_banner_hint + "\n")
            # Çok katmanlı SSH kimlik doğrulama
            auth_success = False
            auth_level = 'none'
            if SSH_HINT in ' '.join(parts):
                auth_success = True
                auth_level = 'admin'
                self._send('Authenticated as admin ().\n')
                self._send(f'# Hint: Use {ESCALATION_HINT} for root access\n')
            elif ESCALATION_HINT in ' '.join(parts):
                auth_success = True
                auth_level = 'root'
                self._send('Authenticated as root ().\n')
            elif any(h in ' '.join(parts) for h in [FTP_HINT, DECOY_PASSWORD]):
                self._send('Permission denied (publickey,password).\n')
                self._send(f'# Hint: Use {SSH_HINT} for admin access\n')
                siem_emit({'event':'ssh_auth_fail','src':self.ip,'dst':dst,'hint_given':True})
                return
            else:
                self._send('Permission denied (publickey,password).\n')
                self._send(f'# Hint: Check FTP for {SSH_HINT}\n')
                siem_emit({'event':'ssh_auth_fail','src':self.ip,'dst':dst,'hint_given':True})
                return
            
            if auth_success:
                siem_emit({'event':'ssh_auth','src':self.ip,'dst':dst,'level':auth_level,'next_hint':ESCALATION_HINT if auth_level == 'admin' else 'none'})
            return
        if base in ('ping',):
            count = 4
            host = parts[1] if len(parts)>1 else '8.8.8.8'
            out = []
            for i in range(count):
                out.append(f"64 bytes from {host}: icmp_seq={i+1} ttl=53 time={random.uniform(10,80):.2f} ms")
            out.append(f"--- {host} ping statistics ---")
            out.append(f"{count} packets transmitted, {count} received, 0% packet loss")
            self._send('\n'.join(out))
            siem_emit({'event':'ping','src':self.ip,'dst':host,'count':count})
            return
        if base in ('nc','netcat'):
            self._send('Ncat: Connection refused ()')
            siem_emit({'event':'nc_attempt','src':self.ip,'args':' '.join(parts[1:])})
            return
        if base == 'sudo' and not self.is_root:
            self._send('[sudo] password for %s: ' % self.user)
            pw = self._recv_line(10) or ''
            log('info', f'sudo attempt from {self.ip} user={self.user} pw="{pw}"', 'SHELL', meta={'src':self.ip})
            siem_emit({'event':'sudo_attempt','src':self.ip,'user':self.user,'password_attempt':pw})
            now = time.time()
            if now < self.sudo_locked_until:
                self._send('sudo: 3 incorrect password attempts; account temporarily locked')
                return
            # make success rare and require correct fake password optionally
            success_roll = secrets.randbelow(100)
            # If user discovered the hint, allow success with higher chance
            if success_roll < (25 if ESCALATION_HINT in pw else 10) and (pw in ('admin123','devops2024!', 'changeme') or ESCALATION_HINT in pw):
                self.is_root = True
                self.cwd = '/root'
                self._send('sudo: successful')
                self.sudo_failures = 0
            else:
                self.sudo_failures += 1
                if self.sudo_failures >= 3:
                    self.sudo_locked_until = now + 120
                    self._send('sudo: 3 incorrect password attempts')
                else:
                    self._send('sudo: authentication failure')
            return
        # execute suspicious binary simulation
        if base in LAB.SUSPICIOUS_BIN_NAMES:
            log('warn', f'Executable invoked by {self.ip}: {cmd}', 'REPLAY', meta={'src':self.ip, 'cmd':cmd})
            siem_emit({'event':'exec_suspicious','src':self.ip,'cmd':cmd})
            ReplayEngine.play(base, self.transport, src_ip=self.ip)
            return
        # detect reverse-shell-like patterns
        joined = ' '.join(parts)
        if self._detect_reverse_shell(joined):
            log('warn', f'Reverse shell attempt detected from {self.ip}: {joined}', 'DETECT', meta={'src':self.ip, 'cmd':joined})
            siem_emit({'event':'reverse_shell_attempt','src':self.ip,'cmd':joined})
            self._simulate_connectback(joined)
            self._send('Done.')
            return
        self._send(f'bash: {base}: command not found')

    def _detect_reverse_shell(self, s):
        patterns = [r'/dev/tcp/', r'nc .* -e', r'nc .* -c', r'bash -i', r'python -c ".*socket', r'perl -e', r'php -r']
        for p in patterns:
            if re.search(p, s): return True
        return False

    def _simulate_connectback(self, s):
        log('info', f'Simulating connectback for {self.ip}: {s}', 'CONN')
        if TARPIT_ENABLED:
            delay = TARPIT_DELAY_BASE + random.random()*5
            log('info', f'Tarpitting {self.ip} for {delay:.1f}s', 'TARPIT')
            time.sleep(delay)
        BLOCKLIST.ban(self.ip, seconds=300)

    def run(self):
        try:
            self._send(f'Welcome to {HOSTNAME}. Type exit to quit.')
            while True:
                if not RATE_LIMIT.allow(self.ip):
                    self._send('Too many requests.'); self.close(); break
                if not BLOCKLIST.allowed(self.ip):
                    self._send('Connection throttled.'); time.sleep(2); continue
                if time.time() - self.last_active > SESSION_TIMEOUT:
                    self._send('Session timed out'); break
                self._send(self.prompt())
                data = self._recv_line()
                if data is None: break
                self.last_active = time.time()
                self.handle_command(data)
        finally:
            try: self.transport.close()
            except: pass
            log('info', f'Session closed for {self.ip}', 'SHELL')

    def close(self):
        self.closed = True
        try: self.transport.shutdown(socket.SHUT_RDWR)
        except: pass
        try: self.transport.close()
        except: pass

# ---------------- HTTP Lure with advanced detectors (unchanged) ----------------
class WebLureHandler(BaseHTTPRequestHandler):
    server_version = random.choice(['nginx/1.18.0','nginx/1.20.2','nginx/1.14.2','nginx/1.22.1'])
    def log_message(self, format, *args):
        log('info', format % args, 'WEB')

    def do_GET(self):
        client_ip = self.client_address[0]
        if not BLOCKLIST.allowed(client_ip):
            self.send_response(403); self.end_headers(); return
        if not allow_service('WEB', client_ip):
            self.send_response(429); self.end_headers(); return
        q = parse_qs(urlparse(self.path).query)
        cmd = q.get('cmd', [None])[0]
        # Always surface attacker path/command in admin console (red) and SIEM
        if cmd is not None:
            admin_post('ERROR', f"DETECT type=WEB method=GET url={self.path} cmd={cmd!r}", 'DETECT', ip=client_ip)
            siem_emit({'event':'web_cmd','src':client_ip,'url':self.path,'cmd':cmd})
        # healthz and metrics endpoints
        if self.path.startswith('/healthz'):
            self.send_response(200)
            self.send_header('Content-type','application/json')
            self.end_headers()
            body = {'status':'ok','uptime_sec': int(time.time()-START_TIME),'instance_id':INSTANCE_ID}
            self.wfile.write(json.dumps(body).encode())
            return
        if self.path.startswith('/metrics'):
            self.send_response(200)
            self.send_header('Content-type','text/plain; version=0.0.4')
            self.end_headers()
            lines = [f"chimera_uptime_seconds {int(time.time()-START_TIME)}"]
            with METRICS_LOCK:
                for (k0, k1), v in METRIC_COUNTERS.items():
                    if k0 == 'event':
                        lines.append(f"chimera_events_total{{event=\"{k1}\"}} {v}")
                    elif k0 == 'rate_limited':
                        lines.append(f"chimera_rate_limited_total{{service=\"{k1}\"}} {v}")
            self.wfile.write(('\n'.join(lines)+'\n').encode())
            return
        self.send_response(200)
        self.send_header('Content-type','text/plain; charset=utf-8')
        self.end_headers()
        if not cmd:
            self.wfile.write(b"System Diagnostic Interface\nUsage: ?cmd=<command>"); return
        safe = re.sub(r'[;&`$\|]', ' ', cmd)[:512]
        out = web_execute_command(safe, client_ip)
        log('info', f'Web  exec from {client_ip}: {safe}', 'WEB')
        self.wfile.write(out.encode())

    def _is_malicious(self, s):
        markers = ['base64', '/dev/tcp/', 'wget ', 'curl ', 'python -c', 'nc ', 'bash -i', 'perl -e']
        s_low = s.lower()
        for m in markers:
            if m in s_low: return True
        return False

    def _simulate_and_respond(self, ip, s):
        log('info', f'Simulating attack chain for {ip}: {s}', 'SIM')
        self.wfile.write(b"Payload received. Performing diagnostics...")
        time.sleep(0.7)
        self.wfile.write(b"Result: Executed in restricted environment. No external connections allowed.")
        BLOCKLIST.ban(ip, seconds=300)

# ---------------- SMB sim (improved) ----------------
def ntlm_like_hash():
    # fake NTLM-like hash: username:LMHASH:NTLMHASH style (not real hash)
    return f"{secrets.token_hex(8)}:{secrets.token_hex(16)}"


# ---------------- Decoy tree creators (FTP/SSH) ----------------
def create_ftp_tree():
    root_dir = pathlib.Path('chimera_ftp_root').resolve()
    (root_dir / 'pub').mkdir(parents=True, exist_ok=True)
    # Seed some decoy files with hints
    try:
        note = root_dir / 'pub' / 'NOTE.txt'
        if not note.exists():
            note.write_text(f"Public area. Contact admin. key={ESCALATION_HINT}\n")
        users = root_dir / 'pub' / 'users.txt'
        if not users.exists():
            users.write_text("devops:disabled\nadmin:locked\n")
        # Richer directory tree and files
        def ensure(p: pathlib.Path):
            p.mkdir(parents=True, exist_ok=True)
            return p
        ensure(root_dir / 'configs')
        ensure(root_dir / 'logs')
        ensure(root_dir / 'backups')
        ensure(root_dir / 'reports')
        ensure(root_dir / 'projects' / 'app')
        ensure(root_dir / 'uploads')
        ensure(root_dir / 'tmp')
        ensure(root_dir / 'archives')
        ensure(root_dir / 'secrets')
        # Classic Linux-like structure
        ensure(root_dir / 'etc')
        ensure(root_dir / 'etc' / 'ssh')
        ensure(root_dir / 'var' / 'log')
        ensure(root_dir / 'var' / 'www' / 'html')
        ensure(root_dir / 'home' / 'devops' / '.ssh')
        ensure(root_dir / 'home' / 'admin' / '.ssh')
        ensure(root_dir / 'srv' / 'share')
        ensure(root_dir / 'opt' / 'tools')
        ensure(root_dir / 'usr' / 'local' / 'bin')
        ensure(root_dir / 'bin')
        ensure(root_dir / 'lib')
        # Write files if missing
        p = root_dir / 'configs' / 'db.conf'
        if not p.exists(): p.write_text(f"[database]\nuser=reporter\npassword={DECOY_PASSWORD}\n# ref={ESCALATION_HINT}\n")
        p = root_dir / 'configs' / 'ssh_config.bak'
        if not p.exists(): p.write_text(f"Host *\n  StrictHostKeyChecking no\n  User devops\n  IdentityFile ~/.ssh/id_rsa\n# {ESCALATION_HINT}\n")
        (root_dir / 'users' / 'creds.txt').parent.mkdir(parents=True, exist_ok=True)
        p = root_dir / 'users' / 'creds.txt'
        if not p.exists(): p.write_text(f"devops:{DECOY_PASSWORD}\nsvc:{secrets.token_hex(2)}\n# hint={ESCALATION_HINT}\n")
        # Çok katmanlı parola zinciri için ek dosyalar
        p = root_dir / 'configs' / 'ftp_access.conf'
        if not p.exists(): p.write_text(f"# FTP Access Configuration\nuser=devops\npass={FTP_HINT}\n# Next stage: SSH\nssh_user=admin\nssh_hint={SSH_HINT}\n")
        p = root_dir / 'configs' / 'web_access.conf'
        if not p.exists(): p.write_text(f"# Web Access Configuration\napi_key={WEB_HINT}\n# Use this for FTP access\nftp_hint={FTP_HINT}\n")
        p = root_dir / 'configs' / 'escalation.conf'
        if not p.exists(): p.write_text(f"# Privilege Escalation Path\n# 1. Web -> {WEB_HINT}\n# 2. FTP -> {FTP_HINT}\n# 3. SSH -> {SSH_HINT}\n# 4. Admin -> {ESCALATION_HINT}\n")
        p = root_dir / 'logs' / 'access.log'
        if not p.exists(): p.write_text(f"{utc_now_iso_z()} LOGIN devops FAIL from 10.0.0.7\n{utc_now_iso_z()} LOGIN anonymous OK from 10.0.0.23\n")
        p = root_dir / 'reports' / 'q1_audit.txt'
        if not p.exists(): p.write_text("Findings: multiple outdated services; rotate credentials.\n")
        p = root_dir / 'projects' / 'app' / '.env'
        if not p.exists(): p.write_text(f"FTP_PASSWORD={DECOY_PASSWORD}\nAPI_TOKEN={secrets.token_hex(8)}\n# {ESCALATION_HINT}\n")
        p = root_dir / 'uploads' / 'readme.txt'
        if not p.exists(): p.write_text("Upload zone. Files older than 24h are purged.\n")
        p = root_dir / 'tmp' / '.lock'
        if not p.exists(): p.write_text("LOCKED\n")
        p = root_dir / 'archives' / 'old_users.csv'
        if not p.exists(): p.write_text("user,status\nlegacy,disabled\narchived,disabled\n")
        p = root_dir / 'secrets' / 'api_keys.txt'
        if not p.exists(): p.write_text(f"service,token\nlogs,{secrets.token_hex(12)}\nbackup,{secrets.token_hex(12)}\n# key={ESCALATION_HINT}\n")
        # Linux-like content
        p = root_dir / 'etc' / 'passwd'
        if not p.exists(): p.write_text("root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\ndevops:x:1001:1001:DevOps:/home/devops:/bin/bash\n")
        p = root_dir / 'etc' / 'group'
        if not p.exists(): p.write_text("root:x:0:\nadmin:x:1000:admin\ndevops:x:1001:devops\n")
        p = root_dir / 'etc' / 'hosts'
        if not p.exists(): p.write_text("127.0.0.1 localhost\n10.0.0.12 internal.ssh\n")
        p = root_dir / 'etc' / 'ssh' / 'sshd_config'
        if not p.exists(): p.write_text(f"PermitRootLogin no\nPasswordAuthentication yes\n# DEBUG {ESCALATION_HINT}\n")
        p = root_dir / 'var' / 'log' / 'auth.log'
        if not p.exists(): p.write_text(f"{utc_now_iso_z()} sshd[123]: Failed password for devops from 10.0.0.7 port 53312 ssh2\n")
        p = root_dir / 'var' / 'log' / 'syslog'
        if not p.exists(): p.write_text(f"{utc_now_iso_z()} systemd[1]: Started app.service\n")
        p = root_dir / 'var' / 'www' / 'html' / 'index.html'
        if not p.exists(): p.write_text("<html><body><h1>Welcome</h1></body></html>\n")
        p = root_dir / 'home' / 'devops' / '.ssh' / 'authorized_keys'
        if not p.exists(): p.write_text("ssh-rsa AAAAF... devops@host\n")
        p = root_dir / 'home' / 'admin' / '.bash_history'
        if not p.exists(): p.write_text("sudo su -\nservice restart app\n")
    except Exception as e:
        log('error', f'create_ftp_tree error: {e}', 'FTP')


def create_ssh_tree():
    root_dir = pathlib.Path('chimera_ssh_root').resolve()
    try:
        def ensure(p: pathlib.Path):
            p.mkdir(parents=True, exist_ok=True)
            return p
        ensure(root_dir / 'etc' / 'ssh')
        ensure(root_dir / 'var' / 'log')
        ensure(root_dir / 'home' / 'devops' / '.ssh')
        ensure(root_dir / 'home' / 'admin' / '.ssh')
        # Files
        p = root_dir / 'etc' / 'ssh' / 'sshd_config'
        if not p.exists(): p.write_text(f"# SSH config\nPort 22\nPasswordAuthentication yes\nPermitRootLogin prohibit-password\n# {ESCALATION_HINT}\n")
        p = root_dir / 'etc' / 'ssh' / 'banner.txt'
        if not p.exists(): p.write_text("Authorized access only.\n")
        # Çok katmanlı parola zinciri için SSH dosyaları
        p = root_dir / 'etc' / 'ssh' / 'access_keys'
        if not p.exists(): p.write_text(f"# SSH Access Keys\n# From FTP: {FTP_HINT}\n# From Web: {WEB_HINT}\n# Next: {SSH_HINT}\n")
        p = root_dir / 'etc' / 'ssh' / 'user_map'
        if not p.exists(): p.write_text(f"devops:{FTP_HINT}\nadmin:{SSH_HINT}\nroot:{ESCALATION_HINT}\n")
        p = root_dir / 'var' / 'log' / 'auth.log'
        if not p.exists(): p.write_text(f"{utc_now_iso_z()} sshd[2201]: Accepted password for devops from 10.0.0.23 port 51234 ssh2\n")
        p = root_dir / 'home' / 'devops' / '.ssh' / 'known_hosts'
        if not p.exists(): p.write_text("internal.ssh ecdsa-sha2-nistp256 AAAAE...\n")
        p = root_dir / 'home' / 'devops' / '.ssh' / 'id_rsa'
        if not p.exists(): p.write_text(f"-----BEGIN FAKE KEY-----\n{secrets.token_hex(64)}\n# {ESCALATION_HINT}\n-----END FAKE KEY-----\n")
        p = root_dir / 'home' / 'devops' / '.ssh' / 'id_rsa.pub'
        if not p.exists(): p.write_text("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... devops@host\n")
        p = root_dir / 'home' / 'admin' / '.ssh' / 'authorized_keys'
        if not p.exists(): p.write_text("ssh-rsa AAAAB3Nza... admin@host\n")
        p = root_dir / 'README.txt'
        if not p.exists(): p.write_text("SSH decoy tree.\n")
    except Exception as e:
        log('error', f'create_ssh_tree error: {e}', 'SSH')


def run_ftp_server(bind, port):
    root_dir = pathlib.Path('chimera_ftp_root').resolve()
    (root_dir / 'pub').mkdir(parents=True, exist_ok=True)
    # Seed some decoy files with hints
    try:
        note = root_dir / 'pub' / 'NOTE.txt'
        if not note.exists():
            note.write_text(f"Public area. Contact admin. key={ESCALATION_HINT}\n")
        users = root_dir / 'pub' / 'users.txt'
        if not users.exists():
            users.write_text("devops:disabled\nadmin:locked\n")
        # Richer directory tree and files
        def ensure(p: pathlib.Path):
            p.mkdir(parents=True, exist_ok=True)
            return p
        ensure(root_dir / 'configs')
        ensure(root_dir / 'logs')
        ensure(root_dir / 'backups')
        ensure(root_dir / 'reports')
        ensure(root_dir / 'projects' / 'app')
        ensure(root_dir / 'uploads')
        ensure(root_dir / 'tmp')
        ensure(root_dir / 'archives')
        ensure(root_dir / 'secrets')
        # Classic Linux-like structure
        ensure(root_dir / 'etc')
        ensure(root_dir / 'etc' / 'ssh')
        ensure(root_dir / 'var' / 'log')
        ensure(root_dir / 'var' / 'www' / 'html')
        ensure(root_dir / 'var' / 'www' / 'website')
        ensure(root_dir / 'home' / 'devops' / '.ssh')
        ensure(root_dir / 'home' / 'admin' / '.ssh')
        ensure(root_dir / 'srv' / 'share')
        ensure(root_dir / 'opt' / 'tools')
        ensure(root_dir / 'usr' / 'local' / 'bin')
        ensure(root_dir / 'bin')
        ensure(root_dir / 'lib')
        # Write files if missing
        (root_dir / 'configs' / 'db.conf').write_text(
            f"[database]\nuser=reporter\npassword={DECOY_PASSWORD}\n# ref={ESCALATION_HINT}\n"
        ) if not (root_dir / 'configs' / 'db.conf').exists() else None
        (root_dir / 'configs' / 'ssh_config.bak').write_text(
            f"Host *\n  StrictHostKeyChecking no\n  User devops\n  IdentityFile ~/.ssh/id_rsa\n# {ESCALATION_HINT}\n"
        ) if not (root_dir / 'configs' / 'ssh_config.bak').exists() else None
        (root_dir / 'users' / 'creds.txt').parent.mkdir(parents=True, exist_ok=True)
        (root_dir / 'users' / 'creds.txt').write_text(
            f"devops:{DECOY_PASSWORD}\nsvc:{secrets.token_hex(2)}\n# hint={ESCALATION_HINT}\n"
        ) if not (root_dir / 'users' / 'creds.txt').exists() else None
        (root_dir / 'logs' / 'access.log').write_text(
            f"{utc_now_iso_z()} LOGIN devops FAIL from 10.0.0.7\n{utc_now_iso_z()} LOGIN anonymous OK from 10.0.0.23\n"
        ) if not (root_dir / 'logs' / 'access.log').exists() else None
        (root_dir / 'reports' / 'q1_audit.txt').write_text(
            "Findings: multiple outdated services; rotate credentials.\n"
        ) if not (root_dir / 'reports' / 'q1_audit.txt').exists() else None
        (root_dir / 'projects' / 'app' / '.env').write_text(
            f"FTP_PASSWORD={DECOY_PASSWORD}\nAPI_TOKEN={secrets.token_hex(8)}\n# {ESCALATION_HINT}\n"
        ) if not (root_dir / 'projects' / 'app' / '.env').exists() else None
        (root_dir / 'uploads' / 'readme.txt').write_text(
            "Upload zone. Files older than 24h are purged.\n"
        ) if not (root_dir / 'uploads' / 'readme.txt').exists() else None
        (root_dir / 'tmp' / '.lock').write_text("LOCKED\n") if not (root_dir / 'tmp' / '.lock').exists() else None
        (root_dir / 'archives' / 'old_users.csv').write_text(
            "user,status\nlegacy,disabled\narchived,disabled\n"
        ) if not (root_dir / 'archives' / 'old_users.csv').exists() else None
        (root_dir / 'secrets' / 'api_keys.txt').write_text(
            f"service,token\nlogs,{secrets.token_hex(12)}\nbackup,{secrets.token_hex(12)}\n# key={ESCALATION_HINT}\n"
        ) if not (root_dir / 'secrets' / 'api_keys.txt').exists() else None
        # Linux-like content
        (root_dir / 'etc' / 'passwd').write_text(
            "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000:Admin:/home/admin:/bin/bash\ndevops:x:1001:1001:DevOps:/home/devops:/bin/bash\n"
        ) if not (root_dir / 'etc' / 'passwd').exists() else None
        (root_dir / 'etc' / 'group').write_text(
            "root:x:0:\nadmin:x:1000:admin\ndevops:x:1001:devops\n"
        ) if not (root_dir / 'etc' / 'group').exists() else None
        (root_dir / 'etc' / 'hosts').write_text(
            "127.0.0.1 localhost\n10.0.0.12 internal.ssh\n"
        ) if not (root_dir / 'etc' / 'hosts').exists() else None
        (root_dir / 'etc' / 'ssh' / 'sshd_config').write_text(
            f"PermitRootLogin no\nPasswordAuthentication yes\n# DEBUG {ESCALATION_HINT}\n"
        ) if not (root_dir / 'etc' / 'ssh' / 'sshd_config').exists() else None
        (root_dir / 'var' / 'log' / 'auth.log').write_text(
            f"{utc_now_iso_z()} sshd[123]: Failed password for devops from 10.0.0.7 port 53312 ssh2\n"
        ) if not (root_dir / 'var' / 'log' / 'auth.log').exists() else None
        (root_dir / 'var' / 'log' / 'syslog').write_text(
            f"{utc_now_iso_z()} systemd[1]: Started app.service\n"
        ) if not (root_dir / 'var' / 'log' / 'syslog').exists() else None
        (root_dir / 'var' / 'www' / 'html' / 'index.html').write_text(
            "<html><body><h1>Welcome</h1></body></html>\n"
        ) if not (root_dir / 'var' / 'www' / 'html' / 'index.html').exists() else None
        (root_dir / 'home' / 'devops' / '.ssh' / 'authorized_keys').write_text(
            "ssh-rsa AAAAF... devops@host\n"
        ) if not (root_dir / 'home' / 'devops' / '.ssh' / 'authorized_keys').exists() else None
        (root_dir / 'home' / 'admin' / '.bash_history').write_text(
            "sudo su -\nservice restart app\n"
        ) if not (root_dir / 'home' / 'admin' / '.bash_history').exists() else None
    except Exception:
        pass
    banner = random.choice([
        '220 ProFTPD 1.3.5 Server ready.',
        '220 (vsFTPd 3.0.3) ready.',
        '220 Pure-FTPd server ready.'
    ])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.listen(50)
    log('info', f'FTP server listening on {bind}:{port}', 'FTP')
    while True:
        try:
            client, addr = s.accept()
            ip = addr[0]
            if not allow_service('FTP', ip):
                client.close(); continue
            client.sendall((banner + "\r\n").encode())
            user = 'anonymous'
            authed = False
            cwd = '/'
            pasv_ok = False
            def send(line):
                try: client.sendall((line + "\r\n").encode())
                except: pass
            while True:
                data = client.recv(1024)
                if not data:
                    break
                try:
                    line = data.decode(errors='ignore').strip()
                except:
                    break
                if not line:
                    continue
                cmd, *args = line.split()
                cmdU = cmd.upper()
                if cmdU == 'USER':
                    user = args[0] if args else 'anonymous'
                    send('331 Please specify the password.')
                elif cmdU == 'PASS':
                    pwd = args[0] if args else ''
                    # Çok katmanlı kimlik doğrulama: anonymous, devops, admin, backup
                    allowed = False
                    if user.lower() == 'anonymous':
                        allowed = True
                    elif user.lower() == 'devops':
                        # devops için FTP_HINT veya ESCALATION_HINT gerekli
                        allowed = FTP_HINT in pwd or ESCALATION_HINT in pwd
                    elif user.lower() == 'admin':
                        # admin için SSH_HINT gerekli
                        allowed = SSH_HINT in pwd
                    elif user.lower() == 'backup':
                        # backup için DECOY_PASSWORD gerekli
                        allowed = DECOY_PASSWORD in pwd
                    else:
                        # Tanınmayan kullanıcı için
                        allowed = False
                    
                    if allowed:
                        authed = True
                        AUTH_FAILS[('FTP', ip)] = 0
                        send('230 Login successful.')
                        # Çok katmanlı ipucu ver
                        if user.lower() == 'devops':
                            send(f'# Hint: Use {FTP_HINT} for SSH access')
                        elif user.lower() == 'admin':
                            send(f'# Hint: Use {SSH_HINT} for root access')
                        siem_emit({'event':'ftp_login','src':ip,'user':user,'level':'multi_stage','next_hint':FTP_HINT if user.lower() == 'devops' else SSH_HINT if user.lower() == 'admin' else 'none'})
                    else:
                        AUTH_FAILS[('FTP', ip)] += 1
                        backoff = min(5, AUTH_FAILS[('FTP', ip)])
                        time.sleep(backoff)
                        send('530 Login incorrect.')
                        # Çok katmanlı ipucu ver
                        if user.lower() == 'devops':
                            send(f'# Try: {FTP_HINT} or check web for hints')
                        elif user.lower() == 'admin':
                            send(f'# Try: {SSH_HINT} or check devops account')
                        siem_emit({'event':'ftp_auth_fail','src':ip,'user':user,'hint_given':True,'expected_hint':FTP_HINT if user.lower() == 'devops' else SSH_HINT if user.lower() == 'admin' else 'none'})
                        if AUTH_FAILS[('FTP', ip)] >= 5:
                            BLOCKLIST.ban(ip, seconds=600)
                            break
                elif cmdU == 'PWD':
                    send(f'257 "{cwd}" is the current directory')
                elif cmdU == 'CWD':
                    if not authed:
                        send('530 Please login with USER and PASS.'); continue
                    target = args[0] if args else '/'
                    if target == '..':
                        cwd = '/'
                    elif target.startswith('/'):
                        cwd = target
                    else:
                        cwd = (cwd.rstrip('/') + '/' + target) if cwd != '/' else ('/' + target)
                    send('250 Directory successfully changed.')
                elif cmdU == 'PASV':
                    # Simulate passive; require before LIST/RETR
                    pasv_ok = True
                    send('227 Entering Passive Mode (127,0,0,1,195,80)')
                elif cmdU == 'LIST':
                    if not authed:
                        send('530 Please login with USER and PASS.'); continue
                    if not pasv_ok:
                        send('425 Use PASV first.'); continue
                    path = root_dir / ('.' if cwd == '/' else cwd.strip('/'))
                    try:
                        entries = []
                        if path.is_dir():
                            for child in sorted(path.iterdir()):
                                name = child.name
                                meta = child.stat()
                                mode = 'drwxr-xr-x' if child.is_dir() else '-rw-r--r--'
                                size = meta.st_size
                                mtime = datetime.fromtimestamp(meta.st_mtime, tz=timezone.utc).strftime('%b %d %H:%M')
                                entries.append(f"{mode} 1 owner group {size:>6} {mtime} {name}")
                        data_conn = None
                        send('150 Here comes the directory listing.')
                        # Passive data transfer is not implemented; inline output for simulation
                        for e in entries:
                            send(e)
                        send('226 Directory send OK.')
                        siem_emit({'event':'ftp_list','src':ip,'cwd':cwd})
                    except Exception as e:
                        send('550 Failed to list directory.')
                        log('error', f'FTP LIST error: {e}', 'FTP')
                elif cmdU == 'RETR':
                    if not authed:
                        send('530 Please login with USER and PASS.'); continue
                    if not pasv_ok:
                        send('425 Use PASV first.'); continue
                    name = args[0] if args else ''
                    if not name:
                        send('501 No such file.'); continue
                    path = root_dir / (name if cwd == '/' else (cwd.strip('/') + '/' + name))
                    try:
                        if path.resolve().is_file() and str(path.resolve()).startswith(str(root_dir)):
                            send('150 Opening data connection.')
                            with open(path, 'rb') as f:
                                chunk = f.read(1024)
                                while chunk:
                                    try: client.sendall(chunk)
                                    except: break
                                    chunk = f.read(1024)
                            send('226 Transfer complete.')
                            siem_emit({'event':'ftp_retr','src':ip,'file':str(path)})
                        else:
                            send('550 Failed to open file.')
                    except Exception as e:
                        send('550 Failed to open file.')
                        log('error', f'FTP RETR error: {e}', 'FTP')
                elif cmdU == 'QUIT':
                    send('221 Goodbye.')
                    break
                else:
                    send('502 Command not implemented.')
            try: client.close()
            except: pass
        except Exception as e:
            log('error', f'FTP listener error: {e}', 'FTP')
def run_smb_server(bind, port):
    """SMB-like light simulation. Protocol not implemented. Supports simple textual commands:
    LIST  -> returns file listing for /share
    GET <filename> -> returns file content if present (can include NTLM-like bait)
    Any other input is logged and  response returned.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.listen(50)
    log('info', f'SMB server listening on {bind}:{port}', 'SMB')
    while True:
        try:
            client, addr = s.accept()
            ip = addr[0]
            log('info', f'SMB connection from {ip}', 'SMB')
            client.sendall(b"SMBv2.0 Fake-Server Ready")
            try:
                data = client.recv(1024).decode(errors='ignore').strip()
                if not data:
                    client.sendall(b"No input")
                else:
                    parts = data.split()
                    cmd = parts[0].upper()
                    if cmd == 'LIST':
                        # list /share children
                        entries = LAB.fs.get('/share', {}).get('children', [])
                        # return as newline-separated for realism
                        out = ('\n'.join(entries) + '')
                        client.sendall(out.encode())
                        siem_emit({'event':'smb_list','src':ip,'listing':entries})
                    elif cmd == 'GET' and len(parts) > 1:
                        fname = parts[1]
                        # path traversal hardening
                        if '..' in fname or fname.startswith('/') or fname.startswith('\\'):
                            client.sendall(b"ERR: invalid path")
                            client.close()
                            continue
                        fpath = f'/share/{fname}'
                        ent = LAB.fs.get(fpath)
                        if ent:
                            # if file is secrets credential, include NTLM-like bait
                            content = ent.get('content','')
                            if 'credentials' in fpath:
                                content = ent.get('content') + '# NTLM-like:' + ntlm_like_hash() + ''
                            client.sendall(content.encode())
                            siem_emit({'event':'smb_get','src':ip,'file':fpath})
                            # generate small pcap artifact for fetch
                            generate_pcap_like(ip, '10.0.0.5', random.randint(1025,55000), 445, annotations={'smb_get':fpath})
                        else:
                            client.sendall(b"ERR: no such file")
                    else:
                        log('info', f'SMB command from {ip}: {data}', 'SMB')
                        client.sendall(b"[Server] Command received ()")
                client.close()
            except Exception as e:
                log('error', f'SMB session error: {e}', 'SMB')
                try: client.close()
                except: pass
        except Exception as e:
            log('error', f'SMB listener error: {e}', 'SMB')

# ---------------- Additional lightweight lure modules (unchanged) ----------------
def run_smtp_server(bind, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.listen(50)
    log('info', f'SMTP server listening on {bind}:{port}', 'SMTP')
    while True:
        try:
            client, addr = s.accept()
            ip = addr[0]
            client.sendall(random.choice([
                b"220 chimera ESMTP Service Ready",
                b"220 mail.example.com ESMTP Postfix",
                b"220 smtp.service.local ESMTP ready"
            ]))
            data = client.recv(1024)
            if data:
                log('info', f'SMTP from {ip}: {data[:200]!r}', 'SMTP')
                siem_emit({'event':'smtp_conn','src':ip,'data':data.decode(errors='ignore')[:200]})
                client.sendall(b"250 OK ()")
            client.close()
        except Exception as e:
            log('error', f'SMTP listener error: {e}', 'SMTP')


def run_redis_server(bind, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.listen(50)
    log('info', f'Redis server listening on {bind}:{port}', 'REDIS')
    while True:
        try:
            client, addr = s.accept()
            ip = addr[0]
            data = client.recv(1024)
            if b'PING' in data.upper():
                client.sendall(b'+PONG')
                log('info', f'Redis PING from {ip}', 'REDIS')
                siem_emit({'event':'redis_ping','src':ip})
            else:
                log('info', f'Redis data from {ip}: {data[:200]!r}', 'REDIS')
                siem_emit({'event':'redis_data','src':ip,'data':data[:200].hex()})
            client.close()
        except Exception as e:
            log('error', f'Redis listener error: {e}', 'REDIS')


def run_es_server(bind, port):
    class ESHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            log('info', format % args, 'ES')
        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type','application/json')
            self.end_headers()
            info = {'cluster_name':'chimera-cluster','version':{'number':random.choice(['7.10.2','7.9.3','7.12.1']), 'build_flavor':'fake'},'tagline':'You Know, for Logs'}
            self.wfile.write(json.dumps(info).encode())
            siem_emit({'event':'es_probe','src':self.client_address[0]})
    server = HTTPServer((bind, port), ESHandler)
    log('info', f'ES server listening on {bind}:{port}', 'ES')
    server.serve_forever()

# ---------------- TCP shell server (unchanged) ----------------
def run_tcp_shell_server(bind, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((bind, port))
    s.listen(200)
    log('info', f'TCP shell lure listening on {bind}:{port}', 'NET')
    while True:
        try:
            client, addr = s.accept()
            ip = addr[0]
            if not BLOCKLIST.allowed(ip):
                client.close(); continue
            if not allow_service('NET', ip):
                client.close(); continue
            t = threading.Thread(target=DeceptionEngine(client, addr).run, daemon=True)
            t.start()
        except Exception as e:
            log('error', f'Listener error: {e}', 'NET')

# ---------------- Admin console (colorful) ----------------
class AdminConsole(threading.Thread):
    os.system("cls || clear")
    def __init__(self):
        super().__init__(daemon=True)
        self.q = Queue()
    def run(self):
        while True:
            try:
                msg = self.q.get(timeout=1)
                self.display(msg)
            except Empty:
                continue
    def display(self, item):
        level = item.get('level','INFO')
        ip = item.get('ip','-')
        tag = item.get('tag','APP')
        text = item.get('msg','')
        if level == 'INFO': col = ANSI.GREEN
        elif level == 'WARN': col = ANSI.YELLOW
        else: col = ANSI.RED
        ts = datetime.now(timezone.utc).strftime('%H:%M:%S')
        if text == '__BANNER__':
            ascii_art = r"""
  ____        _____                 _   _     _  
 |  _ \ _   _| ____|_   _____ _ __ | |_(_)___| |_ 
 | |_) | | | |  _| \ \ / / _ \ '_ \| __| / __| __|
 |  _ <| |_| | |___ \ V /  __/ | | | |_| \__ \ |_ 
 |_| \_\\__, |_____| \_/ \___|_| |_|\__|_|___/\__|
        |___/      ByGhost Honeypot Console
"""
            banner = f"{ANSI.CYAN}{ANSI.BOLD}\n{ascii_art}{ANSI.RESET}"
            print(banner)
            return
        out = f"{ANSI.BOLD}{col}[{ts}] {tag} {ip}:{ANSI.RESET} {text}"
        print(out)

ADMIN = AdminConsole()
ADMIN.start()

# helper to post to admin console and logger
def admin_post(level, msg, tag='APP', ip='-'):
    ADMIN.q.put({'level': level, 'msg': msg, 'tag': tag, 'ip': ip})
    log('info' if level=='INFO' else 'warn' if level=='WARN' else 'error', msg, tag)

# ---------------- Entrypoint ----------------
def start_services():
    threading.Thread(target=lambda: HTTPServer((WEB_BIND, WEB_PORT), WebLureHandler).serve_forever(), daemon=True).start()
    admin_post('INFO', f'Web lure active on {WEB_BIND}:{WEB_PORT}', 'WEB')
    threading.Thread(target=lambda: run_tcp_shell_server(WEB_BIND, SSH_PORT), daemon=True).start()
    admin_post('INFO', f'TCP shell lure active on {WEB_BIND}:{SSH_PORT}', 'NET')
    threading.Thread(target=lambda: run_ftp_server(WEB_BIND, FTP_PORT), daemon=True).start()
    admin_post('INFO', f'FTP server active on {WEB_BIND}:{FTP_PORT}', 'FTP')
    threading.Thread(target=lambda: run_smb_server(WEB_BIND, SMB_PORT), daemon=True).start()
    admin_post('INFO', f'SMB server active on {WEB_BIND}:{SMB_PORT}', 'SMB')
    threading.Thread(target=lambda: run_smtp_server(WEB_BIND, SMTP_PORT), daemon=True).start()
    admin_post('INFO', f'SMTP server active on {WEB_BIND}:{SMTP_PORT}', 'SMTP')
    threading.Thread(target=lambda: run_redis_server(WEB_BIND, REDIS_PORT), daemon=True).start()
    admin_post('INFO', f'Redis server active on {WEB_BIND}:{REDIS_PORT}', 'REDIS')
    threading.Thread(target=lambda: run_es_server(WEB_BIND, ES_PORT), daemon=True).start()
    admin_post('INFO', f'ES server active on {WEB_BIND}:{ES_PORT}', 'ES')

def setup_signal_handlers():
    def _handle(sig, frame):
        admin_post('INFO', f'Received signal {sig}; shutting down gracefully...', 'SYS')
        try:
            # Allow background threads to finish; sockets will close on process exit
            time.sleep(0.5)
        finally:
            os._exit(0)
    for s in (getattr(signal, 'SIGINT', None), getattr(signal, 'SIGTERM', None)):
        if s is not None:
            try:
                signal.signal(s, _handle)
            except Exception:
                pass

if __name__ == '__main__':
    admin_post('INFO', '__BANNER__', 'SYS')
    admin_post('INFO', 'Chimera Hardened v3.2 starting...', 'SYS')
    # Create decoy trees (FTP/SSH) after all helpers are defined and logging is ready
    try:
        create_ftp_tree()
        create_ssh_tree()
        admin_post('INFO', 'Decoy trees created (FTP/SSH)', 'INIT')
        admin_post('INFO', f'Multi-stage password chain: WEB->{WEB_HINT} -> FTP->{FTP_HINT} -> SSH->{SSH_HINT} -> Admin->{ESCALATION_HINT}', 'INIT')
        siem_emit({'event':'decoy_trees_created','password_chain':PASSWORD_CHAIN})
    except Exception as e:
        admin_post('ERROR', f'Decoy tree creation failed: {e}', 'INIT')
    setup_signal_handlers()
    start_services()
    try:
        last_hb = 0
        while True:
            time.sleep(1)
            now = time.time()
            if HEARTBEAT_ENABLED and (now - last_hb) >= HEARTBEAT_INTERVAL:
                last_hb = now
                uptime = int(now - START_TIME)
                if HEARTBEAT_VERBOSE:
                    admin_post('INFO', f'heartbeat uptime={uptime}s active_services=[WEB,NET,SMB,SMTP,REDIS,ES] instance={INSTANCE_ID}', 'HB')
                else:
                    admin_post('INFO', f'uptime={uptime}s', 'HB')
    except KeyboardInterrupt:
        admin_post('INFO', 'Shutdown requested', 'SYS')
