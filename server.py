import base64
import binascii
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
import uuid
from collections import defaultdict, deque
from contextlib import contextmanager
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from pypdf import PdfReader
from pypdf.errors import PdfReadError


ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", ROOT / "data")).resolve()
DB_PATH = DATA_DIR / "eisa.sqlite3"
REPORT_DIR = DATA_DIR / "reports"
PORT = int(os.environ.get("PORT", "8080"))
SUBMISSION_DELAY = 5 * 60
MAX_EXAM_ATTEMPTS = 5
SESSION_HOURS = 12
MAX_BODY = 8 * 1024 * 1024
MAX_CREDENTIALS_PDF = 4 * 1024 * 1024
PBKDF2_ROUNDS = 310_000
login_attempts = defaultdict(deque)
login_lock = threading.Lock()
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)
TEACHER_PASSWORD = os.environ.get("TEACHER_PASSWORD", "")
if len(TEACHER_PASSWORD) < 12:
    raise RuntimeError("Set TEACHER_PASSWORD to a value of at least 12 characters.")


@contextmanager
def db():
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 30000")
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


with db() as connection:
    connection.executescript(
        """
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS students (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, salt BLOB NOT NULL,
            password_hash BLOB NOT NULL, created_at REAL NOT NULL, active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS progress (
            student_id TEXT PRIMARY KEY REFERENCES students(id),
            state_json TEXT NOT NULL, updated_at REAL NOT NULL, attempt_number INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS submissions (
            id TEXT PRIMARY KEY, student_id TEXT NOT NULL REFERENCES students(id),
            submitted_at REAL NOT NULL, release_at REAL NOT NULL, state_json TEXT NOT NULL,
            passed INTEGER NOT NULL, total INTEGER NOT NULL, score INTEGER NOT NULL,
            released INTEGER NOT NULL DEFAULT 0, pdf_path TEXT, attempt_number INTEGER NOT NULL DEFAULT 1
        );
        CREATE INDEX IF NOT EXISTS submissions_student ON submissions(student_id, submitted_at DESC);
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, role TEXT NOT NULL, user_id TEXT NOT NULL,
            expires_at REAL NOT NULL
        );
        CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
        """
    )
    for table in ("progress", "submissions"):
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}
        if "attempt_number" not in columns:
            connection.execute(
                f"ALTER TABLE {table} ADD COLUMN attempt_number INTEGER NOT NULL DEFAULT 1"
            )


def password_digest(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)


def safe_state(raw):
    if not isinstance(raw, dict):
        raise ValueError("A progress object is required.")
    if len(json.dumps(raw, ensure_ascii=False)) > MAX_BODY:
        raise ValueError("Progress is too large to save.")
    return raw


def parse_credentials_pdf(pdf_bytes):
    if not pdf_bytes.startswith(b"%PDF-"):
        raise ValueError("The uploaded file is not a PDF.")
    reader = PdfReader(io.BytesIO(pdf_bytes), strict=False)
    if reader.is_encrypted:
        raise ValueError("Password-protected PDFs are not supported.")
    pages = reader.pages
    if not pages or len(pages) > 10:
        raise ValueError("The credentials PDF must contain between 1 and 10 pages.")
    records = []
    seen_ids = set()
    header_found = False
    row_pattern = re.compile(r"\s*(.*?)\s+(EISA-[A-F0-9]{6})\s+(\S+)\s*", re.I)
    for page in pages:
        text = page.extract_text(extraction_mode="layout") or ""
        for line in text.splitlines():
            if not line.strip():
                continue
            folded = line.casefold()
            if "student id" in folded and "password" in folded:
                header_found = True
                continue
            match = row_pattern.fullmatch(line)
            if not match:
                raise ValueError("The PDF must contain a simple table with student name, ID, and password columns.")
            name, student_id, password = match.groups()
            student_id = student_id.upper()
            name = " ".join(name.split())
            if not name or len(name) > 100 or not password or len(password) > 256:
                raise ValueError("A student row has a missing or invalid name or password.")
            if student_id in seen_ids:
                raise ValueError("The PDF contains a duplicate student ID.")
            seen_ids.add(student_id)
            records.append({"id": student_id, "name": name, "password": password})
            if len(records) > 50:
                raise ValueError("The PDF may contain no more than 50 student accounts.")
    if not header_found or not records:
        raise ValueError("No student credential table was found in the PDF.")
    return records


def import_student_records(records):
    if not isinstance(records, list) or not records or len(records) > 50:
        raise ValueError("Provide between 1 and 50 saved student records.")
    normalized = []
    seen_ids = set()
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Each saved student record must include an ID, name, and password.")
        student_id = str(record.get("id", "")).strip().upper()
        name = " ".join(str(record.get("name", "")).split())[:100]
        password = str(record.get("password", ""))
        if not re.fullmatch(r"EISA-[A-F0-9]{6}", student_id):
            raise ValueError("Each saved student ID must use the EISA-XXXXXX format.")
        if not name or not password or len(password) > 256:
            raise ValueError("Each saved student record must include a name and a password of up to 256 characters.")
        if student_id in seen_ids:
            raise ValueError("The saved records contain a duplicate student ID.")
        seen_ids.add(student_id)
        normalized.append((student_id, name, password))
    created = 0
    skipped = 0
    with db() as connection:
        connection.execute("BEGIN IMMEDIATE")
        for student_id, name, password in normalized:
            if student_record(connection, student_id):
                skipped += 1
                continue
            salt = secrets.token_bytes(16)
            connection.execute(
                "INSERT INTO students (id, name, salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                (student_id, name, salt, password_digest(password, salt), time.time()),
            )
            created += 1
    return {"created": created, "skipped": skipped}


def student_record(connection, student_id):
    return connection.execute(
        "SELECT id, name, salt, password_hash, active FROM students WHERE id = ?",
        (student_id,),
    ).fetchone()


def latest_submission(connection, student_id):
    return connection.execute(
        "SELECT * FROM submissions WHERE student_id = ? ORDER BY submitted_at DESC LIMIT 1",
        (student_id,),
    ).fetchone()


def submission_count(connection, student_id):
    return connection.execute(
        "SELECT COUNT(*) FROM submissions WHERE student_id = ?",
        (student_id,),
    ).fetchone()[0]


THEORY_QUESTION_IDS = {
    "1.1", "1.2", "1.3", "1.4",
    "2.1", "2.2", "2.3", "2.4", "2.5",
    "3.1", "3.2", "3.3", "3.4",
}


def validated_theory_answers(raw):
    if not isinstance(raw, dict):
        raise ValueError("Theory answers must be provided as an object.")
    if any(key not in THEORY_QUESTION_IDS for key in raw):
        raise ValueError("The theory answers contain an unknown question ID.")
    answers = {}
    for question_id, answer in raw.items():
        if not isinstance(answer, str) or len(answer) > 12000:
            raise ValueError("Each theory answer must be text no longer than 12,000 characters.")
        answers[question_id] = answer
    return answers


def get_vm(state):
    vms = state.get("vms") or []
    return next((vm for vm in vms if re.search(r"traffic-node-1", str(vm.get("name", "")), re.I)), None) or (vms[0] if vms else {})


def at(value, *keys, default=None):
    for key in keys:
        if not isinstance(value, dict):
            return default
        value = value.get(key)
    return value if value is not None else default


def traffic_log_partition(vm):
    disks = vm.get("dataDisks") or []
    if any(disk.get("lun") == 0 and disk.get("size") == 8 for disk in disks):
        return "sdc1"
    return None


def has_persistent_fstab_mount(linux, fstab, mountpoint, partition):
    parts = linux.get("parts") or {}
    part = parts.get(partition) or {}
    mounts = linux.get("mounts") or {}
    if not part.get("uuid") or part.get("fs") != "ext4" or mounts.get(mountpoint) != partition:
        return False
    expected_source = f"UUID={part['uuid']}"
    for line in str(fstab).splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 4 and fields[0] == expected_source and fields[1] == mountpoint and fields[2] == "ext4":
            return True
    return False


def evaluate(state):
    vm = get_vm(state)
    linux = vm.get("linux") or {}
    flags = state.get("flags") or {}
    users = linux.get("users") or {}
    parts = linux.get("parts") or {}
    mounts = linux.get("mounts") or {}
    files = linux.get("fs") or {}
    disks = vm.get("dataDisks") or []
    research = state.get("research") or {}
    fstab = at(files, "/etc/fstab", "c", default="")
    cam = users.get("camera_bot") or {}
    cam_file = files.get("/var/traffic_logs/cam_feed_01.log") or {}
    log_part = mounts.get("/var/traffic_logs")
    expected_log_part = traffic_log_partition(vm)
    log_memo = files.get(f"/home/{vm.get('admin', '')}/security_memo.txt") or {}
    memo = str(log_memo.get("c", "")).lower()
    rules = at(linux, "ufw", "rules", default=[]) or []
    ufw = linux.get("ufw") or {}
    ssh_allowed = any(r.get("port") == 22 and r.get("action") == "allow" for r in rules)
    ftp_denied = any(r.get("port") == 21 and r.get("action") == "deny" for r in rules)
    checks = [
        bool(next((v for v in state.get("vms", []) if re.match(r"^traffic-node-1", str(v.get("name", "")), re.I) and v.get("status") == "Running"), None)),
        vm.get("size") == "Standard_B1ms",
        str(vm.get("image", "")).startswith("Ubuntu") and bool(vm.get("pip")) and bool(vm.get("vnet")),
        bool(flags.get("sshConnected")),
        vm.get("privateIp") == "10.0.0.50" and vm.get("ipAlloc") == "Static",
        bool(flags.get("ipShown50")),
        bool(at(linux, "services", "nginx", "run")),
        bool(flags.get("browserOK")),
        any(d.get("lun") == 0 and d.get("size") == 8 for d in disks),
        bool(expected_log_part and log_part == expected_log_part and at(parts, expected_log_part, "fs") == "ext4"),
        bool(expected_log_part and log_part == expected_log_part and flags.get("rebootMountOK") and has_persistent_fstab_mount(linux, fstab, "/var/traffic_logs", expected_log_part)),
        bool(cam and isinstance(cam.get("uid"), (int, float)) and cam["uid"] < 1000 and re.search(r"nologin|false", str(cam.get("shell", "")))),
        cam_file.get("o") == "camera_bot",
        bool(flags.get("cpuObserved")),
        bool(flags.get("memObserved") or flags.get("ioObserved")),
        bool(flags.get("metricsHigh")),
        bool(flags.get("aptUpdate")),
        bool(flags.get("aptList")),
        not bool(flags.get("aptUpgradeRan")),
        bool(flags.get("dfBefore99")),
        bool(flags.get("portalResize25")),
        bool(flags.get("growpart") and flags.get("resize2fs")),
        bool(flags.get("dfAfter25") and files.get("/var/replays/grand_final.replay")),
        bool(flags.get("caseBefore")),
        bool((lambda n: n and (int(n.get("mode", 0)) & 0o777) == 0o700 and n.get("o") == "root")(files.get("/home/evidence/case_files"))),
        bool(re.search(r"2010-20103", str(research.get("cve", ""))) and re.search(r"backdoor", str(research.get("name", "")), re.I)),
        bool(re.search(r"9\.8|critical", str(research.get("severity", "")), re.I) and re.search(r"nvd|cve|exploit", str(research.get("source", "")), re.I)),
        bool(log_memo and re.search(r"vulnerab|risk", memo) and re.search(r"immediate", memo) and re.search(r"long", memo) and re.search(r"verif", memo)),
        bool(flags.get("ftpBefore")),
        bool(ufw.get("enabled") and ssh_allowed and ftp_denied),
        bool(flags.get("sshAfterUfw") and flags.get("tnc21Fail")),
    ]
    return checks


CHECK_LABELS = [
    "VM named Traffic-Node-1 exists and is running",
    "Size is 1 vCPU and 2 GiB RAM (Standard_B1ms)",
    "Ubuntu Linux image with a public IP and a virtual network",
    "Connected to the VM over SSH",
    "Private IP set to Static 10.0.0.50 on the NIC",
    "Shown 10.0.0.50 inside the VM (ip addr)",
    "nginx installed and running",
    "Control panel opened in the browser via the public IP",
    "8 GiB data disk attached",
    "Partition formatted ext4 and mounted at /var/traffic_logs",
    "Mount is permanent (/etc/fstab) and survived a reboot",
    "System user camera_bot exists (no login shell)",
    "/var/traffic_logs/cam_feed_01.log owned by camera_bot",
    "CPU load created and watched live (top/htop) above 90%",
    "Memory or disk load watched (free/vmstat/iostat)",
    "Spike seen in the portal metrics chart",
    "Package lists refreshed (sudo apt update)",
    "Upgradable packages listed (apt list --upgradable)",
    "Updates were NOT installed during the exam",
    "Recorded the full disk before (df -h at 99%)",
    "Replays disk resized to 25 GiB in the portal",
    "Partition and file system grown (growpart + resize2fs)",
    "df -h shows about 25G and the replay file is intact",
    "Recorded case_files before the fix (ls -l showing 755)",
    "case_files is now 700 owned by root",
    "Vulnerability name and CVE recorded",
    "Severity and source recorded",
    "~/security_memo.txt covers risk, immediate, long-term and verification",
    "Open ports recorded before the firewall (ss showing :21)",
    "ufw active: SSH 22 allowed and FTP 21 denied",
    "Verified: new SSH login works and port 21 test fails",
]


def pdf_escape(text):
    text = unicodedata.normalize("NFKD", str(text)).encode("cp1252", "replace").decode("cp1252")
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf(student_name, student_id, submitted_at, score, passed, checks, state, attempt_number):
    started_at = state.get("startedAt")
    duration = max(0, int(submitted_at - started_at / 1000)) if isinstance(started_at, (int, float)) else 0
    lines = [
        "EISA Cloud Lab - Mock exam result",
        f"Student: {student_name} ({student_id})",
        f"Attempt: {attempt_number}/{MAX_EXAM_ATTEMPTS}",
        f"Submitted: {datetime.fromtimestamp(submitted_at, timezone.utc).astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"Time used: {duration // 3600:02d}:{duration // 60 % 60:02d}:{duration % 60:02d}",
        f"Final mark: {score}/100   Practical checks passed: {passed}/{len(checks)}",
        "", "SECTION A - THEORY RESPONSES",
    ]
    theory_answers = state.get("theoryAnswers") or {}
    if not isinstance(theory_answers, dict):
        theory_answers = {}
    for question_id in (
        "1.1", "1.2", "1.3", "1.4",
        "2.1", "2.2", "2.3", "2.4", "2.5",
        "3.1", "3.2", "3.3", "3.4",
    ):
        answer = theory_answers.get(question_id)
        lines.append(f"Question {question_id}:")
        lines.extend(str(answer).splitlines() if isinstance(answer, str) and answer.strip() else ["No response."])
    research = state.get("research") or {}
    lines.extend([
        "",
        "SECTION B - PRACTICAL RESULTS",
        "",
        "RESEARCH RESPONSE",
        f"Vulnerability: {research.get('name', '')}",
        f"CVE: {research.get('cve', '')}",
        f"Severity: {research.get('severity', '')}",
        f"Source: {research.get('source', '')}",
    ])
    lines.extend(["", "EVIDENCE ITEMS"])
    evidence = state.get("evidence") or []
    if not evidence:
        lines.append("No evidence items were captured.")
    for item in reversed(evidence):
        stamp = item.get("t")
        when = datetime.fromtimestamp(stamp / 1000, timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z") if isinstance(stamp, (int, float)) else ""
        lines.append(f"{when} [{item.get('task', 'General')}] {item.get('title', 'Evidence')}")
        lines.extend(str(item.get("body", "")).splitlines())
    lines.extend([
        "",
        "AUTOMATED SIMULATOR RESULT",
        "This mark is calculated from the simulator's automatic checks. It is not a",
        "manual assessment of Section A theory answers, research quality, or real cloud work.",
        "",
        "PRACTICAL CHECKS",
    ])
    for label, result in zip(CHECK_LABELS, checks):
        lines.append(f"[{'PASS' if result else 'NOT PASSED'}] {label}")
    wrapped = []
    for line in lines:
        chunks = [line[i:i + 105] for i in range(0, max(1, len(line)), 105)]
        wrapped.extend(chunks)
    pages = [wrapped[i:i + 51] for i in range(0, len(wrapped), 51)] or [[]]
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        None,
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    page_refs = []
    for page_lines in pages:
        page_obj = len(objects) + 1
        stream_obj = page_obj + 1
        page_refs.append(f"{page_obj} 0 R")
        content = ["BT", "/F1 9 Tf", "50 790 Td", "12 TL"]
        for line in page_lines:
            content.append(f"({pdf_escape(line)}) Tj")
            content.append("T*")
        content.append("ET")
        stream = "\n".join(content).encode("cp1252", "replace")
        objects.append(f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {stream_obj} 0 R >>".encode())
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode() + stream + b"\nendstream")
    objects[1] = f"<< /Type /Pages /Kids [{' '.join(page_refs)}] /Count {len(page_refs)} >>".encode()
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for number, obj in enumerate(objects, 1):
        offsets.append(len(output))
        output.extend(f"{number} 0 obj\n".encode() + obj + b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode())
    output.extend(f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode())
    return bytes(output)


def release_due(connection, submission):
    if submission["released"] or time.time() < submission["release_at"]:
        return submission
    state = json.loads(submission["state_json"])
    checks = evaluate(state)
    passed = sum(checks)
    score = int(passed * 100 / len(checks) + 0.5)
    student = student_record(connection, submission["student_id"])
    path = REPORT_DIR / f"{submission['id']}.pdf"
    write_submission_pdf(path, student, submission, score, passed, checks, state)
    connection.execute(
        "UPDATE submissions SET passed = ?, total = ?, score = ?, released = 1, pdf_path = ? WHERE id = ?",
        (passed, len(checks), score, str(path), submission["id"]),
    )
    return connection.execute("SELECT * FROM submissions WHERE id = ?", (submission["id"],)).fetchone()


def write_submission_pdf(path, student, submission, score, passed, checks, state):
    pdf = build_pdf(
        student["name"], student["id"], submission["submitted_at"],
        score, passed, checks, state, submission["attempt_number"],
    )
    temporary = path.with_suffix(".tmp")
    temporary.write_bytes(pdf)
    os.replace(temporary, path)


def release_worker():
    while True:
        try:
            with db() as connection:
                due = connection.execute(
                    "SELECT * FROM submissions WHERE released = 0 AND release_at <= ?",
                    (time.time(),),
                ).fetchall()
                for submission in due:
                    release_due(connection, submission)
        except Exception as error:
            print(f"Result release error: {error}", flush=True)
        time.sleep(1)


threading.Thread(target=release_worker, daemon=True).start()


class Handler(BaseHTTPRequestHandler):
    server_version = "EISAExam/1.0"

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} {fmt % args}", flush=True)

    def send_json(self, status, value, headers=None):
        payload = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if headers:
            for key, val in headers.items():
                self.send_header(key, val)
        self.end_headers()
        self.wfile.write(payload)

    def body_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        if length < 0 or length > MAX_BODY:
            raise ValueError("Request body exceeds the allowed size.")
        try:
            value = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError as error:
            raise ValueError("Request body must be valid JSON.") from error
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object.")
        return value

    def cookie_token(self):
        for part in self.headers.get("Cookie", "").split(";"):
            key, _, value = part.strip().partition("=")
            if key == "eisa_session":
                return value
        return ""

    def auth(self, required_role=None):
        token = self.cookie_token()
        if not token:
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with db() as connection:
            session = connection.execute(
                "SELECT role, user_id, expires_at FROM sessions WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if not session or session["expires_at"] < time.time():
                connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
                return None
            if required_role and session["role"] != required_role:
                return None
            if session["role"] == "student":
                student = student_record(connection, session["user_id"])
                if not student or not student["active"]:
                    return None
            return {"role": session["role"], "user_id": session["user_id"], "token_hash": token_hash}

    def require(self, role=None):
        user = self.auth(role)
        if not user:
            self.send_json(401, {"error": "Please sign in again."})
        return user

    def check_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        expected = self.headers.get("X-Forwarded-Host", self.headers.get("Host", ""))
        parsed = urlparse(origin)
        return parsed.netloc.lower() == expected.lower()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)
        if path.startswith("/api/"):
            return self.api_get(path, parse_qs(parsed.query))
        if path in ("/", "/dashboard.html"):
            path = "/index.html"
        if path not in ("/index.html", "/teacher.html"):
            self.send_error(404)
            return
        target = ROOT / path.lstrip("/")
        if not target.is_file():
            self.send_error(404)
            return
        content = target.read_bytes()
        mime = "text/html; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.end_headers()
        self.wfile.write(content)

    def api_get(self, path, query):
        if path == "/api/health":
            return self.send_json(200, {"ok": True})
        if path == "/api/me":
            user = self.auth()
            if not user:
                return self.send_json(200, {"user": None})
            if user["role"] == "teacher":
                return self.send_json(200, {"user": {"role": "teacher", "name": "Teacher"}})
            with db() as connection:
                student = student_record(connection, user["user_id"])
                used = submission_count(connection, student["id"])
                progress = connection.execute(
                    "SELECT attempt_number FROM progress WHERE student_id = ?",
                    (student["id"],),
                ).fetchone()
                active_attempt = bool(
                    used < MAX_EXAM_ATTEMPTS
                    and progress
                    and progress["attempt_number"] == used + 1
                )
                submission = None if active_attempt else latest_submission(connection, student["id"])
                if submission:
                    submission = release_due(connection, submission)
                return self.send_json(200, {
                    "user": {"role": "student", "id": student["id"], "name": student["name"]},
                    "submission": self.submission_json(submission, used) if submission else None,
                    "attemptsUsed": used,
                    "attemptsRemaining": MAX_EXAM_ATTEMPTS - used,
                    "activeAttemptNumber": used + 1 if active_attempt else None,
                })
        if path == "/api/state":
            user = self.require("student")
            if not user:
                return
            with db() as connection:
                row = connection.execute("SELECT state_json FROM progress WHERE student_id = ?", (user["user_id"],)).fetchone()
            return self.send_json(200, {"state": json.loads(row["state_json"]) if row else None})
        if path == "/api/submission":
            user = self.require("student")
            if not user:
                return
            with db() as connection:
                submission = latest_submission(connection, user["user_id"])
                if not submission:
                    return self.send_json(404, {"error": "No submission found."})
                submission = release_due(connection, submission)
                used = submission_count(connection, user["user_id"])
                return self.send_json(200, self.submission_json(submission, used))
        if path == "/api/my-pdf":
            user = self.require("student")
            if not user:
                return
            with db() as connection:
                submission = latest_submission(connection, user["user_id"])
                if not submission:
                    return self.send_json(404, {"error": "No submission found."})
                submission = release_due(connection, submission)
                if not submission["released"]:
                    return self.send_json(403, {"error": "Your PDF will be available when your mark is released."})
                filename = f"{user['user_id']}-attempt-{submission['attempt_number']}-mock-exam-result.pdf"
                return self.send_pdf(submission["pdf_path"], filename, query.get("inline") == ["1"])
        if path == "/api/teacher/students":
            user = self.require("teacher")
            if not user:
                return
            with db() as connection:
                students = connection.execute(
                    """SELECT s.id, s.name, s.created_at, s.active, x.id AS submission_id,
                    x.attempt_number, x.submitted_at, x.release_at, x.released, x.passed,
                    x.total, x.score,
                    (SELECT COUNT(*) FROM submissions WHERE student_id = s.id) AS attempts_used
                    FROM students s LEFT JOIN submissions x ON x.student_id = s.id
                    ORDER BY s.name COLLATE NOCASE, x.attempt_number"""
                ).fetchall()
            return self.send_json(200, {"students": [dict(row) for row in students]})
        if path.startswith("/api/teacher/pdf/"):
            user = self.require("teacher")
            if not user:
                return
            submission_id = path.rsplit("/", 1)[-1]
            with db() as connection:
                submission = connection.execute("SELECT * FROM submissions WHERE id = ?", (submission_id,)).fetchone()
                if not submission:
                    return self.send_json(404, {"error": "Submission not found."})
                submission = release_due(connection, submission)
                if not submission["released"]:
                    return self.send_json(403, {"error": "The mark and PDF are not released yet."})
                filename = f"{submission['student_id']}-attempt-{submission['attempt_number']}-mock-exam-result.pdf"
                return self.send_pdf(submission["pdf_path"], filename)
        self.send_json(404, {"error": "API endpoint not found."})

    def submission_json(self, submission, attempts_used=None):
        state = json.loads(submission["state_json"])
        return {
            "id": submission["id"], "submittedAt": submission["submitted_at"],
            "releaseAt": submission["release_at"], "released": bool(submission["released"]),
            "score": submission["score"] if submission["released"] else None,
            "passed": submission["passed"] if submission["released"] else None,
            "total": submission["total"],
            "attemptNumber": submission["attempt_number"],
            "attemptsUsed": attempts_used if attempts_used is not None else submission["attempt_number"],
            "attemptsRemaining": max(0, MAX_EXAM_ATTEMPTS - (attempts_used if attempts_used is not None else submission["attempt_number"])),
            "theoryAnswers": state.get("theoryAnswers") if isinstance(state.get("theoryAnswers"), dict) else {},
        }

    def send_pdf(self, filepath, filename, inline=False):
        path = Path(filepath or "")
        if not path.is_file() or path.parent.resolve() != REPORT_DIR.resolve():
            return self.send_json(404, {"error": "PDF not found."})
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/pdf")
        disposition = "inline" if inline else "attachment"
        self.send_header("Content-Disposition", f'{disposition}; filename="{filename}"')
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "private, no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if not self.check_origin():
            return self.send_json(403, {"error": "Request origin was rejected."})
        path = urlparse(self.path).path
        try:
            data = self.body_json()
        except (ValueError, UnicodeDecodeError) as error:
            return self.send_json(400, {"error": str(error)})
        if path == "/api/login":
            return self.login(data)
        if path == "/api/logout":
            token = self.cookie_token()
            if token:
                with db() as connection:
                    connection.execute("DELETE FROM sessions WHERE token_hash = ?", (hashlib.sha256(token.encode()).hexdigest(),))
            return self.send_json(200, {"ok": True}, {"Set-Cookie": self.clear_cookie()})
        if path == "/api/attempts/start":
            user = self.require("student")
            if not user:
                return
            try:
                state = safe_state(data.get("state"))
            except ValueError as error:
                return self.send_json(400, {"error": str(error)})
            with db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                used = submission_count(connection, user["user_id"])
                progress = connection.execute(
                    "SELECT attempt_number FROM progress WHERE student_id = ?",
                    (user["user_id"],),
                ).fetchone()
                if used == 0:
                    return self.send_json(409, {"error": "Submit your current attempt before starting another."})
                if used >= MAX_EXAM_ATTEMPTS:
                    return self.send_json(409, {"error": f"You have used all {MAX_EXAM_ATTEMPTS} exam attempts."})
                if progress and progress["attempt_number"] == used + 1:
                    return self.send_json(409, {"error": "Your next exam attempt has already started."})
                if not latest_submission(connection, user["user_id"]):
                    return self.send_json(409, {"error": "Submit your current attempt before starting another."})
                attempt_number = used + 1
                connection.execute(
                    """INSERT INTO progress (student_id, state_json, updated_at, attempt_number)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(student_id) DO UPDATE SET state_json = excluded.state_json,
                    updated_at = excluded.updated_at, attempt_number = excluded.attempt_number""",
                    (user["user_id"], json.dumps(state, ensure_ascii=False), time.time(), attempt_number),
                )
            return self.send_json(201, {
                "attemptNumber": attempt_number,
                "attemptsRemaining": MAX_EXAM_ATTEMPTS - used,
            })
        if path == "/api/submit":
            user = self.require("student")
            if not user:
                return
            try:
                state = safe_state(data.get("state"))
            except ValueError as error:
                return self.send_json(400, {"error": str(error)})
            with db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                used = submission_count(connection, user["user_id"])
                if used >= MAX_EXAM_ATTEMPTS:
                    return self.send_json(409, {"error": f"You have used all {MAX_EXAM_ATTEMPTS} exam attempts."})
                progress = connection.execute(
                    "SELECT attempt_number FROM progress WHERE student_id = ?",
                    (user["user_id"],),
                ).fetchone()
                if not progress or progress["attempt_number"] != used + 1:
                    return self.send_json(409, {"error": "The current exam attempt is not active. Refresh the page and try again."})
                now = time.time()
                checks = evaluate(state)
                passed = sum(checks)
                submission_id = uuid.uuid4().hex
                connection.execute(
                    """INSERT INTO submissions
                    (id, student_id, submitted_at, release_at, state_json, passed, total, score, attempt_number)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (submission_id, user["user_id"], now, now + SUBMISSION_DELAY,
                     json.dumps(state, ensure_ascii=False), passed, len(checks),
                     int(passed * 100 / len(checks) + 0.5), used + 1),
                )
                submission = latest_submission(connection, user["user_id"])
                return self.send_json(201, self.submission_json(submission, used + 1))
        if path == "/api/teacher/students":
            user = self.require("teacher")
            if not user:
                return
            names = data.get("names")
            if not isinstance(names, list) or not names or len(names) > 50:
                return self.send_json(400, {"error": "Provide between 1 and 50 student names."})
            credentials = []
            with db() as connection:
                for raw_name in names:
                    name = " ".join(str(raw_name).split())[:100]
                    if not name:
                        continue
                    student_id = "EISA-" + secrets.token_hex(3).upper()
                    while student_record(connection, student_id):
                        student_id = "EISA-" + secrets.token_hex(3).upper()
                    password = secrets.token_urlsafe(9)
                    salt = secrets.token_bytes(16)
                    connection.execute(
                        "INSERT INTO students (id, name, salt, password_hash, created_at) VALUES (?, ?, ?, ?, ?)",
                        (student_id, name, salt, password_digest(password, salt), time.time()),
                    )
                    credentials.append({"id": student_id, "name": name, "password": password})
            if not credentials:
                return self.send_json(400, {"error": "Enter at least one non-empty student name."})
            return self.send_json(201, {"students": credentials})
        if path == "/api/teacher/students/import":
            user = self.require("teacher")
            if not user:
                return
            try:
                result = import_student_records(data.get("students"))
            except ValueError as error:
                return self.send_json(400, {"error": str(error)})
            return self.send_json(201, result)
        if path == "/api/teacher/students/import-pdf":
            user = self.require("teacher")
            if not user:
                return
            encoded_pdf = data.get("pdf")
            if not isinstance(encoded_pdf, str):
                return self.send_json(400, {"error": "Upload a PDF containing the saved student credentials."})
            try:
                pdf_bytes = base64.b64decode(encoded_pdf, validate=True)
                if len(pdf_bytes) > MAX_CREDENTIALS_PDF:
                    return self.send_json(400, {"error": "The PDF must be no larger than 4 MB."})
                records = parse_credentials_pdf(pdf_bytes)
                result = import_student_records(records)
            except (binascii.Error, ValueError, PdfReadError) as error:
                return self.send_json(400, {"error": str(error) or "The uploaded PDF could not be read."})
            return self.send_json(201, result)
        self.send_json(404, {"error": "API endpoint not found."})

    def login(self, data):
        now = time.time()
        role = data.get("role")
        requested_id = str(data.get("id", "")).strip().upper()
        rate_key = f"student:{requested_id}" if role == "student" else "teacher"
        with login_lock:
            attempts = login_attempts[rate_key]
            while attempts and attempts[0] < now - 60:
                attempts.popleft()
            if len(attempts) >= 10:
                return self.send_json(429, {"error": "Too many sign-in attempts. Wait one minute and try again."})
            attempts.append(now)
        password = str(data.get("password", ""))
        user_id = requested_id
        if len(password) > 256:
            return self.send_json(400, {"error": "Invalid credentials."})
        valid = False
        if role == "teacher":
            valid = hmac.compare_digest(password.encode(), TEACHER_PASSWORD.encode())
            user_id = "teacher"
        elif role == "student":
            with db() as connection:
                student = student_record(connection, user_id)
                if student and student["active"]:
                    valid = hmac.compare_digest(password_digest(password, student["salt"]), student["password_hash"])
        if not valid:
            return self.send_json(401, {"error": "The ID or password is not correct."})
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        expires = time.time() + SESSION_HOURS * 3600
        with db() as connection:
            connection.execute(
                "INSERT INTO sessions (token_hash, role, user_id, expires_at) VALUES (?, ?, ?, ?)",
                (token_hash, role, user_id, expires),
            )
        secure = "; Secure" if self.headers.get("X-Forwarded-Proto", "").lower() == "https" else ""
        cookie = f"eisa_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESSION_HOURS * 3600}{secure}"
        return self.send_json(200, {"ok": True, "role": role}, {"Set-Cookie": cookie})

    def do_PUT(self):
        if not self.check_origin():
            return self.send_json(403, {"error": "Request origin was rejected."})
        path = urlparse(self.path).path
        if path == "/api/submission/theory":
            user = self.require("student")
            if not user:
                return
            try:
                answers = validated_theory_answers(self.body_json().get("answers"))
            except (ValueError, UnicodeDecodeError) as error:
                return self.send_json(400, {"error": str(error)})
            with db() as connection:
                connection.execute("BEGIN IMMEDIATE")
                submission = latest_submission(connection, user["user_id"])
                if not submission:
                    return self.send_json(404, {"error": "No submitted exam is available to update."})
                state = json.loads(submission["state_json"])
                state["theoryAnswers"] = answers
                state_json = json.dumps(state, ensure_ascii=False)
                connection.execute(
                    "UPDATE submissions SET state_json = ? WHERE id = ?",
                    (state_json, submission["id"]),
                )
                if submission["released"]:
                    checks = evaluate(state)
                    student = student_record(connection, user["user_id"])
                    pdf_path = REPORT_DIR / f"{submission['id']}.pdf"
                    write_submission_pdf(
                        pdf_path, student, submission, submission["score"],
                        submission["passed"], checks, state,
                    )
            return self.send_json(200, {"ok": True, "answers": answers})
        if path != "/api/state":
            return self.send_json(404, {"error": "API endpoint not found."})
        user = self.require("student")
        if not user:
            return
        try:
            state = safe_state(self.body_json().get("state"))
        except (ValueError, UnicodeDecodeError) as error:
            return self.send_json(400, {"error": str(error)})
        with db() as connection:
            connection.execute("BEGIN IMMEDIATE")
            used = submission_count(connection, user["user_id"])
            if used >= MAX_EXAM_ATTEMPTS:
                return self.send_json(409, {"error": f"You have used all {MAX_EXAM_ATTEMPTS} exam attempts."})
            progress = connection.execute(
                "SELECT attempt_number FROM progress WHERE student_id = ?",
                (user["user_id"],),
            ).fetchone()
            if (progress and progress["attempt_number"] != used + 1) or (not progress and used > 0):
                return self.send_json(409, {"error": "This exam attempt is locked. Start a new attempt to continue."})
            connection.execute(
                """INSERT INTO progress (student_id, state_json, updated_at, attempt_number) VALUES (?, ?, ?, ?)
                ON CONFLICT(student_id) DO UPDATE SET state_json = excluded.state_json, updated_at = excluded.updated_at""",
                (user["user_id"], json.dumps(state, ensure_ascii=False), time.time(), used + 1),
            )
        self.send_json(200, {"ok": True})

    def end_headers(self):
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        super().end_headers()

    def clear_cookie(self):
        return "eisa_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print(f"EISA exam server listening on port {PORT}; data stored at {DATA_DIR}", flush=True)
    Server(("0.0.0.0", PORT), Handler).serve_forever()
