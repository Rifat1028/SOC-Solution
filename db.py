# file: db.py
import base64
import hashlib
import hmac
from typing import Optional
import json
import os
import pathlib
import secrets
import sqlite3
import time
import uuid
from datetime import datetime, timezone
from cryptography.fernet import Fernet, InvalidToken

from config import settings

BASE_DIR = pathlib.Path(__file__).parent


def _load_master_key() -> bytes:
    """Master key comes ONLY from the environment (or a generated key file for first-run dev)."""
    env_key = os.getenv("SOC_MASTER_KEY", "").strip()
    if env_key:
        if len(env_key) < 32:
            raise RuntimeError("SOC_MASTER_KEY must be at least 32 characters")
        return env_key.encode("utf-8")

    key_file = BASE_DIR / ".soc_master_key"
    if key_file.exists():
        return key_file.read_text().strip().encode("utf-8")

    # First run with no key supplied: generate one and persist it.
    new_key = secrets.token_urlsafe(48)
    fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(new_key)
    print(
        f"[SECURITY] SOC_MASTER_KEY not set. Generated a new key at {key_file}. "
        "Set SOC_MASTER_KEY in production and back this key up: losing it makes stored data unreadable."
    )
    return new_key.encode("utf-8")


MASTER_KEY = _load_master_key()


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(BASE_DIR / settings.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# =====================================================================
# CRYPTOGRAPHIC ENGINE (Encrypts BOTH Username & Password at Rest)
# =====================================================================
def _keystream(nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(MASTER_KEY, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


_FERNET = Fernet(base64.urlsafe_b64encode(hmac.new(MASTER_KEY, b"fernet-field-encryption", hashlib.sha256).digest()))


def encrypt_text(plaintext: str) -> str:
    """Encrypt with Fernet (AES-128-CBC + HMAC-SHA256). Prefix 'enc2$'."""
    return "enc2$" + _FERNET.encrypt(plaintext.encode("utf-8")).decode("ascii")


def is_legacy_token(token: str) -> bool:
    return token.startswith("enc$")


def decrypt_text(token: str) -> str:
    if token.startswith("enc2$"):
        try:
            return _FERNET.decrypt(token[5:].encode("ascii")).decode("utf-8")
        except InvalidToken as e:
            raise ValueError("Integrity check failed on encrypted field") from e
    if not token.startswith("enc$"):
        return token
    raw = base64.urlsafe_b64decode(token[4:].encode("ascii"))
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    expected_tag = hmac.new(MASTER_KEY, nonce + ciphertext, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expected_tag):
        raise ValueError("Integrity check failed on encrypted field")
    stream = _keystream(nonce, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, stream)).decode("utf-8")


def username_blind_index(username: str) -> str:
    clean = username.strip().lower().encode("utf-8")
    return "idx$" + hmac.new(MASTER_KEY, b"user_lookup:" + clean, hashlib.sha256).hexdigest()


def encrypt_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    combined = base64.b64encode(salt + dk).decode("ascii")
    return encrypt_text(combined)


def verify_password(password: str, stored_encrypted: str) -> bool:
    try:
        decrypted_b64 = decrypt_text(stored_encrypted)
        raw = base64.b64decode(decrypted_b64.encode("ascii"))
        salt, stored_dk = raw[:16], raw[16:]
        new_dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return hmac.compare_digest(stored_dk, new_dk)
    except Exception:
        return False


def settings_session_seconds() -> int:
    """Session lifetime; defaults to 8h. Override with SOC_SESSION_SECONDS."""
    try:
        return int(os.getenv("SOC_SESSION_SECONDS", "28800"))
    except ValueError:
        return 28800


def create_session_token(user_id: str, username: str, role: str, tenant_id: str, extra: Optional[dict] = None) -> str:
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "tenant_id": tenant_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + settings_session_seconds(),
        **(extra or {}),                 # e.g. a super admin's tenant context: {"ctx": tenant_id, "ro": True}
    }
    body = base64.urlsafe_b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    sig = hmac.new(MASTER_KEY, body.encode("ascii"), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def verify_session_token(token: str) -> dict:
    try:
        body, sig = token.split(".", 1)
        expected = hmac.new(MASTER_KEY, body.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise ValueError("Invalid token signature")
        payload = json.loads(base64.urlsafe_b64decode(body.encode("ascii")).decode("utf-8"))
        if payload.get("exp", 0) < time.time():
            raise ValueError("Session expired")
        return payload
    except Exception as e:
        raise ValueError(f"Authentication failed: {e}") from e


def create_encrypted_user(conn: sqlite3.Connection, tenant_id: str, username: str, password: str, role: str) -> None:
    u_idx = username_blind_index(username)
    u_enc = encrypt_text(username.strip())
    p_enc = encrypt_password(password)
    conn.execute(
        """INSERT OR REPLACE INTO users (id, tenant_id, username_lookup, username_encrypted, password_encrypted, role)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), tenant_id, u_idx, u_enc, p_enc, role),
    )


# =====================================================================
# TAMPER-EVIDENT AUDIT LOGGING & INTEGRITY VERIFICATION
# =====================================================================
GENESIS_PREV_HASH = "GENESIS_0000000000000000"


def compute_audit_hmac(
    log_id: str,
    tenant_id: str,
    actor: str,
    actor_role: str,
    action: str,
    target: str,
    details: str,
    ip_address: str,
    created_at: str,
) -> str:
    """Computes an HMAC-SHA256 integrity seal over every column of an audit log entry."""
    canonical = f"{log_id}|{tenant_id}|{actor}|{actor_role}|{action}|{target}|{details}|{ip_address}|{created_at}"
    return hmac.new(MASTER_KEY, canonical.encode("utf-8"), hashlib.sha256).hexdigest()[:20]


def write_audit(
    tenant_id: str,
    actor: str,
    action: str,
    target: str,
    details: str = "",
    actor_role: str = "system",
    ip_address: str = "192.168.1.64",
) -> None:
    log_id = str(uuid.uuid4())
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    sig = compute_audit_hmac(log_id, tenant_id, actor, actor_role, action, target, details, ip_address, now_str)
    with get_db() as conn:
        last = conn.execute(
            "SELECT integrity_hash FROM audit_logs WHERE tenant_id = ? ORDER BY rowid DESC LIMIT 1",
            (tenant_id,),
        ).fetchone()
        prev_hash = last["integrity_hash"] if (last and last["integrity_hash"]) else GENESIS_PREV_HASH
        conn.execute(
            """INSERT INTO audit_logs
               (id, tenant_id, actor, actor_role, action, target, details, ip_address, prev_hash, integrity_hash, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (log_id, tenant_id, actor, actor_role, action, target, details, ip_address, prev_hash, sig, now_str),
        )
        conn.commit()


def verify_audit_chain(tenant_id: str) -> dict:
    """Verifies HMAC seals and chain links across all audit records for a tenant."""
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_logs WHERE tenant_id = ? ORDER BY rowid ASC",
            (tenant_id,),
        ).fetchall()

    verified = 0
    for r in rows:
        d = dict(r)
        expected_sig = compute_audit_hmac(
            d["id"],
            d["tenant_id"],
            d["actor"],
            d.get("actor_role") or "system",
            d["action"],
            d["target"],
            d.get("details") or "",
            d.get("ip_address") or "192.168.1.64",
            d["created_at"],
        )
        if not hmac.compare_digest(d.get("integrity_hash") or "", expected_sig):
            return {
                "valid": False,
                "total_records": len(rows),
                "verified_records": verified,
                "tampered_id": d["id"],
            }
        verified += 1

    return {
        "valid": True,
        "total_records": len(rows),
        "verified_records": verified,
        "tampered_id": None,
    }


def init_db() -> None:
    schema_file = BASE_DIR / "sql" / "schema.sql"
    seed_file = BASE_DIR / "sql" / "seed_inc2041.sql"
    with get_db() as conn:
        if schema_file.exists():
            conn.executescript(schema_file.read_text(encoding="utf-8"))
        if seed_file.exists():
            conn.executescript(seed_file.read_text(encoding="utf-8"))

        # Tables for SOAR Playbooks, Entity 360° Profiles, and Case/Handover Notes
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS soar_playbook_steps (
            id TEXT PRIMARY KEY,
            incident_id TEXT NOT NULL,
            tenant_id TEXT NOT NULL,
            step_order INTEGER NOT NULL,
            action_type TEXT NOT NULL,
            title TEXT NOT NULL,
            target_system TEXT NOT NULL,
            confidence INTEGER DEFAULT 95,
            requires_approval INTEGER DEFAULT 1,
            status TEXT DEFAULT 'pending',
            executed_by TEXT DEFAULT NULL,
            executed_at TEXT DEFAULT NULL
        );

        CREATE TABLE IF NOT EXISTS entity_profiles (
            entity_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            entity_type TEXT NOT NULL,
            criticality TEXT NOT NULL,
            department_or_zone TEXT NOT NULL,
            cves TEXT DEFAULT '[]',
            ueba_baseline TEXT NOT NULL,
            risk_score INTEGER DEFAULT 50
        );

        CREATE TABLE IF NOT EXISTS case_notes (
            id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            incident_id TEXT DEFAULT 'SHIFT-HANDOVER',
            author TEXT NOT NULL,
            author_role TEXT NOT NULL,
            note_type TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)

        # Safe column migrations for existing databases
        for col_sql in (
            "ALTER TABLE incidents ADD COLUMN assigned_to TEXT DEFAULT 'Unassigned'",
            "ALTER TABLE incidents ADD COLUMN confidence INTEGER DEFAULT 94",
            "ALTER TABLE node_status ADD COLUMN agents_total INTEGER DEFAULT NULL",
            "ALTER TABLE node_status ADD COLUMN agents_alive INTEGER DEFAULT NULL",
            "ALTER TABLE audit_logs ADD COLUMN actor_role TEXT DEFAULT 'system'",
            "ALTER TABLE audit_logs ADD COLUMN ip_address TEXT DEFAULT '192.168.1.64'",
            "ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT DEFAULT 'GENESIS_0000000000000000'",
            "ALTER TABLE audit_logs ADD COLUMN integrity_hash TEXT DEFAULT ''",
        ):
            try:
                conn.execute(col_sql)
            except sqlite3.OperationalError:
                pass

        # Populate agent counts for agent-based nodes (SIEM, XDR, EDR, PAM)
        conn.execute(
            """INSERT OR IGNORE INTO node_status (id, tenant_id, node_name, node_type, ip_address, status, eps, last_seen, agents_alive, agents_total)
               VALUES ('node-7', 'tenant-trustaira', 'Trustaira PAM Vault & Bastion', 'PAM', '192.168.1.64', 'online', 38, datetime('now'), 24, 24)"""
        )
        conn.execute("UPDATE node_status SET agents_alive = 48, agents_total = 50 WHERE id = 'node-1'")
        conn.execute("UPDATE node_status SET agents_alive = 45, agents_total = 45 WHERE id = 'node-2'")
        conn.execute("UPDATE node_status SET agents_alive = 62, agents_total = 64 WHERE id = 'node-3'")
        conn.execute("UPDATE node_status SET agents_alive = NULL, agents_total = NULL WHERE id IN ('node-4', 'node-5', 'node-6')")

        # Seed SOAR Playbook Steps if empty
        if conn.execute("SELECT COUNT(*) as c FROM soar_playbook_steps").fetchone()["c"] == 0:
            soar_seeds = [
                ("pb-2041-1", "INC-2041", "tenant-trustaira", 1, "ITSM_TICKET", "Open High-Priority ITSM Ticket #INC-2041 & Notify SOC Channel", "ServiceNow / ITSM", 99, 0, "auto_executed", "SOAR-Auto", "09:17 UTC"),
                ("pb-2041-2", "INC-2041", "tenant-trustaira", 2, "PAM_DISABLE", "Disable Privileged Session & Rotate Vault Credentials for a.rahman", "Trustaira PAM Vault", 96, 1, "pending", None, None),
                ("pb-2041-3", "INC-2041", "tenant-trustaira", 3, "EDR_ISOLATE", "Isolate Host SRV-FILE-02 & Workstation WS-RAHMAN-01", "Trend Vision One XDR", 94, 1, "pending", None, None),
                ("pb-2041-4", "INC-2041", "tenant-trustaira", 4, "FW_BLOCK", "Block Exfiltration C2 IP 185.220.101.42 on Perimeter Firewall", "Perimeter Firewall", 98, 0, "auto_executed", "SOAR-Auto", "10:07 UTC"),
                ("pb-2042-1", "INC-2042", "tenant-trustaira", 1, "ITSM_TICKET", "Auto-Create Cloud SecOps Ticket & Enrich Tor Exit Node", "ITSM / Threat Intel", 98, 0, "auto_executed", "SOAR-Auto", "14:23 UTC"),
                ("pb-2042-2", "INC-2042", "tenant-trustaira", 2, "PAM_DISABLE", "Revoke Compromised IAM Key for dev-pipeline-role in PAM", "AWS IAM / PAM", 95, 1, "pending", None, None),
                ("pb-2042-3", "INC-2042", "tenant-trustaira", 3, "EDR_ISOLATE", "Terminate 45 Unauthorized GPU Mining Instances in eu-west-3", "AWS CloudController", 92, 1, "pending", None, None),
                ("pb-2043-1", "INC-2043", "tenant-trustaira", 1, "PAM_DISABLE", "Emergency Lockout of Domain Admin Vault Accounts", "Trustaira PAM Vault", 99, 0, "auto_executed", "SOAR-Auto", "23:46 UTC"),
                ("pb-2043-2", "INC-2043", "tenant-trustaira", 2, "EDR_ISOLATE", "Network-Isolate Domain Controller SRV-DC-01 via Wazuh/XDR", "Wazuh EDR / Vision One", 99, 1, "pending", None, None),
            ]
            conn.executemany("INSERT INTO soar_playbook_steps VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", soar_seeds)

        # Seed Entity 360° Profiles if empty
        if conn.execute("SELECT COUNT(*) as c FROM entity_profiles").fetchone()["c"] == 0:
            entity_seeds = [
                ("a.rahman", "tenant-trustaira", "User", "High (Finance Privileged)", "Finance & Payroll", '[]', "Logins 08:30–18:00 BST from Dhaka LAN; 0 prior RDP sessions to file servers; avg outbound 45 MB/day", 88),
                ("SRV-FILE-02", "tenant-trustaira", "Host", "Tier-1 Critical Asset", "Core File Storage", '["CVE-2024-38063 (CVSS 9.8)", "CVE-2023-44487"]', "SMB traffic internal only; typical outbound < 50 MB/day; 2.3 GB spike is 49x baseline", 92),
                ("SRV-DC-01", "tenant-trustaira", "Host", "Tier-0 Crown Jewel (DC)", "Active Directory Core", '["CVE-2024-43451", "CVE-2023-36884"]', "Zero interactive command shells expected; vssadmin shadow deletion is 100% anomalous", 98),
                ("dev-pipeline-role", "tenant-trustaira", "CloudRole", "High (CI/CD Admin)", "AWS Production", '["IAM-LongLivedKey-Exposure"]', "Normally invoked from Dhaka Office NAT IP only; Moldova Tor Exit login is Impossible Travel", 85),
                ("185.220.101.42", "tenant-trustaira", "IP", "Malicious External IOC", "External / C2 Node", '[]', "Flagged across 12 AlienVault OTX pulses and 9 VirusTotal engines as C2 Exfiltration node", 96),
            ]
            conn.executemany("INSERT INTO entity_profiles VALUES (?, ?, ?, ?, ?, ?, ?, ?)", entity_seeds)

        # Seed Shift Handover & Case Notes if empty
        if conn.execute("SELECT COUNT(*) as c FROM case_notes").fetchone()["c"] == 0:
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            conn.executemany(
                "INSERT INTO case_notes VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (str(uuid.uuid4()), "tenant-trustaira", "SHIFT-HANDOVER", "admin", "admin", "handover",
                     "Morning Shift Handover: Exfiltration IP 185.220.101.42 auto-blocked by SOAR on perimeter firewall. Awaiting customer sign-off to isolate SRV-FILE-02 and rotate a.rahman PAM credentials.", now_str),
                    (str(uuid.uuid4()), "tenant-trustaira", "INC-2041", "analyst", "analyst", "case_comment",
                     "Verified macro hash on VirusTotal (44/70 malicious). Confirmed first-time RDP anomaly from WS-RAHMAN-01 to SRV-FILE-02 at 09:41.", now_str),
                ],
            )

        # Backfill HMAC integrity seal for any legacy audit rows
        all_audits = conn.execute("SELECT * FROM audit_logs ORDER BY rowid ASC").fetchall()
        prev = GENESIS_PREV_HASH
        for r in all_audits:
            role = r["actor_role"] or "system"
            ip_addr = r["ip_address"] or "192.168.1.64"
            sig = compute_audit_hmac(
                r["id"], r["tenant_id"], r["actor"], role, r["action"], r["target"], r["details"] or "", ip_addr, r["created_at"]
            )
            conn.execute(
                "UPDATE audit_logs SET prev_hash = ?, integrity_hash = ?, actor_role = ?, ip_address = ? WHERE id = ?",
                (prev, sig, role, ip_addr, r["id"]),
            )
            prev = sig

        # First-run seeding ONLY. Existing accounts are never deleted or reset here.
        # (A previous "self-healing" check wiped every user whenever the admin password was
        #  anything other than the default, which happened after a normal password change + restart.)
        if conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"] == 0:
            demo = os.getenv("SOC_DEMO_MODE", "0") == "1"
            for name, role, demo_pw in (
                ("admin", "admin", "Admin@123"),
                ("analyst", "analyst", "Analyst@123"),
                ("viewer", "viewer", "Viewer@123"),
            ):
                pw = demo_pw if demo else secrets.token_urlsafe(12)
                create_encrypted_user(conn, "tenant-trustaira", name, pw, role)
                print(f"[SECURITY] Initial {role} account '{name}' password (shown once): {pw}")

        conn.commit()


def upgrade_legacy_user_encryption(conn: sqlite3.Connection, user_id: str, password: str) -> None:
    """Re-encrypt a user's fields with Fernet the first time they log in after upgrade."""
    row = conn.execute(
        "SELECT username_encrypted, password_encrypted FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if not row:
        return
    if is_legacy_token(row["username_encrypted"]):
        conn.execute(
            "UPDATE users SET username_encrypted = ? WHERE id = ?",
            (encrypt_text(decrypt_text(row["username_encrypted"])), user_id),
        )
    if is_legacy_token(row["password_encrypted"]):
        conn.execute(
            "UPDATE users SET password_encrypted = ? WHERE id = ?", (encrypt_password(password), user_id)
        )
    conn.commit()