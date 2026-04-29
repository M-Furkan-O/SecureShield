from flask import Flask, request, jsonify, render_template_string
from flask_bcrypt import Bcrypt
from flask_cors import CORS
import jwt
import sqlite3
import logging
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "supersecretkey_change_in_prod")
app.config["JWT_EXP_DELTA_SECONDS"] = 3600
CORS(app)
bcrypt = Bcrypt(app)
token_blacklist = set()

logging.basicConfig(
    filename="security.log", level=logging.WARNING,
    format="%(asctime)s | %(levelname)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S",
)
security_logger = logging.getLogger("security")
DB_PATH = "secureshield.db"

def get_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with get_db() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )""")
        # Seed demo users if missing (keeps the UI demo flow smooth).
        existing = {r["username"] for r in db.execute("SELECT username FROM users").fetchall()}
        seeds = [
            ("alice", "alicepass", "user"),
            ("admin", "adminpass", "admin"),
        ]
        for username, password, role in seeds:
            if username in existing:
                continue
            hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
            db.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                (username, hashed_pw, role),
            )
        db.commit()

def create_token(username, role):
    payload = {
        "sub": username, "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(seconds=app.config["JWT_EXP_DELTA_SECONDS"]),
    }
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

def decode_token(token):
    return jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            security_logger.warning(f"UNAUTHORIZED | No auth header | {request.method} {request.path}")
            return jsonify({"error": "Missing or malformed Authorization header"}), 401
        token = auth_header.split(" ", 1)[1]
        if token in token_blacklist:
            security_logger.warning(f"UNAUTHORIZED | Blacklisted token | {request.method} {request.path}")
            return jsonify({"error": "Token revoked. Please log in again."}), 401
        try:
            from flask import g
            g.user = decode_token(token)
            g.raw_token = token
        except jwt.ExpiredSignatureError:
            security_logger.warning(f"UNAUTHORIZED | Expired token | {request.method} {request.path}")
            return jsonify({"error": "Token expired."}), 401
        except jwt.InvalidTokenError as e:
            security_logger.warning(f"UNAUTHORIZED | Invalid token ({e}) | {request.method} {request.path}")
            return jsonify({"error": "Invalid token."}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        from flask import g
        if g.user.get("role") != "admin":
            security_logger.warning(f"FORBIDDEN | User '{g.user.get('sub')}' tried admin route | {request.method} {request.path}")
            return jsonify({"error": "Forbidden: Admin access required."}), 403
        return f(*args, **kwargs)
    return decorated

@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    role = data.get("role", "user").lower()
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    if role not in ("user", "admin"):
        return jsonify({"error": "role must be 'user' or 'admin'"}), 400
    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    try:
        with get_db() as db:
            db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_pw, role))
            db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    return jsonify({"message": f"User '{username}' registered successfully.", "role": role}), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "username and password are required"}), 400
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not bcrypt.check_password_hash(row["password"], password):
        security_logger.warning(f"UNAUTHORIZED | Failed login for '{username}'")
        return jsonify({"error": "Invalid credentials"}), 401
    token = create_token(row["username"], row["role"])
    return jsonify({"message": "Login successful", "token": token, "role": row["role"], "username": row["username"]}), 200

@app.route("/logout", methods=["POST"])
@token_required
def logout():
    from flask import g
    token_blacklist.add(g.raw_token)
    return jsonify({"message": "Logged out. Token revoked."}), 200

@app.route("/profile", methods=["GET"])
@token_required
def profile():
    from flask import g
    username = g.user["sub"]
    with get_db() as db:
        row = db.execute("SELECT id, username, role FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify({"id": row["id"], "username": row["username"], "role": row["role"]}), 200

@app.route("/user/<int:user_id>", methods=["DELETE"])
@token_required
@admin_required
def delete_user(user_id):
    with get_db() as db:
        row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return jsonify({"error": f"User with id {user_id} not found"}), 404
        db.execute("DELETE FROM users WHERE id = ?", (user_id,))
        db.commit()
    return jsonify({"message": f"User '{row['username']}' (id={user_id}) deleted."}), 200

@app.route("/users", methods=["GET"])
@token_required
@admin_required
def list_users():
    with get_db() as db:
        rows = db.execute("SELECT id, username, role FROM users").fetchall()
    return jsonify([dict(r) for r in rows]), 200

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200

# ── Frontend UI ───────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>SecureShield — RBAC Demo</title>
<style>
:root {
  --bg: #0a0c10;
  --surface: #111318;
  --surface2: #181b22;
  --border: #1e2330;
  --border2: #2a3045;
  --accent: #4f8ef7;
  --accent2: #7c5cfc;
  --green: #22c55e;
  --red: #ef4444;
  --amber: #f59e0b;
  --text: #e8eaf0;
  --muted: #6b7280;
  --mono: 'Courier New', Courier, monospace;
  --display: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--mono);min-height:100vh;overflow-x:hidden}

/* grid bg */
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:40px 40px;opacity:.4;pointer-events:none;z-index:0}

.wrap{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:2rem 1.5rem}

/* header */
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:2.5rem;padding-bottom:1.5rem;border-bottom:1px solid var(--border)}
.logo{font-family:var(--display);font-size:1.5rem;font-weight:800;letter-spacing:-.02em}
.logo span{color:var(--accent)}

/* token bar */
.token-bar{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1rem 1.25rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:1rem;flex-wrap:wrap}
.token-label{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.1em;white-space:nowrap}
.token-val{font-size:.72rem;color:var(--accent);word-break:break-all;flex:1;min-width:0}
.token-role{font-size:.7rem;padding:.25rem .7rem;border-radius:999px;font-weight:700;white-space:nowrap}
.token-role.user{background:rgba(79,142,247,.15);color:var(--accent);border:1px solid rgba(79,142,247,.3)}
.token-role.admin{background:rgba(124,92,252,.15);color:var(--accent2);border:1px solid rgba(124,92,252,.3)}
.token-role.none{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}

/* main grid */
.grid{display:grid;grid-template-columns:1fr 1fr;gap:1rem}
@media(max-width:700px){.grid{grid-template-columns:1fr}}

/* cards */
.card{background:var(--surface);border:1px solid var(--border);border-radius:14px;overflow:hidden;display:flex;flex-direction:column}
.card-head{padding:.9rem 1.2rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.75rem}
.step-num{width:26px;height:26px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:.75rem;font-weight:700;font-family:var(--display);flex-shrink:0}
.s1{background:rgba(79,142,247,.2);color:var(--accent)}
.s2{background:rgba(239,68,68,.2);color:var(--red)}
.s3{background:rgba(245,158,11,.2);color:var(--amber)}
.s4{background:rgba(34,197,94,.2);color:var(--green)}
.card-title{font-family:var(--display);font-size:.9rem;font-weight:600}
.card-body{padding:1.2rem;flex:1;display:flex;flex-direction:column;gap:.75rem}

/* inputs */
input,select{width:100%;background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:.6rem .85rem;font-size:.8rem;font-family:var(--mono);color:var(--text);outline:none;transition:border .2s}
input:focus,select:focus{border-color:var(--accent)}
input::placeholder{color:var(--muted)}
.row{display:flex;gap:.5rem}
.row input,.row select{flex:1}

/* buttons */
button{font-family:var(--mono);font-size:.78rem;font-weight:500;border:none;border-radius:8px;padding:.6rem 1.1rem;cursor:pointer;transition:all .15s;white-space:nowrap}
.btn-primary{background:var(--accent);color:#fff}
.btn-primary:hover{background:#6fa3f8;transform:translateY(-1px)}
.btn-danger{background:var(--red);color:#fff}
.btn-danger:hover{background:#f87171;transform:translateY(-1px)}
.btn-amber{background:var(--amber);color:#0a0c10}
.btn-amber:hover{background:#fbbf24;transform:translateY(-1px)}
.btn-ghost{background:var(--surface2);color:var(--text);border:1px solid var(--border2)}
.btn-ghost:hover{border-color:var(--border2);background:var(--border)}
button:disabled{opacity:.45;cursor:not-allowed;transform:none!important}

/* response */
.resp{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.75rem 1rem;font-size:.75rem;line-height:1.7;min-height:56px;transition:border .3s;display:none}
.resp.show{display:block}
.resp.ok{border-color:rgba(34,197,94,.4);color:#86efac}
.resp.err{border-color:rgba(239,68,68,.4);color:#fca5a5}
.resp.info{border-color:rgba(79,142,247,.3);color:#93c5fd}

/* logs section */
.log-card{grid-column:1/-1}
.log-area{background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:.75rem 1rem;font-size:.72rem;line-height:1.8;max-height:180px;overflow-y:auto;min-height:60px}
.log-line{color:var(--muted);border-bottom:1px solid var(--border);padding:.15rem 0}
.log-line:last-child{border:none}
.log-line .ts{color:var(--border2)}
.log-line .warn{color:var(--amber)}
.log-line .block{color:var(--red)}

/* jwt explainer */
.jwt-parts{display:flex;gap:4px;flex-wrap:wrap;margin:.25rem 0}
.jwt-part{padding:.2rem .5rem;border-radius:5px;font-size:.68rem;word-break:break-all}
.jp-h{background:rgba(239,68,68,.15);color:#fca5a5}
.jp-p{background:rgba(124,92,252,.15);color:#c4b5fd}
.jp-s{background:rgba(34,197,94,.15);color:#86efac}

.hint{font-size:.7rem;color:var(--muted);line-height:1.6}
.divider{height:1px;background:var(--border);margin:.25rem 0}

/* logout row */
.logout-row{display:flex;gap:.5rem;align-items:center}
.logout-row span{font-size:.75rem;color:var(--muted);flex:1}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="logo">Secure<span>Shield</span> <span style="font-size:.75rem;color:var(--muted);font-weight:400">RBAC Demo</span></div>
  </header>

  <!-- Active Token Bar -->
  <div class="token-bar">
    <span class="token-label">Aktif token</span>
    <span class="token-val" id="tok-display">— henüz giriş yapılmadı —</span>
    <span class="token-role none" id="tok-role">Yok</span>
    <button class="btn-ghost" onclick="copyToken()" id="copy-btn" style="display:none;padding:.35rem .8rem;font-size:.7rem">Kopyala</button>
    <button class="btn-ghost" onclick="openJwt()" id="jwt-btn" style="display:none;padding:.35rem .8rem;font-size:.7rem">jwt.io ↗</button>
  </div>

  <div class="grid">

    <!-- CARD 1: Register + Login -->
    <div class="card">
      <div class="card-head">
        <div class="step-num s1">1</div>
        <div class="card-title">Kayıt & Giriş</div>
      </div>
      <div class="card-body">
        <p class="hint">Kullanıcı oluştur, giriş yap, token al.</p>
        <div class="row">
          <input id="r-user" placeholder="kullanıcı adı" value="alice"/>
          <input id="r-pass" placeholder="şifre" type="password" value="alicepass"/>
        </div>
        <div class="row">
          <select id="r-role"><option value="user">user</option><option value="admin">admin</option></select>
          <button class="btn-ghost" onclick="doRegister()">Kayıt ol</button>
        </div>
        <div class="resp" id="reg-resp"></div>
        <div class="divider"></div>
        <div class="row">
          <input id="l-user" placeholder="kullanıcı adı" value="alice"/>
          <input id="l-pass" placeholder="şifre" type="password" value="alicepass"/>
        </div>
        <button class="btn-primary" onclick="doLogin()">Giriş yap → Token al</button>
        <div class="resp" id="login-resp"></div>

        <div class="divider"></div>
        <div class="logout-row">
          <span>Oturumu kapat (token blacklist'e eklenir)</span>
          <button class="btn-ghost" onclick="doLogout()" id="logout-btn" disabled>Logout</button>
        </div>
        <div class="resp" id="logout-resp"></div>
      </div>
    </div>

    <!-- CARD 2: Access Denied Test -->
    <div class="card">
      <div class="card-head">
        <div class="step-num s2">2</div>
        <div class="card-title">403 — Erişim Engeli</div>
      </div>
      <div class="card-body">
        <p class="hint">"user" rolüyle admin rotasına erişmeye çalış. Sunucu 403 döndürmeli.</p>
        <p class="hint" style="color:var(--accent)">→ Önce user olarak giriş yap (Kart 1), sonra test et.</p>

        <div class="row">
          <input id="del-id" type="number" value="1" style="max-width:80px;flex:none"/>
          <span style="font-size:.78rem;color:var(--muted);align-self:center">DELETE /user/{id}</span>
        </div>
        <button class="btn-danger" onclick="tryDelete()">Silmeye çalış (403 bekleniyor)</button>
        <div class="resp" id="del-resp"></div>

        <div class="divider"></div>
        <p class="hint">GET /profile — her iki rol de erişebilir:</p>
        <button class="btn-ghost" onclick="doProfile()">Profili gör</button>
        <div class="resp" id="prof-resp"></div>
      </div>
    </div>

    <!-- CARD 3: Tamper Test -->
    <div class="card">
      <div class="card-head">
        <div class="step-num s3">3</div>
        <div class="card-title">Tamper Test — Sahte Token</div>
      </div>
      <div class="card-body">
        <p class="hint">1. Yukarıdaki "jwt.io ↗" butonuna tıkla<br>2. Payload'da <code style="color:var(--amber)">"role":"user"</code> → <code style="color:var(--red)">"role":"admin"</code> yap<br>3. Değişmiş token'ı aşağıya yapıştır<br>4. Gönder → Sunucu imzayı reddeder</p>
        <input id="tamper-tok" placeholder="jwt.io'dan değiştirilmiş token'ı yapıştır..."/>
        <button class="btn-amber" onclick="doTamper()">Gönder → sunucu reddetmeli</button>
        <div class="resp" id="tamper-resp"></div>

        <div class="divider"></div>
        <p class="hint" style="margin-bottom:.25rem">Token yapısı (3 parça):</p>
        <div class="jwt-parts" id="jwt-parts">
          <span class="jwt-part jp-h">header (base64)</span>
          <span style="color:var(--muted);align-self:center">.</span>
          <span class="jwt-part jp-p">payload (base64)</span>
          <span style="color:var(--muted);align-self:center">.</span>
          <span class="jwt-part jp-s">signature (HMAC-SHA256)</span>
        </div>
      </div>
    </div>

    <!-- CARD 4: Admin Panel -->
    <div class="card">
      <div class="card-head">
        <div class="step-num s4">4</div>
        <div class="card-title">Admin Paneli</div>
      </div>
      <div class="card-body">
        <p class="hint">Önce admin olarak giriş yap (Kart 1'de role=admin seç), sonra bu işlemleri dene.</p>
        <button class="btn-ghost" onclick="listUsers()">Tüm kullanıcıları listele</button>
        <div class="resp" id="users-resp"></div>
        <div class="divider"></div>
        <p class="hint">Admin olarak sil:</p>
        <div class="row">
          <input id="admin-del-id" type="number" value="2" style="max-width:80px;flex:none"/>
          <button class="btn-danger" onclick="adminDelete()">Admin olarak sil</button>
        </div>
        <div class="resp" id="admin-del-resp"></div>
      </div>
    </div>

    <!-- CARD 5: Logs -->
    <div class="card log-card">
      <div class="card-head">
        <div class="step-num" style="background:rgba(107,114,128,.2);color:var(--muted)">●</div>
        <div class="card-title">Güvenlik Logları (security.log)</div>
      </div>
      <div class="card-body">
        <p class="hint">Her yetkisiz / engellenmiş istek burada görünür ve security.log dosyasına yazılır.</p>
        <div class="log-area" id="log-area">
          <div class="log-line" style="color:var(--border2)">— henüz log yok —</div>
        </div>
      </div>
    </div>

  </div>
</div>

<script>
const B = '';
let token = '';
let role = '';
const logs = [];

function addLog(type, msg) {
  const ts = new Date().toLocaleTimeString('tr-TR');
  logs.unshift({ts, type, msg});
  renderLogs();
}
function renderLogs() {
  const area = document.getElementById('log-area');
  if (!logs.length) return;
  area.innerHTML = logs.map(l => {
    const cls = l.type === 'warn' ? 'warn' : l.type === 'block' ? 'block' : '';
    return `<div class="log-line"><span class="ts">[${l.ts}]</span> <span class="${cls}">${l.msg}</span></div>`;
  }).join('');
}

function show(id, data, ok) {
  const el = document.getElementById(id);
  el.textContent = JSON.stringify(data, null, 2);
  el.className = 'resp show ' + (ok ? 'ok' : 'err');
}

function setToken(t, r) {
  token = t; role = r;
  const el = document.getElementById('tok-display');
  const roleEl = document.getElementById('tok-role');
  if (t) {
    el.textContent = t;
    roleEl.textContent = r.toUpperCase();
    roleEl.className = 'token-role ' + r;
    document.getElementById('copy-btn').style.display = '';
    document.getElementById('jwt-btn').style.display = '';
    document.getElementById('logout-btn').disabled = false;
    splitJwt(t);
    addLog('info', `Giriş başarılı | kullanıcı: "${r}" rolüyle token aldı`);
  } else {
    el.textContent = '— oturum kapatıldı —';
    roleEl.textContent = 'Yok';
    roleEl.className = 'token-role none';
    document.getElementById('copy-btn').style.display = 'none';
    document.getElementById('jwt-btn').style.display = 'none';
    document.getElementById('logout-btn').disabled = true;
  }
}

function splitJwt(t) {
  const parts = t.split('.');
  if (parts.length !== 3) return;
  const area = document.getElementById('jwt-parts');
  area.innerHTML = `
    <span class="jwt-part jp-h" title="Header">${parts[0].slice(0,12)}...</span>
    <span style="color:var(--muted);align-self:center">.</span>
    <span class="jwt-part jp-p" title="Payload">${parts[1].slice(0,16)}...</span>
    <span style="color:var(--muted);align-self:center">.</span>
    <span class="jwt-part jp-s" title="Signature">${parts[2].slice(0,16)}...</span>
  `;
}

function copyToken() {
  navigator.clipboard.writeText(token);
  document.getElementById('copy-btn').textContent = 'Kopyalandı!';
  setTimeout(() => document.getElementById('copy-btn').textContent = 'Kopyala', 1500);
}
function openJwt() { window.open('https://jwt.io/#debugger-io?token=' + token, '_blank'); }

async function doRegister() {
  const body = { username: document.getElementById('r-user').value, password: document.getElementById('r-pass').value, role: document.getElementById('r-role').value };
  try {
    const r = await fetch(B + '/register', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    const d = await r.json();
    show('reg-resp', d, r.ok);
    if (r.ok) addLog('info', `Kayıt: "${body.username}" (${body.role}) oluşturuldu`);
  } catch { show('reg-resp', {error: 'Sunucuya ulaşılamadı'}, false); }
}

async function doLogin() {
  const body = { username: document.getElementById('l-user').value, password: document.getElementById('l-pass').value };
  try {
    const r = await fetch(B + '/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
    const d = await r.json();
    show('login-resp', d, r.ok);
    if (r.ok) setToken(d.token, d.role);
    else addLog('block', `Başarısız giriş: "${body.username}" — 401 Unauthorized`);
  } catch { show('login-resp', {error: 'Sunucuya ulaşılamadı'}, false); }
}

async function doLogout() {
  if (!token) return;
  try {
    const r = await fetch(B + '/logout', { method: 'POST', headers: {'Authorization': 'Bearer ' + token} });
    const d = await r.json();
    show('logout-resp', d, r.ok);
    if (r.ok) { addLog('info', \"Logout: token blacklist'e eklendi\"); setToken('', ''); }
  } catch { show('logout-resp', {error: 'Sunucuya ulaşılamadı'}, false); }
}

async function doProfile() {
  if (!token) { show('prof-resp', {error: 'Önce giriş yap'}, false); return; }
  try {
    const r = await fetch(B + '/profile', { headers: {'Authorization': 'Bearer ' + token} });
    const d = await r.json();
    show('prof-resp', d, r.ok);
    addLog('info', `GET /profile — ${r.status}`);
  } catch { show('prof-resp', {error: 'Sunucuya ulaşılamadı'}, false); }
}

async function tryDelete() {
  if (!token) { show('del-resp', {error: 'Önce giriş yap (user rolüyle)'}, false); return; }
  const id = document.getElementById('del-id').value;
  try {
    const r = await fetch(B + '/user/' + id, { method: 'DELETE', headers: {'Authorization': 'Bearer ' + token} });
    const d = await r.json();
    show('del-resp', {status: r.status, ...d}, false);
    if (r.status === 403) addLog('block', `FORBIDDEN: "${role}" rolü DELETE /user/${id} denedi — 403`);
  } catch { show('del-resp', {error: 'Sunucuya ulaşılamadı'}, false); }
}

async function listUsers() {
  if (!token) { show('users-resp', {error: 'Önce admin olarak giriş yap'}, false); return; }
  try {
    const r = await fetch(B + '/users', { headers: {'Authorization': 'Bearer ' + token} });
    const d = await r.json();
    show('users-resp', d, r.ok);
    if (!r.ok) addLog('block', `FORBIDDEN: kullanıcı listesi reddedildi — ${r.status}`);
  } catch { show('users-resp', {error: 'Sunucuya ulaşılamadı'}, false); }
}

async function adminDelete() {
  if (!token) { show('admin-del-resp', {error: 'Önce admin olarak giriş yap'}, false); return; }
  const id = document.getElementById('admin-del-id').value;
  try {
    const r = await fetch(B + '/user/' + id, { method: 'DELETE', headers: {'Authorization': 'Bearer ' + token} });
    const d = await r.json();
    show('admin-del-resp', d, r.ok);
    if (r.ok) addLog('info', `Admin DELETE /user/${id} — başarılı`);
    else addLog('block', `Admin DELETE /user/${id} — ${r.status}`);
  } catch { show('admin-del-resp', {error: 'Sunucuya ulaşılamadı'}, false); }
}

async function doTamper() {
  const t = document.getElementById('tamper-tok').value.trim();
  if (!t) { show('tamper-resp', {error: "jwt.io'dan değiştirilmiş token'ı yapıştır"}, false); return; }
  try {
    const r = await fetch(B + '/user/1', { method: 'DELETE', headers: {'Authorization': 'Bearer ' + t} });
    const d = await r.json();
    show('tamper-resp', {status: r.status, ...d}, false);
    addLog('block', `TAMPER TEST: sahte token reddedildi — ${r.status} ${d.error || ''}`);
  } catch { show('tamper-resp', {error: 'Sunucuya ulaşılamadı'}, false); }
}

// Health indicator removed from header (keeps UI minimal).
</script>
</body>
</html>"""

@app.route("/")
def index():
    return render_template_string(HTML)

if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", "5001"))
    print("\n🛡️  SecureShield başlatılıyor...")
    print(f"   → http://localhost:{port}  adresini tarayıcıda aç\n")
    app.run(debug=True, host="0.0.0.0", port=port)
