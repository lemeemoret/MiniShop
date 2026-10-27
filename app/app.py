"""MiniShop : application FastAPI VOLONTAIREMENT VULNÉRABLE (support du TP Cours 7).

Ne jamais déployer ce code tel quel. Votre mission : le rendre conforme.
Documentation interactive : http://localhost:5000/docs
"""

import ast
import html
import logging
import operator
import os
import secrets
import sqlite3
import subprocess
import traceback
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

import requests
import uvicorn
import yaml
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from fastapi import Body, Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.sessions import SessionMiddleware

SECRET_KEY = os.environ["SECRET_KEY"]
DB_PATH = os.environ.get("DB_PATH", "shop.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
ALLOWED_HOSTS = {"api.partenaire.com"}

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("minishop")

app = FastAPI(title="MiniShop", debug=True)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, https_only=True, same_site="lax")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

ph = PasswordHasher()
DUMMY_HASH = ph.hash("dummy-password")  # permet de comparer même si l'utilisateur n'existe pas

def init_db():
    conn = db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                            password TEXT, is_admin INTEGER DEFAULT 0);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER,
                               label TEXT, amount REAL);
        """
    )
    conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                 ("admin", ph.hash("admin123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("alice", ph.hash("alice123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("bob", ph.hash("bob123")))
    conn.executemany("INSERT INTO products (name, price) VALUES (?, ?)",
                     [("apple", 1.2), ("banana", 0.8), ("cherry", 3.5)])
    conn.executemany("INSERT INTO invoices (owner_id, label, amount) VALUES (?, ?, ?)",
                     [(2, "Facture Alice", 42.0), (3, "Facture Bob", 99.0)])
    conn.commit()
    conn.close()


@app.exception_handler(Exception)
async def handle_error(request: Request, exc: Exception):
    return HTMLResponse("<pre>" + traceback.format_exc() + "</pre>", status_code=500)

def current_user(request: Request):
    """Utilisateur connecté (lu en base d'après la session signée), sinon 401."""
    user_id = request.session.get("user_id")
    row = None
    if user_id is not None:
        row = db().execute("SELECT id, username, is_admin FROM users WHERE id = ?",
                           (user_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=401, detail="login required")
    user = dict(row)
    user["role"] = "admin" if user["is_admin"] else "viewer"
    return user

ROLE_PERMS = {
    "viewer": {"invoice:read"},
    "admin": {"invoice:read", "user:read", "user:delete"},
}


def require(perm: str):
    """Dépendance FastAPI : 401 si anonyme, 403 si la permission manque (refus par défaut)."""
    def checker(user: dict = Depends(current_user)):
        if perm not in ROLE_PERMS.get(user["role"], set()):
            raise HTTPException(status_code=403, detail="forbidden")
        return user
    return checker

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(request: Request, data: dict = Body(...)):
    username, password = data["username"], data["password"]
    row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    try:
        ph.verify(row["password"] if row else DUMMY_HASH, password)
    except (VerifyMismatchError, InvalidHashError):
        return JSONResponse({"error": "bad credentials"}, status_code=401)
    if not row:
        return JSONResponse({"error": "bad credentials"}, status_code=401)
    log.info("login user_id=%s", row["id"])
    request.session["user_id"] = row["id"]
    request.session["token"] = secrets.token_urlsafe(32)
    return {"status": "logged in", "user": row["username"]}


@app.get("/search")
def search(q: str = ""):
    sql = "SELECT id, name, price FROM products WHERE name LIKE ?"
    return [dict(r) for r in db().execute(sql, (f"%{q}%",)).fetchall()]


@app.get("/ping")
def ping(host: str = "127.0.0.1"):
    try:
        ip = ip_address(host)  # lève ValueError si ce n'est pas une IP valide
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid host")
    try:
        out = subprocess.run(["ping", "-c", "1", str(ip)], capture_output=True,
                             text=True, timeout=5, check=False)
    except (subprocess.TimeoutExpired, OSError):
        return JSONResponse({"error": "ping failed"}, status_code=502)
    return PlainTextResponse(out.stdout + out.stderr)


@app.get("/hello")
def hello(name: str = ""):
    return HTMLResponse(f"<h1>Bonjour {html.escape(name)}</h1>")


@app.get("/files/{name:path}")
def get_file(name: str):
    base = Path(UPLOAD_DIR).resolve()
    try:
        path = (base / name).resolve()
    except ValueError:  # octet nul dans le chemin
        raise HTTPException(status_code=404)
    if not path.is_relative_to(base) or not path.is_file():
        raise HTTPException(status_code=404)
    return FileResponse(path)


_OPS = {ast.Add: operator.add, ast.Sub: operator.sub,
        ast.Mult: operator.mul, ast.Div: operator.truediv}


def safe_eval(node):
    """Évalue une expression arithmétique (+ - * /) : liste blanche de noeuds AST."""
    if isinstance(node, ast.Expression):
        return safe_eval(node.body)
    if (isinstance(node, ast.Constant) and isinstance(node.value, (int, float))
            and not isinstance(node.value, bool)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPS:
        return _OPS[type(node.op)](safe_eval(node.left), safe_eval(node.right))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        value = safe_eval(node.operand)
        return value if isinstance(node.op, ast.UAdd) else -value
    raise ValueError("unsupported expression")


@app.post("/calc")
def calc(data: dict = Body(...)):
    expr = data.get("expr")
    if not isinstance(expr, str) or len(expr) > 100:
        raise HTTPException(status_code=400, detail="invalid expression")
    try:
        result = safe_eval(ast.parse(expr, mode="eval"))
    except (ValueError, SyntaxError, ZeroDivisionError, RecursionError):
        raise HTTPException(status_code=400, detail="invalid expression")
    return {"result": str(result)}

@app.post("/import-yaml")
async def import_yaml(request: Request):
    try:
        cfg = yaml.safe_load(await request.body())
    except yaml.YAMLError:
        raise HTTPException(status_code=400, detail="invalid YAML")
    return {"keys": list(cfg.keys()) if isinstance(cfg, dict) else str(type(cfg))}


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64)
    age: int = Field(ge=0, le=150)


@app.post("/import-profile")
def import_profile(profile: Profile):
    return {"profile": profile.model_dump()}


@app.get("/fetch")
def fetch(url: str):
    u = urlparse(url)
    if u.scheme != "https" or u.hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="url not allowed")
    try:
        r = requests.get(url, timeout=5, allow_redirects=False)  # verify=True par défaut
    except requests.RequestException:
        raise HTTPException(status_code=502, detail="upstream error")
    return PlainTextResponse(r.text[:500])


@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: int, user: dict = Depends(current_user)):
    row = db().execute("SELECT * FROM invoices WHERE id = ? AND owner_id = ?",
                       (invoice_id, user["id"])).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="not found")
    return dict(row)


@app.get("/admin/users")
def admin_users(user: dict = Depends(require("user:read"))):
    rows = db().execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.delete("/users/{user_id}")
def delete_user(user_id: int, user: dict = Depends(require("user:delete"))):
    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"deleted": user_id}


@app.get("/boom")
def boom():
    return 1 / 0


if __name__ == "__main__":
    init_db()
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
