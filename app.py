import os
import uuid
import json
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv

load_dotenv()

# ─── APP CONFIG ───────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "dev-secret-cambia-esto")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///velvet_touch.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

UPLOAD_FOLDER = os.path.join("static", "uploads")
ALLOWED_EXT = {"png", "jpg", "jpeg", "webp"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

GOOGLE_CLIENT_ID     = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")

# ─── EXTENSIONES ──────────────────────────────────────────────────────────────
db    = SQLAlchemy(app)
oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─── MODELO ───────────────────────────────────────────────────────────────────
class Masajista(db.Model):
    __tablename__ = "masajistas"

    id            = db.Column(db.Integer,     primary_key=True)
    nombre        = db.Column(db.String(80),  nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)
    google_id     = db.Column(db.String(120), unique=True, nullable=True)

    edad          = db.Column(db.Integer,     nullable=True)
    nacionalidad  = db.Column(db.String(60),  nullable=True)
    ubicacion     = db.Column(db.String(100), nullable=True)
    tarifa_hora   = db.Column(db.Float,       nullable=True)
    tarifa_30min  = db.Column(db.Float,       nullable=True)
    descripcion   = db.Column(db.Text,        nullable=True)
    telefono      = db.Column(db.String(30),  nullable=True)
    servicios     = db.Column(db.Text,        nullable=True)  # JSON string
    foto_perfil   = db.Column(db.String(200), nullable=True)
    publicado     = db.Column(db.Boolean,     default=False)
    creado_en     = db.Column(db.DateTime,    default=datetime.utcnow)

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return bool(self.password_hash) and check_password_hash(self.password_hash, pw)

    def foto_url(self):
        if self.foto_perfil:
            return url_for("static", filename=f"uploads/{self.foto_perfil}")
        return "https://images.unsplash.com/photo-1534528741775-53994a69daeb?w=600&q=80"

with app.app_context():
    db.create_all()

# ─── FILTRO JINJA2 para parsear JSON de servicios en el template ──────────────
@app.template_filter("from_json")
def from_json_filter(value):
    try:
        return json.loads(value)
    except Exception:
        return []

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT

def save_photo(field="foto_perfil"):
    if field not in request.files:
        return None
    f = request.files[field]
    if not f or f.filename == "" or not allowed_file(f.filename):
        return None
    ext      = f.filename.rsplit(".", 1)[1].lower()
    filename = f"{uuid.uuid4().hex}.{ext}"
    f.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return filename

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Debes iniciar sesión para acceder.", "warning")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def get_current_user():
    uid = session.get("user_id")
    return Masajista.query.get(uid) if uid else None

@app.context_processor
def inject_user():
    return {"current_user": get_current_user()}

# ─── RUTAS PRINCIPALES ────────────────────────────────────────────────────────
@app.route("/")
def index():
    masajistas = Masajista.query.filter_by(publicado=True).all()
    return render_template("index.html", masajistas=masajistas)


@app.route("/perfil/<int:masajista_id>")
def perfil(masajista_id):
    m = Masajista.query.get_or_404(masajista_id)
    # El dueño puede ver su propio perfil aunque no esté publicado
    u = get_current_user()
    if not m.publicado and (not u or u.id != m.id):
        flash("Este perfil no está disponible.", "warning")
        return redirect(url_for("index"))
    return render_template("perfil-template.html", masajista=m)


# ─── AUTH TRADICIONAL ─────────────────────────────────────────────────────────
@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre   = request.form.get("nombre", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        if not nombre or not email or not password:
            flash("Todos los campos son obligatorios.", "danger")
            return redirect(url_for("registro"))
        if password != confirm:
            flash("Las contraseñas no coinciden.", "danger")
            return redirect(url_for("registro"))
        if len(password) < 8:
            flash("La contraseña debe tener al menos 8 caracteres.", "danger")
            return redirect(url_for("registro"))
        if Masajista.query.filter_by(email=email).first():
            flash("Ya existe una cuenta con ese email.", "danger")
            return redirect(url_for("registro"))

        u = Masajista(nombre=nombre, email=email)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()

        session["user_id"] = u.id
        flash("¡Cuenta creada! Ahora completa tu perfil.", "success")
        return redirect(url_for("crear_perfil"))

    return render_template("registro.html", active_tab="registro")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        u = Masajista.query.filter_by(email=email).first()

        if not u or not u.check_password(password):
            flash("Email o contraseña incorrectos.", "danger")
            return render_template("registro.html", active_tab="login")

        session["user_id"] = u.id
        flash(f"Bienvenida de nuevo, {u.nombre}.", "success")
        return redirect(url_for("panel"))

    return render_template("registro.html", active_tab="login")


@app.route("/logout")
def logout():
    session.clear()
    flash("Has cerrado sesión.", "info")
    return redirect(url_for("index"))


# ─── GOOGLE OAUTH ─────────────────────────────────────────────────────────────
@app.route("/login/google")
def google_login():
    redirect_uri = url_for("google_callback", _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route("/login/google/callback")
def google_callback():
    token    = google.authorize_access_token()
    userinfo = token.get("userinfo")
    if not userinfo:
        flash("No se pudo obtener información de Google.", "danger")
        return redirect(url_for("login"))

    google_id = userinfo["sub"]
    email     = userinfo.get("email", "").lower()
    nombre    = userinfo.get("name", "")

    u = (Masajista.query.filter_by(google_id=google_id).first()
         or Masajista.query.filter_by(email=email).first())

    if u:
        if not u.google_id:
            u.google_id = google_id
            db.session.commit()
    else:
        u = Masajista(nombre=nombre, email=email, google_id=google_id)
        db.session.add(u)
        db.session.commit()

    session["user_id"] = u.id
    flash(f"Bienvenida, {u.nombre}.", "success")
    return redirect(url_for("panel"))


# ─── PANEL PRIVADO ────────────────────────────────────────────────────────────
@app.route("/panel")
@login_required
def panel():
    u = get_current_user()
    return render_template("panel.html", usuario=u)


# ─── CREAR / EDITAR PERFIL ────────────────────────────────────────────────────
@app.route("/crear-perfil", methods=["GET", "POST"])
@login_required
def crear_perfil():
    u = get_current_user()

    if request.method == "POST":
        u.nombre       = request.form.get("nombre", u.nombre).strip()
        u.edad         = request.form.get("edad",         type=int)   or u.edad
        u.nacionalidad = request.form.get("nacionalidad", "").strip() or u.nacionalidad
        u.ubicacion    = request.form.get("ubicacion",    "").strip() or u.ubicacion
        u.tarifa_hora  = request.form.get("tarifa_hora",  type=float) or u.tarifa_hora
        u.tarifa_30min = request.form.get("tarifa_30min", type=float) or u.tarifa_30min
        u.descripcion  = request.form.get("descripcion",  "").strip() or u.descripcion
        u.telefono     = request.form.get("telefono",     "").strip() or u.telefono
        u.servicios    = request.form.get("servicios",    "")         or u.servicios

        nueva_foto = save_photo("foto_perfil")
        if nueva_foto:
            if u.foto_perfil:
                old = os.path.join(app.config["UPLOAD_FOLDER"], u.foto_perfil)
                if os.path.exists(old):
                    os.remove(old)
            u.foto_perfil = nueva_foto

        accion      = request.form.get("accion", "borrador")
        u.publicado = (accion == "publicar")

        db.session.commit()

        if accion == "publicar":
            flash("¡Perfil publicado con éxito!", "success")
            return redirect(url_for("perfil", masajista_id=u.id))
        flash("Borrador guardado.", "info")
        return redirect(url_for("crear_perfil"))

    return render_template("crear-perfil.html", usuario=u)


# ─── API JSON (opcional) ──────────────────────────────────────────────────────
@app.route("/api/masajistas")
def api_masajistas():
    ms = Masajista.query.filter_by(publicado=True).all()
    return jsonify([{
        "id": m.id, "nombre": m.nombre, "edad": m.edad,
        "nacionalidad": m.nacionalidad, "ubicacion": m.ubicacion,
        "tarifa_hora": m.tarifa_hora, "foto_url": m.foto_url()
    } for m in ms])


# ─── ERRORES ──────────────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(413)
def file_too_large(e):
    flash("La foto no puede superar 5 MB.", "danger")
    return redirect(url_for("crear_perfil"))


# ─── ARRANQUE ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True)