"""
Keneviz VIP Panel - app.py (Tam sürüm)
- Robot doğrulama (keneviz_challenge / keneviz_verify)
- /api/sorgu route'u (frontend için)
- Admin ve key yönetimi
- Worker proxy fonksiyonları
"""

from datetime import datetime, timedelta
import os
import secrets
import string
import urllib.parse
import requests
import time

from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for, jsonify)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'keneviz.sqlite')

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', secrets.token_urlsafe(32))

ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'sistemnabide')

db = SQLAlchemy(app)

# ----------------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------------
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    plan = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean, default=True)
    notes = db.Column(db.Text, nullable=True)

    def is_expired(self):
        if not self.expires_at:
            return False
        return datetime.utcnow() > self.expires_at

# ----------------------------------------------------------------------------
# Utilities
# ----------------------------------------------------------------------------
def init_db():
    with app.app_context():
        db.create_all()
        if Admin.query.first() is None:
            admin_pw = ADMIN_PASSWORD
            admin = Admin(username='admin', password_hash=generate_password_hash(admin_pw))
            db.session.add(admin)
            db.session.commit()
            app.logger.info("[setup] created admin user 'admin'")


def generate_key_string(length=20):
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

PLAN_TO_DAYS = {
    '1week': 7,
    '1month': 30,
    '3month': 90,
    '1year': 365,
    'free': None
}


def create_key(plan='1month', notes=None):
    while True:
        k = generate_key_string(20)
        if not Key.query.filter_by(key=k).first():
            break
    expires = None
    days = PLAN_TO_DAYS.get(plan)
    if days:
        expires = datetime.utcnow() + timedelta(days=days)
    key = Key(key=k, plan=plan, expires_at=expires, notes=notes)
    db.session.add(key)
    db.session.commit()
    return key


def verify_key_string(kstr):
    if not kstr:
        return None
    key = Key.query.filter_by(key=kstr, active=True).first()
    if not key:
        return None
    if key.is_expired():
        key.active = False
        db.session.commit()
        return None
    return key

# ----------------------------------------------------------------------------
# API list & worker resolver
# ----------------------------------------------------------------------------
APIS = [
    { 'ad': 'tc_sorgulama', 'url': 'https://keneviz.kolsuzpabg.workers.dev/tc_sorgulama?tc=', 'params': 'tc' },
    { 'ad': 'tc_pro_sorgulama', 'url': 'https://keneviz.kolsuzpabg.workers.dev/tc_pro_sorgulama?tc=', 'params': 'tc' },
    { 'ad': 'hayat_hikayesi', 'url': 'https://keneviz.kolsuzpabg.workers.dev/hayat_hikayesi?tc=', 'params': 'tc' },
    { 'ad': 'ad_soyad', 'url': 'https://keneviz.kolsuzpabg.workers.dev/ad_soyad?ad=&soyad=', 'params': 'ad, soyad' },
    { 'ad': 'ad_soyad_pro', 'url': 'https://keneviz.kolsuzpabg.workers.dev/ad_soyad_pro?tc=', 'params': 'tc' },
    { 'ad': 'is_yeri', 'url': 'https://keneviz.kolsuzpabg.workers.dev/is_yeri?tc=', 'params': 'tc' },
    { 'ad': 'vergi_no', 'url': 'https://keneviz.kolsuzpabg.workers.dev/vergi_no?vergi=', 'params': 'vergi' },
    { 'ad': 'yas', 'url': 'https://keneviz.kolsuzpabg.workers.dev/yas?tc=', 'params': 'tc' },
    { 'ad': 'tc_gsm', 'url': 'https://keneviz.kolsuzpabg.workers.dev/tc_gsm?tc=', 'params': 'tc' },
    { 'ad': 'gsm_tc', 'url': 'https://keneviz.kolsuzpabg.workers.dev/gsm_tc?gsm=', 'params': 'gsm' },
    { 'ad': 'adres', 'url': 'https://keneviz.kolsuzpabg.workers.dev/adres?tc=', 'params': 'tc' },
    { 'ad': 'hane', 'url': 'https://keneviz.kolsuzpabg.workers.dev/hane?tc=', 'params': 'tc' },
    { 'ad': 'apartman', 'url': 'https://keneviz.kolsuzpabg.workers.dev/apartman?tc=', 'params': 'tc' },
    { 'ad': 'ada_parsel', 'url': 'https://keneviz.kolsuzpabg.workers.dev/ada_parsel?il=&ada=&parsel=', 'params': 'il, ada, parsel' },
    { 'ad': 'adi_il_ilce', 'url': 'https://keneviz.kolsuzpabg.workers.dev/adi_il_ilce?ad=&il=', 'params': 'ad, il' },
    { 'ad': 'aile', 'url': 'https://keneviz.kolsuzpabg.workers.dev/aile?tc=', 'params': 'tc' },
    { 'ad': 'aile_pro', 'url': 'https://keneviz.kolsuzpabg.workers.dev/aile_pro?tc=', 'params': 'tc' },
    { 'ad': 'es', 'url': 'https://keneviz.kolsuzpabg.workers.dev/es?tc=', 'params': 'tc' },
    { 'ad': 'sulale', 'url': 'https://keneviz.kolsuzpabg.workers.dev/sulale?tc=', 'params': 'tc' },
    { 'ad': 'lgs', 'url': 'https://keneviz.kolsuzpabg.workers.dev/lgs?tc=', 'params': 'tc' },
    { 'ad': 'e_kurs', 'url': 'https://keneviz.kolsuzpabg.workers.dev/e_kurs?tc=&okulno=', 'params': 'tc, okulno' },
    { 'ad': 'ip', 'url': 'https://keneviz.kolsuzpabg.workers.dev/ip?domain=', 'params': 'domain' },
    { 'ad': 'dns', 'url': 'https://keneviz.kolsuzpabg.workers.dev/dns?domain=', 'params': 'domain' },
    { 'ad': 'whois', 'url': 'https://keneviz.kolsuzpabg.workers.dev/whois?domain=', 'params': 'domain' },
    { 'ad': 'subdomain', 'url': 'https://keneviz.kolsuzpabg.workers.dev/subdomain?url=', 'params': 'url' },
    { 'ad': 'leak', 'url': 'https://keneviz.kolsuzpabg.workers.dev/leak?query=', 'params': 'query' },
    { 'ad': 'telegram', 'url': 'https://keneviz.kolsuzpabg.workers.dev/telegram?kullanici=', 'params': 'kullanici' },
    { 'ad': 'sifre_encrypt', 'url': 'https://keneviz.kolsuzpabg.workers.dev/sifre_encrypt?method=&password=', 'params': 'method, password' },
    { 'ad': 'prem_ad', 'url': 'https://keneviz.kolsuzpabg.workers.dev/prem_ad?ad=&il=&ilce=', 'params': 'ad, il, ilce' },
    { 'ad': 'mhrs_randevu', 'url': 'https://keneviz.kolsuzpabg.workers.dev/mhrs_randevu?tc=', 'params': 'tc' },
    { 'ad': 'prem_adres', 'url': 'https://keneviz.kolsuzpabg.workers.dev/prem_adres?tc=', 'params': 'tc' },
    { 'ad': 'sgk_pro', 'url': 'https://keneviz.kolsuzpabg.workers.dev/sgk_pro?tc=', 'params': 'tc' },
    { 'ad': 'vergi_levhasi', 'url': 'https://keneviz.kolsuzpabg.workers.dev/vergi_levhasi?tc=', 'params': 'tc' },
    { 'ad': 'facebook', 'url': 'https://keneviz.kolsuzpabg.workers.dev/facebook?numara=', 'params': 'numara' },
    { 'ad': 'diploma', 'url': 'https://keneviz.kolsuzpabg.workers.dev/diploma?tc=', 'params': 'tc' },
    { 'ad': 'basvuru', 'url': 'https://keneviz.kolsuzpabg.workers.dev/basvuru?tc=', 'params': 'tc' },
    { 'ad': 'nobetci_eczane', 'url': 'https://keneviz.kolsuzpabg.workers.dev/nobetci_eczane?il=&ilce=', 'params': 'il, ilce' },
    { 'ad': 'randevu', 'url': 'https://keneviz.kolsuzpabg.workers.dev/randevu?tc=', 'params': 'tc' },
    { 'ad': 'internet', 'url': 'https://keneviz.kolsuzpabg.workers.dev/internet?tc=', 'params': 'tc' },
    { 'ad': 'personel', 'url': 'https://keneviz.kolsuzpabg.workers.dev/personel?tc=', 'params': 'tc' },
    { 'ad': 'interpol', 'url': 'https://keneviz.kolsuzpabg.workers.dev/interpol?ad=&soyad=', 'params': 'ad, soyad' },
    { 'ad': 'sehit', 'url': 'https://keneviz.kolsuzpabg.workers.dev/sehit?Ad=&Soyad=', 'params': 'Ad, Soyad' },
    { 'ad': 'arac_parca', 'url': 'https://keneviz.kolsuzpabg.workers.dev/arac_parca?plaka=', 'params': 'plaka' },
    { 'ad': 'universite', 'url': 'https://keneviz.kolsuzpabg.workers.dev/universite?tc=', 'params': 'tc' },
    { 'ad': 'sertifika', 'url': 'https://keneviz.kolsuzpabg.workers.dev/sertifika?tc=', 'params': 'tc' },
    { 'ad': 'nude', 'url': 'https://keneviz.kolsuzpabg.workers.dev/nude', 'params': '' },
    { 'ad': 'arac_borc', 'url': 'https://keneviz.kolsuzpabg.workers.dev/arac_borc?plaka=', 'params': 'plaka' },
    { 'ad': 'lgs_2', 'url': 'https://keneviz.kolsuzpabg.workers.dev/lgs_2?tc=', 'params': 'tc' },
    { 'ad': 'muhalle', 'url': 'https://keneviz.kolsuzpabg.workers.dev/muhalle?tc=', 'params': 'tc' },
    { 'ad': 'vesika', 'url': 'https://keneviz.kolsuzpabg.workers.dev/vesika?tc=', 'params': 'tc' },
    { 'ad': 'ehliyet', 'url': 'https://keneviz.kolsuzpabg.workers.dev/ehliyet?tc=', 'params': 'tc' },
    { 'ad': 'hava_durumu', 'url': 'https://keneviz.kolsuzpabg.workers.dev/hava_durumu?sehir=', 'params': 'sehir' },
    { 'ad': 'email', 'url': 'https://keneviz.kolsuzpabg.workers.dev/email?email=', 'params': 'email' },
    { 'ad': 'boy', 'url': 'https://keneviz.kolsuzpabg.workers.dev/boy?tc=', 'params': 'tc' },
    { 'ad': 'ayak_no', 'url': 'https://keneviz.kolsuzpabg.workers.dev/ayak_no?tc=', 'params': 'tc' },
    { 'ad': 'cm', 'url': 'https://keneviz.kolsuzpabg.workers.dev/cm?tc=', 'params': 'tc' },
    { 'ad': 'burc', 'url': 'https://keneviz.kolsuzpabg.workers.dev/burc?tc=', 'params': 'tc' },
    { 'ad': 'cocuk', 'url': 'https://keneviz.kolsuzpabg.workers.dev/cocuk?tc=', 'params': 'tc' },
    { 'ad': 'imei', 'url': 'https://keneviz.kolsuzpabg.workers.dev/imei?imei=', 'params': 'imei' },
    { 'ad': 'baba', 'url': 'https://keneviz.kolsuzpabg.workers.dev/baba?tc=', 'params': 'tc' },
    { 'ad': 'anne', 'url': 'https://keneviz.kolsuzpabg.workers.dev/anne?tc=', 'params': 'tc' },
    { 'ad': 'operator', 'url': 'https://keneviz.kolsuzpabg.workers.dev/operator?gsm=', 'params': 'gsm' },
    { 'ad': 'fatura', 'url': 'https://keneviz.kolsuzpabg.workers.dev/fatura?tc=', 'params': 'tc' },
    { 'ad': 'hexnox_subdomain', 'url': 'https://keneviz.kolsuzpabg.workers.dev/hexnox_subdomain?url=', 'params': 'url' },
    { 'ad': 'sexgorsel', 'url': 'https://keneviz.kolsuzpabg.workers.dev/sexgorsel?soru=', 'params': 'soru' },
    { 'ad': 'meslek_hex', 'url': 'https://keneviz.kolsuzpabg.workers.dev/meslek_hex?tc=', 'params': 'tc' },
    { 'ad': 'sgk_hex', 'url': 'https://keneviz.kolsuzpabg.workers.dev/sgk_hex?tc=', 'params': 'tc' },
    { 'ad': 'subdomain_generic', 'url': 'https://keneviz.kolsuzpabg.workers.dev/subdomain_generic?url=', 'params': 'url' },
    { 'ad': 'secmen', 'url': 'https://keneviz.kolsuzpabg.workers.dev/secmen?tc=', 'params': 'tc' },
    { 'ad': 'ogretmen', 'url': 'https://keneviz.kolsuzpabg.workers.dev/ogretmen?ad=&soyad=', 'params': 'ad, soyad' },
    { 'ad': 'smsbomber', 'url': 'https://keneviz.kolsuzpabg.workers.dev/smsbomber?number=', 'params': 'number' },
    { 'ad': 'yabanci', 'url': 'https://keneviz.kolsuzpabg.workers.dev/yabanci?ad=&soyad=', 'params': 'ad, soyad' },
    { 'ad': 'log', 'url': 'https://keneviz.kolsuzpabg.workers.dev/log?site=', 'params': 'site' },
    { 'ad': 'vesika2', 'url': 'https://keneviz.kolsuzpabg.workers.dev/vesika2?tc=', 'params': 'tc' },
    { 'ad': 'tapu2', 'url': 'https://keneviz.kolsuzpabg.workers.dev/tapu2?tc=', 'params': 'tc' },
]

# quick param map for frontend usage
API_PARAMS = {
    # TC tabanlı
    'tc_sorgulama': ['tc'],
    'tc_pro_sorgulama': ['tc'],
    'hayat_hikayesi': ['tc'],
    'ad_soyad': ['ad','soyad'],
    'ad_soyad_pro': ['tc'],
    'is_yeri': ['tc'],
    'vergi_no': ['vergi'],
    'yas': ['tc'],
    'tc_gsm': ['tc'],
    'gsm_tc': ['gsm'],
    'adres': ['tc'],
    'hane': ['tc'],
    'apartman': ['tc'],
    'ada_parsel': ['il','ada','parsel'],
    'adi_il_ilce': ['ad','il'],
    'aile': ['tc'],
    'aile_pro': ['tc'],
    'es': ['tc'],
    'sulale': ['tc'],
    'lgs': ['tc'],
    'e_kurs': ['tc','okulno'],
    # domain/gsm/others
    'ip': ['domain'],
    'dns': ['domain'],
    'whois': ['domain'],
    'subdomain': ['url'],
    'leak': ['query'],
    'telegram': ['kullanici'],
    'sifre_encrypt': ['method','password'],
    'prem_ad': ['ad','il','ilce'],
    'mhrs_randevu': ['tc'],
    'prem_adres': ['tc'],
    'sgk_pro': ['tc'],
    'vergi_levhasi': ['tc'],
    'facebook': ['numara'],
    'diploma': ['tc'],
    'basvuru': ['tc'],
    'nobetci_eczane': ['il','ilce'],
    'randevu': ['tc'],
    'internet': ['tc'],
    'personel': ['tc'],
    'interpol': ['ad','soyad'],
    'sehit': ['ad','soyad'],
    'arac_parca': ['plaka'],
    'universite': ['tc'],
    'sertifika': ['tc'],
    'nude': [],
    'arac_borc': ['plaka'],
    'lgs_2': ['tc'],
    'muhalle': ['tc'],
    'vesika': ['tc'],
    'ehliyet': ['tc'],
    'hava_durumu': ['sehir'],
    'email': ['email'],
    'boy': ['tc'],
    'ayak_no': ['tc'],
    'cm': ['tc'],
    'burc': ['tc'],
    'cocuk': ['tc'],
    'imei': ['imei'],
    'baba': ['tc'],
    'anne': ['tc'],
    'operator': ['gsm'],
    'fatura': ['tc'],
    'hexnox_subdomain': ['url'],
    'sexgorsel': ['soru'],
    'meslek_hex': ['tc'],
    'sgk_hex': ['tc'],
    'subdomain_generic': ['url'],
    'secmen': ['tc'],
    'ogretmen': ['ad','soyad'],
    'smsbomber': ['number'],
    'yabanci': ['ad','soyad'],
    'log': ['site'],
    'vesika2': ['tc'],
    'tapu2': ['tc'],
}


BASE_WORKER = 'https://keneviz.kolsuzpabg.workers.dev/'

SLUG_ALIAS = {
    'tc_sorgulama': 'tc_sorgulama',
    'tc-pro': 'tc_pro_sorgulama',
    'tc_pro_sorgulama': 'tc_pro_sorgulama',
    'ad_soyad': 'ad_soyad',
    'ad-soyad': 'ad_soyad',
    'ip': 'ip',
    'whois': 'whois',
    'dns': 'dns',
    'havadurumu': 'hava_durumu',
    'telegram': 'telegram',
}


def resolve_worker_url(slug, params):
    candidates = []
    if slug in SLUG_ALIAS:
        candidates.append(SLUG_ALIAS[slug])
    candidates.append(slug)
    candidates.append(slug.replace('-', '_'))
    candidates.append(slug.replace('_', '-'))
    seen = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]

    for cand in candidates:
        url = BASE_WORKER.rstrip('/') + '/' + cand
        if params:
            qs = urllib.parse.urlencode(params, doseq=True)
            url = url + '?' + qs
        return url
    return None


def proxy_worker_request(url):
    try:
        resp = requests.get(url, timeout=10)
        status = resp.status_code
        ctype = resp.headers.get('Content-Type','').lower()
        if 'application/json' in ctype or resp.text.strip().startswith('{') or resp.text.strip().startswith('['):
            try:
                return True, resp.json(), status
            except Exception:
                return True, resp.text, status
        else:
            return True, resp.text, status
    except requests.RequestException as e:
        return False, str(e), 502

# ----------------------------------------------------------------------------
# Robot/Doğrulama: challenge & daha toleranslı verify
# ----------------------------------------------------------------------------

@app.route('/keneviz_challenge', methods=['POST'])
def keneviz_challenge():
    nonce = secrets.token_urlsafe(16)
    now = int(time.time())
    # session'da challenge objesi
    session['keneviz_challenge'] = {
        'nonce': nonce,
        'ts': now,
        'tries': 0,
    }
    app.logger.debug(f"new challenge {nonce} ts={now} for session")
    return jsonify({'challenge_id': nonce, 'ts': now})


@app.route('/keneviz_verify', methods=['POST'])
def keneviz_verify():
    data = request.get_json() or {}
    saved = session.get('keneviz_challenge')
    if not saved:
        app.logger.warning("verify: no saved challenge for session")
        return jsonify({'success': False, 'error': 'no_challenge'}), 400

    # rate-limit / brute-force guard (basit)
    tries = int(saved.get('tries', 0))
    if tries >= 6:
        app.logger.warning("verify: too many tries, blocking")
        return jsonify({'success': False, 'error': 'too_many_attempts'}), 429

    incoming_nonce = data.get('challenge_id') or data.get('nonce')
    if not incoming_nonce or incoming_nonce != saved.get('nonce'):
        saved['tries'] = tries + 1
        session['keneviz_challenge'] = saved
        app.logger.info(f"verify: nonce mismatch incoming={incoming_nonce} expected={saved.get('nonce')}, tries={saved['tries']}")
        return jsonify({'success': False, 'error': 'challenge_mismatch'}), 400

    client_meta = data.get('client_meta') or {}

    # extract common signals (önemli: JS tarafındaki alan isimleriyle eşleşmeli)
    webdriver_flag = bool(client_meta.get('webdriver'))
    moves = int(client_meta.get('moves') or client_meta.get('mouse_moves') or 0)
    touch = bool(client_meta.get('touch'))
    hw = int(client_meta.get('hw') or client_meta.get('hardwareConcurrency') or 0)
    tz = client_meta.get('tz') or ''
    screen = client_meta.get('screen') or {}
    ua = client_meta.get('ua') or request.headers.get('User-Agent','')

    reasons = []
    # Heuristics (daha tolerant):
    # - webdriver true -> şüpheli ama tek başına fail etmeyebilir. (Burada hala reddediyoruz)
    # - moves > 0 OR touch true OR hw >=1 OR tz present => insan benzeri
    human_like = False
    if moves > 0:
        human_like = True
    if touch:
        # dokunmatik cihazlarda mousemove olmayabilir; touch göstergesi insanı gösterir
        human_like = True
    if hw >= 1:
        human_like = True
    if tz:
        human_like = True
    # ekran boyutu mantıklı mı?
    try:
        sw = int(screen.get('w') or 0)
        sh = int(screen.get('h') or 0)
        if sw > 50 and sh > 50:
            human_like = True
    except Exception:
        pass

    if webdriver_flag:
        reasons.append('webdriver_detected')

    if not human_like:
        reasons.append('no_human_interaction')

    # Karar: webdriver tespit edilirse reddet (daha güvenli).
    # Aksi halde, human_like ise geçir; değilse reddet.
    if webdriver_flag:
        saved['tries'] = tries + 1
        session['keneviz_challenge'] = saved
        app.logger.info(f"verify FAILED (webdriver). meta={client_meta}")
        return jsonify({'success': False, 'reasons': reasons}), 403

    if human_like:
        token = 'kv-' + secrets.token_urlsafe(12)
        session['keneviz_verified'] = True
        # temizle (tek seferlik)
        session.pop('keneviz_challenge', None)
        app.logger.info(f"verify PASSED token={token} ua={ua} meta={client_meta}")
        return jsonify({'success': True, 'verification_token': token})
    else:
        saved['tries'] = tries + 1
        session['keneviz_challenge'] = saved
        app.logger.info(f"verify FAILED reasons={reasons} tries={saved['tries']} meta={client_meta}")
        return jsonify({'success': False, 'reasons': reasons}), 403

# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------

@app.route('/')
def index():
    if session.get('key_id'):
        return redirect(url_for('panel'))
    if not session.get('keneviz_verified'):
        return redirect(url_for('robot_dogrulama') + '?next=/login')
    return render_template('index.html')


@app.route('/robot_dogrulama')
def robot_dogrulama():
    return render_template('robot_dogrulama.html')


@app.route('/sorgu.html')
def sorgu_page():
    return render_template('sorgu.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if not session.get('keneviz_verified'):
        return redirect(url_for('robot_dogrulama') + '?next=/login')
    if request.method == 'GET':
        return render_template('login.html')
    key_str = request.form.get('key', '').strip()
    key = verify_key_string(key_str)
    if not key:
        flash('Geçersiz veya süresi dolmuş key')
        return redirect(url_for('login'))
    session['key_id'] = key.id
    session.pop('keneviz_verified', None)
    return redirect(url_for('panel'))


@app.route('/logout')
def logout():
    session.pop('key_id', None)
    session.pop('admin_id', None)
    return redirect(url_for('index'))


@app.route('/panel')
def panel():
    kid = session.get('key_id')
    if not kid:
        return redirect(url_for('login'))
    key = Key.query.filter_by(id=kid).first()
    if not key or not key.active or key.is_expired():
        session.pop('key_id', None)
        flash('Key geçersiz veya süresi dolmuş')
        return redirect(url_for('login'))
    remaining = 'Limitsiz'
    if key.expires_at:
        remaining_delta = key.expires_at - datetime.utcnow()
        remaining = f"{remaining_delta.days} gün {remaining_delta.seconds//3600} saat"
    return render_template('panel.html', key=key, apis=APIS, remaining=remaining)

# ----------------------------------------------------------------------------
# Admin routes
# ----------------------------------------------------------------------------

@app.route('/admin/login', methods=['GET','POST'])
def admin_login():
    if request.method == 'GET':
        return render_template('admin_login.html')
    username = request.form.get('username')
    password = request.form.get('password')
    admin = Admin.query.filter_by(username=username).first()
    if not admin or not admin.check_password(password):
        flash('Geçersiz admin bilgileri')
        return redirect(url_for('admin_login'))
    session['admin_id'] = admin.id
    return redirect(url_for('admin_panel'))


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_id', None)
    return redirect(url_for('admin_login'))


@app.route('/admin')
def admin_panel():
    admin_id = session.get('admin_id')
    if not admin_id:
        return redirect(url_for('admin_login'))
    keys = Key.query.order_by(Key.created_at.desc()).limit(200).all()
    return render_template('admin_panel.html', keys=keys)


@app.route('/admin/generate')
def admin_generate():
    admin_id = session.get('admin_id')
    if not admin_id:
        return redirect(url_for('admin_login'))
    plan = request.args.get('plan', '1month')
    try:
        qty = int(request.args.get('qty', '1'))
    except ValueError:
        qty = 1
    note = request.args.get('note', None)

    created = []
    for _ in range(max(1, min(qty, 1000))):
        k = create_key(plan=plan, notes=note)
        created.append(k)

    lines = []
    for k in created:
        lines.append(f"New key created: {k.key} (plan={k.plan})")
    return "<br>".join(lines)

# ----------------------------------------------------------------------------
# API endpoints
# ----------------------------------------------------------------------------

@app.route('/api/user')
def api_user():
    kid = session.get('key_id')
    if not kid:
        return jsonify({'logged_in': False, 'role': 'guest', 'username': None})
    key = Key.query.filter_by(id=kid).first()
    if not key or not key.active or key.is_expired():
        return jsonify({'logged_in': False, 'role': 'guest', 'username': None})
    role = 'vip' if key.plan != 'free' else 'free'
    username = f"user{key.id}"
    return jsonify({'logged_in': True, 'role': role, 'username': username})


@app.route('/api/sorgu', methods=['POST'])
def api_sorgu():
    # Oturum bazlı erişim (frontend panelden çağrılacak)
    kid = session.get('key_id')
    if not kid:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    key_obj = Key.query.filter_by(id=kid).first()
    if not key_obj or not key_obj.active or key_obj.is_expired():
        return jsonify({'success': False, 'error': 'Invalid or expired key'}), 401

    payload = request.get_json() or {}
    api_slug = payload.get('api') or payload.get('action') or payload.get('slug')
    if not api_slug:
        return jsonify({'success': False, 'error': 'Missing api slug'}), 400

    params = {k:v for k,v in payload.items() if k not in ['api','action','slug'] and v is not None}

    url = resolve_worker_url(api_slug, params)
    if not url:
        return jsonify({'success': False, 'error': 'Unable to resolve worker endpoint'}), 400

    ok, data, status = proxy_worker_request(url)
    if not ok:
        return jsonify({'success': False, 'error': 'Upstream request failed', 'detail': data}), status
    if isinstance(data, (dict, list)):
        return jsonify({'success': True, 'data': data}), status
    return jsonify({'success': True, 'data': data}), status


@app.route('/api/list')
def api_list():
    key_header = request.args.get('key') or request.headers.get('X-API-KEY')
    key_obj = verify_key_string(key_header) if key_header else None
    if not key_obj:
        return jsonify({'error':'Invalid or missing key'}), 401
    return jsonify({'apis': APIS, 'plan': key_obj.plan})

# ----------------------------------------------------------------------------
# Startup
# ----------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
