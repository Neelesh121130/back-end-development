from flask import Flask, request, jsonify, session, g
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from passlib.hash import pbkdf2_sha256
import functools
import time

app = Flask(__name__)
app.config['SECRET_KEY'] = 'change-this-secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///community.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    body = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved = db.Column(db.Boolean, default=False)  # moderation flag
    reports = db.relationship('Report', backref='post', lazy=True)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    reporter = db.Column(db.String(80))
    reason = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Audit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(200))
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# --- Simple in-memory rate limiter (per-IP) ---
RATE_LIMIT = {
    'window_seconds': 60,
    'max_requests': 10
}
_requests = {}

def rate_limited():
    ip = request.remote_addr or 'unknown'
    now = time.time()
    window = RATE_LIMIT['window_seconds']
    max_req = RATE_LIMIT['max_requests']
    reqs = _requests.get(ip, [])
    # drop old
    reqs = [t for t in reqs if t > now - window]
    if len(reqs) >= max_req:
        return True
    reqs.append(now)
    _requests[ip] = reqs
    return False

# --- Simple content rules (example) ---
DISALLOWED_WORDS = {'insult1','insult2','illegalword'}  # replace with actual policy terms

def violates_policy(text):
    lower = text.lower()
    for w in DISALLOWED_WORDS:
        if w in lower:
            return True, f"Contains disallowed term: {w}"
    return False, None

# --- Helpers ---
def login_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error':'authentication required'}), 401
        g.user = User.query.get(user_id)
        if not g.user:
            return jsonify({'error':'invalid session'}), 401
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error':'authentication required'}), 401
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            return jsonify({'error':'admin privileges required'}), 403
        g.user = user
        return f(*args, **kwargs)
    return wrapper

def audit(action, details=''):
    db.session.add(Audit(action=action, details=details))
    db.session.commit()

# --- Routes ---
@app.route('/init', methods=['POST'])
def init_db():
    """Initialize DB and create an admin account (call once)."""
    db.create_all()
    # create admin if missing
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', password_hash=pbkdf2_sha256.hash('adminpass'), is_admin=True)
        db.session.add(admin)
        db.session.commit()
    return jsonify({'status':'ok','admin_user':'admin','admin_pass':'adminpass'})

@app.route('/register', methods=['POST'])
def register():
    if rate_limited():
        return jsonify({'error':'too many requests'}), 429
    data = request.json or {}
    username = data.get('username','').strip()
    password = data.get('password','')
    if not username or not password:
        return jsonify({'error':'username and password required'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error':'username taken'}), 400
    user = User(username=username, password_hash=pbkdf2_sha256.hash(password))
    db.session.add(user)
    db.session.commit()
    audit('register', f'user={username}')
    return jsonify({'status':'registered'})

@app.route('/login', methods=['POST'])
def login():
    if rate_limited():
        return jsonify({'error':'too many requests'}), 429
    data = request.json or {}
    username = data.get('username','').strip()
    password = data.get('password','')
    user = User.query.filter_by(username=username).first()
    if not user or not pbkdf2_sha256.verify(password, user.password_hash):
        return jsonify({'error':'invalid credentials'}), 401
    session['user_id'] = user.id
    audit('login', f'user={username}')
    return jsonify({'status':'logged_in'})

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    uname = g.user.username
    session.pop('user_id', None)
    audit('logout', f'user={uname}')
    return jsonify({'status':'logged_out'})

@app.route('/posts', methods=['POST'])
@login_required
def create_post():
    if rate_limited():
        return jsonify({'error':'too many requests'}), 429
    data = request.json or {}
    title = (data.get('title') or '').strip()
    body = (data.get('body') or '').strip()
    if not title or not body:
        return jsonify({'error':'title and body required'}), 400
    # policy check
    violated, reason = violates_policy(title + ' ' + body)
    if violated:
        return jsonify({'error':'content violates policy','reason':reason}), 400
    post = Post(author_id=g.user.id, title=title, body=body, approved=False)
    db.session.add(post)
    db.session.commit()
    audit('create_post', f'user={g.user.username},post_id={post.id}')
    return jsonify({'status':'created','post_id':post.id})

@app.route('/posts', methods=['GET'])
def list_posts():
    # only show approved posts to public
    posts = Post.query.filter_by(approved=True).order_by(Post.created_at.desc()).limit(100).all()
    out = []
    for p in posts:
        out.append({
            'id': p.id,
            'title': p.title,
            'body': p.body,
            'author_id': p.author_id,
            'created_at': p.created_at.isoformat()
        })
    return jsonify(out)

@app.route('/post/<int:post_id>', methods=['GET'])
def get_post(post_id):
    p = Post.query.get_or_404(post_id)
    if not p.approved:
        # only admin or author can view unapproved
        uid = session.get('user_id')
        if not uid or (uid != p.author_id and not (User.query.get(uid) and User.query.get(uid).is_admin)):
            return jsonify({'error':'not found'}), 404
    return jsonify({
        'id': p.id, 'title': p.title, 'body': p.body,
        'author_id': p.author_id, 'approved': p.approved,
        'created_at': p.created_at.isoformat()
    })

@app.route('/report/<int:post_id>', methods=['POST'])
@login_required
def report_post(post_id):
    data = request.json or {}
    reason = data.get('reason','').strip()
    p = Post.query.get_or_404(post_id)
    rpt = Report(post_id=post_id, reporter=g.user.username, reason=reason)
    db.session.add(rpt)
    db.session.commit()
    audit('report', f'user={g.user.username},post_id={post_id},reason={reason}')
    return jsonify({'status':'reported'})

# --- Admin moderation ---
@app.route('/admin/moderation', methods=['GET'])
@admin_required
def moderation_queue():
    # return posts that need review
    posts = Post.query.filter_by(approved=False).order_by(Post.created_at.asc()).all()
    out = []
    for p in posts:
        out.append({
            'id':p.id, 'title':p.title, 'body':p.body, 'author_id':p.author_id,
            'created_at':p.created_at.isoformat(), 'reports':[{'id':r.id,'reporter':r.reporter,'reason':r.reason} for r in p.reports]
        })
    return jsonify(out)

@app.route('/admin/approve/<int:post_id>', methods=['POST'])
@admin_required
def approve_post(post_id):
    p = Post.query.get_or_404(post_id)
    p.approved = True
    db.session.commit()
    audit('approve', f'admin={g.user.username},post_id={post_id}')
    return jsonify({'status':'approved'})

@app.route('/admin/remove/<int:post_id>', methods=['POST'])
@admin_required
def remove_post(post_id):
    p = Post.query.get_or_404(post_id)
    db.session.delete(p)
    db.session.commit()
    audit('remove', f'admin={g.user.username},post_id={post_id}')
    return jsonify({'status':'removed'})

@app.route('/admin/audit', methods=['GET'])
@admin_required
def view_audit():
    entries = Audit.query.order_by(Audit.timestamp.desc()).limit(200).all()
    return jsonify([{'action':e.action,'details':e.details,'timestamp':e.timestamp.isoformat()} for e in entries])

# --- Misc ---
@app.errorhandler(404)
def not_found(e):
    return jsonify({'error':'not found'}), 404

if __name__ == '__main__':
    # create db tables if missing
    with app.app_context():
        db.create_all()
    app.run(debug=True)

