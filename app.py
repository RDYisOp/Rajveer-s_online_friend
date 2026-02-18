from flask import Flask, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI
from datetime import datetime
import os

app = Flask(__name__)
app.config["SECRET_KEY"] = "rajveer_secret"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///rajveer_ai.db"

db = SQLAlchemy(app)
login_manager = LoginManager(app)

client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

# ================= DATABASE MODELS =================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200))
    role = db.Column(db.String(10))
    usage_count = db.Column(db.Integer, default=0)

class ChatHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    question = db.Column(db.Text)
    answer = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class TestResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    score = db.Column(db.Integer)
    total = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ================= INIT DATABASE (Flask 3 FIX) =================

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="rajveer").first():
        admin = User(
            username="rajveer",
            password=generate_password_hash("admin123"),
            role="admin"
        )
        db.session.add(admin)
        db.session.commit()

# ================= LOGIN =================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()

        if user and check_password_hash(user.password, request.form["password"]):
            login_user(user)
            return redirect("/")

        return "Invalid login"

    return """
    <h2>Rajveer's Online Friend</h2>
    <form method="post">
    Username:<input name="username"><br>
    Password:<input name="password"><br>
    <button>Login</button>
    </form>
    """

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

# ================= REGISTER (ADMIN ONLY, MAX 10 USERS) =================

@app.route("/register", methods=["POST"])
@login_required
def register():
    if current_user.role != "admin":
        return "Only admin can add users"

    if User.query.count() >= 10:
        return "User limit reached (10 max)"

    new_user = User(
        username=request.form["username"],
        password=generate_password_hash(request.form["password"]),
        role="user"
    )

    db.session.add(new_user)
    db.session.commit()

    return "User created"

# ================= HOME =================

@app.route("/")
@login_required
def home():
    return f"""
    <h2>Rajveer's Online Friend</h2>
    <p>Welcome {current_user.username}</p>

    <a href="/mock-test">Take Mock Test</a><br>
    <a href="/leaderboard">Leaderboard</a><br>
    <a href="/dashboard">Admin Dashboard</a><br><br>

    <form action="/chat" method="post">
    <input name="question" size="60">
    <button>Ask AI</button>
    </form>

    <br><a href="/logout">Logout</a>
    """

# ================= SMART AI =================

@app.route("/chat", methods=["POST"])
@login_required
def chat():
    if current_user.usage_count >= 100:
        return "Daily limit reached."

    question = request.form["question"]

    primary = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are an elite JEE tutor. Solve step-by-step."},
            {"role": "user", "content": question}
        ]
    )

    reply = primary.choices[0].message.content

    if len(reply) < 80 or "UNSURE" in reply:
        fallback = client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": "You are a senior IIT professor. Solve rigorously."},
                {"role": "user", "content": question}
            ]
        )
        reply = fallback.choices[0].message.content + "\n\n[Enhanced Mode Activated]"

    chat_entry = ChatHistory(
        user_id=current_user.id,
        question=question,
        answer=reply
    )

    db.session.add(chat_entry)
    current_user.usage_count += 1
    db.session.commit()

    return f"<p><b>Answer:</b><br>{reply}</p><br><a href='/'>Back</a>"

# ================= MOCK TEST =================

@app.route("/mock-test")
@login_required
def mock_test():
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "Generate 5 JEE level MCQs with options and correct answers separately."}
        ]
    )

    questions = response.choices[0].message.content

    return f"""
    <h2>Mock Test</h2>
    <pre>{questions}</pre>
    <form action="/submit-test" method="post">
    Score:<input name="score">
    Total:<input name="total">
    <button>Submit</button>
    </form>
    """

@app.route("/submit-test", methods=["POST"])
@login_required
def submit_test():
    score = int(request.form["score"])
    total = int(request.form["total"])

    result = TestResult(
        user_id=current_user.id,
        score=score,
        total=total
    )

    db.session.add(result)
    db.session.commit()

    return "<p>Test recorded.</p><a href='/'>Back</a>"

# ================= LEADERBOARD =================

@app.route("/leaderboard")
@login_required
def leaderboard():
    results = TestResult.query.all()

    scores = {}
    for r in results:
        if r.user_id not in scores:
            scores[r.user_id] = 0
        scores[r.user_id] += r.score

    board = "<h2>Leaderboard</h2>"
    sorted_scores = sorted(scores.items(), key=lambda x: x[1], reverse=True)

    for user_id, total_score in sorted_scores:
        user = User.query.get(user_id)
        board += f"{user.username} : {total_score}<br>"

    return board + "<br><a href='/'>Back</a>"

# ================= DASHBOARD =================

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.role != "admin":
        return "Admin only"

    users = User.query.all()
    logs = ChatHistory.query.order_by(ChatHistory.timestamp.desc()).limit(10).all()

    user_info = "<h3>Users</h3>"
    for u in users:
        user_info += f"{u.username} | Usage: {u.usage_count}<br>"

    log_info = "<h3>Recent Activity</h3>"
    for l in logs:
        log_info += f"{l.timestamp} | Q: {l.question[:40]}...<br>"

    return user_info + "<br>" + log_info + "<br><a href='/'>Back</a>"

# ================= RUN =================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
        
