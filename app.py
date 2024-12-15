from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_migrate import Migrate
import os

app = Flask(__name__)
app.secret_key = 'rahasiabro'

# Konfigurasi database SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///finance.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
migrate = Migrate(app, db)

# Konfigurasi Flask-Login
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please login to access this page."
login_manager.login_message_category = "warning"

# Model database untuk pengguna
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    transactions = db.relationship('Transaction', backref='user', lazy=True)

# Model database untuk transaksi
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    description = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(10), nullable=False)  # 'income' atau 'expense'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def log_request():
    print(f"Incoming request: {request.method} {request.path}")

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory(app.static_folder, filename)

# Route untuk registrasi pengguna
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password are required.", "danger")
            return redirect(url_for("register"))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("Username is already taken. Please choose another.", "danger")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

# Route untuk login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash("Logged in successfully!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")
    return render_template("login.html")

# Route untuk logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# Route untuk halaman utama
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        amount = request.form.get("amount")
        description = request.form.get("description")
        transaction_type = request.form.get("transaction_type")

        if not amount or not description or not transaction_type:
            flash("All fields are required.", "danger")
            return redirect(url_for("index"))

        new_transaction = Transaction(
            amount=float(amount),
            description=description,
            type=transaction_type,
            user_id=current_user.id
        )
        db.session.add(new_transaction)
        db.session.commit()
        flash("Transaction added successfully!", "success")
        return redirect(url_for("dashboard"))
    return render_template("index.html")

# Route untuk dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    filter_type = request.args.get("filter")  # Ambil filter dari query parameter
    transactions = Transaction.query.filter_by(user_id=current_user.id)

    if filter_type:
        transactions = transactions.filter_by(type=filter_type)

    transactions = transactions.all()
    total_income = sum(t.amount for t in transactions if t.type == "income")
    total_expense = sum(t.amount for t in transactions if t.type == "expense")
    balance = total_income - total_expense

    return render_template(
        "dashboard.html",
        transactions=transactions,
        total_income=total_income,
        total_expense=total_expense,
        balance=balance,
        filter_type=filter_type
    )

# Route untuk menghapus transaksi
@app.route("/delete/<int:transaction_id>")
@login_required
def delete_transaction(transaction_id):
    transaction = Transaction.query.get(transaction_id)
    if transaction and transaction.user_id == current_user.id:
        db.session.delete(transaction)
        db.session.commit()
        flash("Transaction deleted successfully!", "success")
    else:
        flash("Transaction not found or unauthorized.", "danger")
    return redirect(url_for("dashboard"))

# Route untuk edit transaksi
@app.route("/edit/<int:transaction_id>", methods=["GET", "POST"])
@login_required
def edit_transaction(transaction_id):
    transaction = Transaction.query.get(transaction_id)
    if transaction is None or transaction.user_id != current_user.id:
        flash("Transaction not found or unauthorized.", "danger")
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        transaction.amount = float(request.form.get("amount"))
        transaction.description = request.form.get("description")
        transaction.type = request.form.get("transaction_type")
        db.session.commit()
        flash("Transaction updated successfully!", "success")
        return redirect(url_for("dashboard"))
    return render_template("edit.html", transaction=transaction)

# Data authors, termasuk nama, gambar, dan deskripsi
authors_data = [
    {
        "name": "Willy Agustianus",
        "photo": "willy.jpg",  # Pastikan gambar ini ada di folder static
        "description": "Full Stack Developer."
    },
    {
        "name": "Cahyo Apriansyah Catur Aji",
        "photo": "cahyo.jpg",  # Pastikan gambar ini ada di folder static
        "description": "Security Development."
    },
    {
        "name": "Rafi Ahmad Baihaqi",
        "photo": "rafi.jpg",  # Pastikan gambar ini ada di folder static
        "description": "Frontend Developer."
    },
    {
        "name": "Muhammad Akbar Firmansyah",
        "photo": "akbar.jpg",  # Pastikan gambar ini ada di folder static
        "description": "Backend Developer."
    }
]

# Route untuk halaman authors
@app.route("/authors")
def authors():
    return render_template("authors.html", authors=authors_data)

if __name__ == "__main__":
    app.run(debug=True)
