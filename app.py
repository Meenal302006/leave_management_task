from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Use a strong secret key in production

# Database config
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///elms.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login manager setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class UserModel(UserMixin, db.Model):
    __tablename__ = 'user_model'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(20), nullable=False)

    def get_id(self):
        return str(self.id)

# Leave model
class LeaveRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user_model.id'), nullable=False)
    start_date = db.Column(db.String(20), nullable=False)
    end_date = db.Column(db.String(20), nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), default='Pending')

# Load user
@login_manager.user_loader
def load_user(user_id):
    return UserModel.query.get(int(user_id))

# Create users route
@app.route('/create_users')
def create_users():
    if not UserModel.query.first():
        u1 = UserModel(username='admin', password=generate_password_hash('admin123'), role='Admin')
        u2 = UserModel(username='employee', password=generate_password_hash('emp123'), role='Employee')
        u3 = UserModel(username='manager', password=generate_password_hash('mgr123'), role='Manager')
        db.session.add_all([u1, u2, u3])
        db.session.commit()
        return "✅ Sample users created."
    return "ℹ️ Users already exist."

# Home redirects to login
@app.route('/')
def home():
    return redirect(url_for('login'))

with app.app_context():
    db.create_all()

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = UserModel.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            error = '❌ Invalid username or password.'

    return render_template('login.html', error=error)



# Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Apply Leave
@app.route('/apply_leave', methods=['GET', 'POST'])
@login_required
def apply_leave():
    if request.method == 'POST':
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        reason = request.form['reason']

        leave = LeaveRequest(
            user_id=current_user.id,
            start_date=start_date,
            end_date=end_date,
            reason=reason
        )
        db.session.add(leave)
        db.session.commit()
        flash("✅ Leave request submitted!", "success")
        return redirect(url_for('dashboard'))

    return render_template('apply_leave.html')

@app.route('/my_leaves')
@login_required
def my_leaves():
    leaves = LeaveRequest.query.filter_by(user_id=current_user.id).all()
    return render_template('my_leaves.html', leaves=leaves)

@app.route('/admin/leave_requests')
@login_required
def admin_leave_requests():
    if current_user.role != 'Admin':
        return "⛔ Access Denied", 403

    leaves = LeaveRequest.query.all()
    return render_template('admin_leaves.html', leaves=leaves)

@app.route('/admin/update_leave/<int:leave_id>/<string:status>')
@login_required
def update_leave_status(leave_id, status):
    if current_user.role != 'Admin':
        return "⛔ Access Denied", 403

    leave = LeaveRequest.query.get_or_404(leave_id)
    leave.status = status
    db.session.commit()
    flash(f"Leave status updated to {status}", "success")
    return redirect(url_for('admin_leave_requests'))

# Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("👋 You have been logged out.", "info")
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
print("ROUTES LOADED:", app.url_map)