from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, EqualTo
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

# Initialize the database
db = SQLAlchemy(app)

# Initialize Login Manager
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)  # Add this line to differentiate admins

    # Relationship to Image
    images = db.relationship('Image', backref='user', lazy=True)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # This links the image to a user

# Create the database tables if they don't exist
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Forms
class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=150)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired(), Length(min=4, max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=150)])
    submit = SubmitField('Login')

class UploadImageForm(FlaskForm):
    image = FileField('Choose Image', validators=[InputRequired()])
    submit = SubmitField('Upload Image')

# Routes
@app.route('/')
def home_redirect():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Check username and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/home', methods=['GET', 'POST'])
@login_required
def home():
    form = UploadImageForm()

    if current_user.is_admin:
        # Admin can see all images from all users
        images = Image.query.all()  # Admin sees all images
        users = User.query.all()  # Get all users for the admin
    else:
        # Regular users only see their own images
        images = Image.query.filter_by(user_id=current_user.id).all()  # Regular users see only their images
        users = []  # No need to pass users for regular users

    if form.validate_on_submit():
        image_file = form.image.data
        filename = secure_filename(image_file.filename)  # Ensure secure file name
        image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))  # Save the file to the server

        # Create a new Image record in the database
        new_image = Image(filename=filename, user_id=current_user.id)
        db.session.add(new_image)
        db.session.commit()

        flash('Image uploaded successfully!', 'success')
        return redirect(url_for('home'))

    return render_template('home.html', form=form, images=images, users=users)  # Pass users to the template if admin

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/set_admin')
def set_admin():
    # Find the admin user by username
    admin = User.query.filter_by(username='admin').first()
    
    # Check if admin exists and if is_admin is False, set it to True
    if admin:
        if not admin.is_admin:  # Only set to True if it's currently False
            admin.is_admin = True
            db.session.commit()
            return "Admin user is now set as an admin."
        else:
            return "Admin user is already an admin."
    else:
        return "Admin user not found."


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
