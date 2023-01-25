import re
import time
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from passlib.hash import sha256_crypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_ckeditor import CKEditor
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_ckeditor import CKEditorField
import bleach, blowfish
import jwt


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = "234kj5j798sfpdsajfkad987982"

tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
        'h1', 'h2', 'h3', 'p', 'img', 'video', 'div', 'iframe', 'p', 'br', 'span', 'hr', 'src', 'class']
attrs = {'*': ['class'],
         'a': ['href', 'rel'],
        'img': ['src', 'alt', 'style']}

db = SQLAlchemy(app)

ckeditor = CKEditor(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))


@app.route('/login', methods=['GET', 'POST'])

def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            #time.sleep(1)
            if user.count_wrong_logins < 5:
                if user.blocked == 1 and ((datetime.now() - user.date_blocked).total_seconds()/60.0) < 5:
                    flash('Hey you failed to login to this account 5 times!\n You need to wait 5 minutes to log in again!')
                else:    
                    if sha256_crypt.verify(form.password.data, user.password_hash):
                        login_user(user)
                        user.count_wrong_logins = 0
                        user.blocked = 0
                        db.session.commit()
                        return redirect(url_for('index'))
                    else:
                        user.count_wrong_logins += 1
                        db.session.commit()
                        flash('Wrong username or password!')
            else:
                flash('Hey you failed to login to this account 5 times!\n You need to wait 5 minutes to log in again!')
                user.date_blocked = datetime.now()
                user.blocked = 1
                user.count_wrong_logins = 0
                db.session.commit()

        else:
            flash('Wrong username or password')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out!')
    return redirect(url_for('login'))


@app.route('/posts')
@login_required
def posts():
    posts = Posts.query.order_by(Posts.date_posted)
    return render_template('posts.html', posts=posts)

@app.route('/users_posts')
@login_required
def users_posts():
    posts = Posts.query.order_by(Posts.date_posted)
    return render_template('users_posts.html', posts=posts)

@app.route('/posts/<int:id>')
@login_required
def post(id):
    post = Posts.query.get_or_404(id)

    return render_template('post.html',post=post)

@app.route('/add-post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = PostForm()
    if form.validate_on_submit():
        poster = current_user.id
        content = bleach.clean(form.content.data, tags=tags, attributes=attrs)
        title = bleach.clean(form.title.data, tags=tags, attributes=attrs)
        if form.encrypted.data:
            if form.public.data:
                flash('You cannot publish encrypted notes!')
                return render_template('add_post.html',form=form)
            elif len(form.password.data) < 4:
                flash('Password needs to be at least 4 characters long to encrypt your note!')
                return render_template('add_post.html',form=form)
            else:
                cipher = blowfish.Cipher(bytes(form.password.data, 'utf-8'))
                content = b"".join(cipher.encrypt_ecb_cts(bytes(content, 'utf-8')))

        post = Posts(title=title, content=content, poster_id = poster, public=form.public.data, encrypted=form.encrypted.data)
        form.title.data = ''
        form.content.data = ''
        form.public.data = ''
        form.encrypted.data = ''
        db.session.add(post)
        db.session.commit()

        flash('Blog post submitted succesfully!')

    return render_template('add_post.html',form=form)

@app.route('/posts/decrypt/<int:id>', methods=['GET', 'POST'])
@login_required
def decrypt_note(id):
    post = Posts.query.get_or_404(id)
    form = DecryptForm()
    if form.validate_on_submit():
        time.sleep(1)
        cipher = blowfish.Cipher(bytes(form.password.data, 'utf-8'))
        decrypted = b"".join(cipher.decrypt_ecb_cts(post.content))
        decrypted_string = str(decrypted)[2:-1].replace('\\n', '')
        return render_template('decrypt_note.html', form=form, decrypted=decrypted_string)
    return render_template('decrypt_note.html', form=form)


@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = bleach.clean(form.title.data, tags=tags, attributes=attrs)
        post.content = bleach.clean(form.content.data, tags=tags, attributes=attrs)

        db.session.add(post)
        db.session.commit()

        flash('Post has been updated')

        return redirect(url_for('post', id=post.id))
    if current_user.id == post.poster.id:
        form.title.data = post.title
        form.content.data = post.content

        return render_template('edit_post.html', form=form)
    else:
        flash("You cannot edit someone else's note")
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template('posts.html', posts=posts)

@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    id = current_user.id
    if id == post_to_delete.poster.id:
        try:
            db.session.delete(post_to_delete)
            db.session.commit()
            
            flash('Note was deleted')
            posts = Posts.query.order_by(Posts.date_posted)
            return render_template('users_posts.html',posts=posts)
        except:
            flash('There was a problem deleting the note')
            posts = Posts.query.order_by(Posts.date_posted)
            return render_template('users_posts.html',posts=posts)
    else:
        flash("You cannot delete someone else's note")
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template('users_posts.html',posts=posts)


@app.route('/')

def index():
    return render_template('index.html')


@app.errorhandler(404)

def page_not_found(e):
    return render_template('404.html'), 404


@app.route('/user/register', methods=['GET','POST'])

def register():
    name = None
    form = UserForm()
    if form.validate_on_submit() and validate_password(form.password_hash.data) == 0:
        hashed_pw = sha256_crypt.using(salt='ochrona').hash(form.password_hash.data)
        user = Users(name=form.name.data, username=form.username.data ,email=form.email.data, password_hash=hashed_pw)
        db.session.add(user)
        db.session.commit()
        name = form.name.data
        flash('You created an account!')
    return render_template('register.html', form=form, name=name)


@app.route('/reset_password', methods=['GET','POST'])

def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('An email to reset your password has been sent')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route('/reset_password/<token>', methods=['GET','POST'])

def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    user = Users.verify_reset_token(token)
    if user is None:
        flash('That is an invalid token or expired token')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit() and validate_password(form.password.data) == 0:
        hashed_pw = sha256_crypt.using(salt='ochrona').hash(form.password.data)
        user.password_hash = hashed_pw 
        db.session.commit()
        flash('Your password has been updated!')
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)

def send_reset_email(user):
    token = user.get_reset_token()
    message = f''' Here I would send an email to {user.email} with a message:
    To reset your password visit this link:
{url_for('reset_token', token=token, _external=True)}
'''
    flash(message)
    

def validate_password(password):
        if re.search(r"\d", password) is None:
            flash('Password must contain at least one digit!')
            return 1        
        if re.search(r"[A-Z]", password) is None:
            flash('Password must contain at least one uppercase letter!')
            return 1
        if re.search(r"[a-z]", password) is None:
            flash('Password must contain at least one lowercase letter!')
            return 1
        if re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', password) is None:
            flash('Password must contain at least one symbol!')
            return 1
        return 0


class UserForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired()])
    password_hash = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password_hash2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password_hash', message='Passwords Must Match!')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = Users.query.filter_by(username=username.data).first()
        if user:
            flash('That username is already taken!')
            raise ValidationError('That username is already taken!')

    def validate_email(self, email):
        user = Users.query.filter_by(email=email.data).first()
        if user:
            flash('That email is already taken!')
            raise ValidationError('That email is already taken!')
    
    
class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = CKEditorField('Content', validators=[DataRequired()])
    submit = SubmitField('Submit')
    public = BooleanField('Public')
    encrypted = BooleanField('Encrypt')
    password = PasswordField('Password')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()]) 
    password = PasswordField('Password', validators=[DataRequired()]) 
    submit = SubmitField('Login')

class DecryptForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(min=4)])
    submit = SubmitField('Submit')


class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired()]) 
    submit = SubmitField('Request Password Reset')

    def validate_email(self, email):
        user = Users.query.filter_by(email=email.data).first()
        if user is None:
            flash('Account with that email does not exist!')
            raise ValidationError('Account with that email does not exist!')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password', message='Passwords Must Match!')])
    submit = SubmitField('Reset Password')


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Posts', backref='poster')
    count_wrong_logins = db.Column(db.Integer, default=0)
    date_blocked = db.Column(db.DateTime, default=datetime.now())
    blocked = db.Column(db.Integer, default=0)


    def get_reset_token(self, expires_sec=900):
        token = jwt.encode({
            'user_id' : self.id,
            'exp' : datetime.utcnow() + timedelta(seconds=expires_sec)
            }, app.config['SECRET_KEY'], algorithm="HS256")
        return token

    @staticmethod
    def verify_reset_token(token):
        try:
          data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"]) 
          user_id = data.get("user_id")
        except:
            return None
        return Users.query.get(user_id)

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    public = db.Column(db.Integer, default=0)
    encrypted = db.Column(db.Integer, default=0)
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))