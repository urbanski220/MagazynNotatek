import re
import time
from flask import Flask, flash, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from passlib.hash import sha256_crypt
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_ckeditor import CKEditor
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, BooleanField, ValidationError
from wtforms.validators import DataRequired, EqualTo, Length
from flask_ckeditor import CKEditorField
import bleach, blowfish


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = "234kj5j798sfpdsajfkad987982"

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
            if sha256_crypt.verify(form.password.data, user.password_hash):
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Wrong username or password!')
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
        content = bleach.clean(form.content.data)
        title = bleach.clean(form.title.data)
        if form.encrypted.data:
            if form.public.data:
                flash('You cannot publish encrypted notes!')
                return render_template('add_post.html',form=form)
            elif form.password.data == '':
                flash('You have to add password to encrypt your note!')
                return render_template('add_post.html',form=form)
            else:
                cipher = blowfish.Cipher(bytes(form.password.data, 'utf-8'))
                content = b"".join(cipher.encrypt_ecb_cts(bytes(content, 'utf-8')))
        flash(form.encrypted.data)
        post = Posts(title=title, content=content, poster_id = poster, public=form.public.data, encrypted=form.encrypted.data)
        form.title.data = ''
        form.content.data = ''
        form.public.data = ''
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
        return render_template('decrypt_note.html', form=form, decrypted=decrypted)
    return render_template('users_posts.html', form=form)


@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = bleach.clean(form.title.data)
        post.content = bleach.clean(form.content.data)

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
            return render_template('posts.html',posts=posts)
        except:
            flash('There was a problem deleting the note')
            posts = Posts.query.order_by(Posts.date_posted)
            return render_template('posts.html',posts=posts)
    else:
        flash("You cannot delete someone else's note")
        posts = Posts.query.order_by(Posts.date_posted)
        return render_template('posts.html',posts=posts)


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
        hashed_pw = sha256_crypt.hash(form.password_hash.data)
        user = Users(name=form.name.data, username=form.username.data ,email=form.email.data, password_hash=hashed_pw)
        db.session.add(user)
        db.session.commit()
        name = form.name.data
        flash('You created an account!')
    return render_template('register.html', form=form, name=name)

@app.route('/delete/<int:id>')

def delete(id):
    user_to_delete = Users.query.get_or_404(id)
    name = None
    form = UserForm()
    try:
        db.session.delete(user_to_delete)
        db.session.commit()
        flash('user deleted succesfully')
        our_users = Users.query.order_by(Users.date_added)
        return render_template('add_user.html', form=form,
            name = name,
            our_users=our_users)
    except:
        flash('error')
        return render_template('add_user.html', form=form,
            name = name,
            our_users=our_users)



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
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(25), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow)
    password_hash = db.Column(db.String(128))
    posts = db.relationship('Posts', backref='poster')
    count_wrong_logins = db.Column(db.Integer, default=0)
    date_blocked = db.Column(db.DateTime, default=datetime.utcnow)



class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    public = db.Column(db.Integer, default=0)
    encrypted = db.Column(db.Integer, default=0)
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))