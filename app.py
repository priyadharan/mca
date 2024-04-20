from flask import Flask,render_template,url_for,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from wtforms import FileField,SubmitField
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_login import UserMixin

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import os

app= Flask(__name__)
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///database.db'
app.config['SECRET_KEY']='thisissecretkey'
app.config['UPLOAD_FOLDER'] ='static/files'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view="login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username=db.Column(db.String(20), nullable=False, unique=True)
    password=db.Column(db.String(80), nullable=False)

class User1(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    projectname=db.Column(db.String(80), nullable=False, unique=True)
    projectguide=db.Column(db.String(80), nullable=False)


class RegisterForm(FlaskForm):
    username=StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password=PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit=SubmitField("Register")

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("that username already exists.")
        
class LoginForm(FlaskForm):
    username=StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password=PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit=SubmitField("Login")

class DetailsForm(FlaskForm):
    projectname=StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Projectname"})
    projectguide=PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Projectguide"})
    submit=SubmitField("Details")

class UploadFileForm(FlaskForm):
    file=FileField("File", validators=[InputRequired()])
    submit=SubmitField("Upload File")

admin = Admin(app)
admin.add_view(ModelView(User, db.session))
admin.add_view(ModelView(User1, db.session))


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET','POST'])
def login():
    
    form=LoginForm()
    if form.validate_on_submit():
        user=User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)

@app.route('/dashboard', methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout',methods=['GET','POST'])

def logout():
    logout_user()
    
    return render_template('logout.html')


@app.route('/register', methods=['GET','POST'])
def register():
    form=RegisterForm()

    if form.validate_on_submit():
        hashed_password=bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)
@app.route('/pro',methods=['GET','POST'])
def pro():
    form=UploadFileForm()
    if form.validate_on_submit():
        file=form.file.data
        file.save(os.path.join(os.path.abspath(os.path.dirname(__file__)),app.config['UPLOAD_FOLDER'],secure_filename(file.filename)))
        return "File has been uploaded!"
    return render_template('pro.html',form=form)

@app.route('/details',methods=['GET','POST'])
def details():
    form=DetailsForm()  
    if form.validate_on_submit():
       new_user = User1(projectname=form.projectname.data, projectguide=form.projectguide.data)
       db.session.add(new_user)
       db.session.commit()
       
       return redirect(url_for('pro'))
    return render_template('/details.html',form=form)

if __name__=='__main__':
    app.run(debug=True)
