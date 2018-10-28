import os
from flask import Flask, render_template, request, send_from_directory, redirect, url_for
#from PIL import Image
from resizeimage import resizeimage
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)

APP_ROOT = os.path.dirname(os.path.abspath(__file__))




app.config.update(dict(
                       SECRET_KEY="powerful secretkey",
                       WTF_CSRF_SECRET_KEY="a csrf secret key"
                       ))

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////Users/asimpoddar/Desktop/Projects/Resize/database.db'

Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key = True)
    username= db.Column(db.String(15), unique = True)
    email= db.Column(db.String(), unique = True)
    password= db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username' ,validators = [InputRequired(), Length(min = 4, max = 15 )])
    password = PasswordField('password' ,validators = [InputRequired(), Length(min = 8, max = 80 )])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    email = StringField('email', validators = [ InputRequired(), Email(message = 'Invalid Email')])
    username = StringField('username' ,validators = [InputRequired(), Length(min = 4, max = 15 )])
    password = PasswordField('password' ,validators = [InputRequired(), Length(min = 8, max = 80 )])






@app.route("/")
def index():
    return render_template("home.html")

@app.route ('/upload', methods = ["POST"])
def upload():
    target = os.path.join(APP_ROOT, 'images/')
    print (target)
    
    if not os.path.isdir(target):
        os.mkdir(target)
    else:
        print("Couldn't create directory: {}".format(target))
    print(request.files.getlist("file"))
    
    for upload in request.files.getlist("file"):
        print(upload)
        #print("{} is the file name".format(upload, filename))
        filename = upload.filename
        filename =  '-' + current_user.username + '-' + filename
        destination = "/".join([target, filename])
        print("Accept incoming file:", filename)
        print("Save to: ", destination)
        
        
        # with send_from_directory("images", filename) as f:
        #with Image.open(f) as image:
        #        cover = resizeimage.resize_cover(image, [200, 100])
        #        cover.save(filename, destination)


        upload.save(destination)
    return render_template("complete.html", image_name = filename,  name = current_user.username)
#To download the file:
#return send_from_directory("images", filename, as_attachment = True)

@app.route("/home")
@login_required
def loggedin():
    return render_template("upload.html", name = current_user.username)

@app.route('/upload/<filename>')
def send_image(filename):
    return send_from_directory("images", filename)

@app.route('/login', methods = ["GET", "POST"])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username = form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('loggedin'))

        return '<h1>Invalid Login Info</h1>'
    
    
    
    #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
    
    return render_template("login.html", form = form)

@app.route('/signup', methods = ["GET", "POST"])
def signup():
    form = RegisterForm()
    
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method = 'sha256')
        new_user = User(username = form.username.data, email = form.email.data, password = hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('loggedin'))
    
    # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'
    
    return render_template("signup.html", form = form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect (url_for('index'))


#to view all images together (not needed for assignment:)
@app.route('/gallery')
@login_required
def get_gallery():
    image_names = os.listdir('./images')
    return render_template("gallery.html", image_name = image_names, name = current_user.username)

@app.route('/')
def home():
    return render_template("home.html")


if __name__ == "__main__":
    app.run(debug=True)
