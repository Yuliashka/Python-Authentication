# HASH AND SALT DOCS: https://werkzeug.palletsprojects.com/en/1.0.x/utils/#module-werkzeug.security
# FLASK LOGIN DOCS: https://flask-login.readthedocs.io/en/latest/
# CHECK PASSWORD: https://werkzeug.palletsprojects.com/en/1.0.x/utils/#werkzeug.security.check_password_hash
# FLASK FLASH MESSAGES: https://flask.palletsprojects.com/en/1.1.x/patterns/flashing/

from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
# TO HASH THE PASSWORD:
# To do this, we'll use the Werkzeug helper function generate_password_hash()
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


# WORKING WITH FLASK LOGIN:
# The login manager contains the code that lets your application and Flask-Login work together,
# such as how to load a user from an ID, where to send users when they need to log in,
# and the like.
login_manager = LoginManager()
# CONFIG OUR APP TO BE ABLE TO USE FLASK_LOGIN:
# Once the actual application object has been created, you can configure it for login with:
login_manager.init_app(app)

# CREATING USER LOADER FUNCTION:
# You will need to provide a user_loader callback. This callback is used to reload
# the user object from the user ID stored in the session.
# It should take the unicode ID of a user, and return the corresponding user object.
# For example:
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##CREATE TABLE IN DB
# For FLask_login we need to implement the UserMixin in our User class.
# A Mixin is simply a way to provide multiple inheritance to Python.
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
#Line below only required once, when creating DB. 
# db.create_all()


@app.route('/')
def home():
    # Every render_template has a logged_in variable set.
    # current_user function is from flask_login
    return render_template("index.html", logged_in=current_user.is_authenticated)



@app.route('/register', methods=["GET", "POST"])
def register():
    # IF THE FORM AT REGISTER.HTML WILL BE POSTED:
    if request.method == "POST":
        # CHECKING IF SUCH EMAIL ALREADY EXIST IN OUR DATABASE:
        # Taking email value from the input at register.html
        email = request.form.get("email")
        # Finding our user with such email in our Database:
        existed_user = User.query.filter_by(email=email).first()

        # USING FLASK FLASH MESSAGES:
        # Check if the user with such email already exists in our DB:
        if existed_user:
            flash("That email already exists, please login.")
            return redirect(url_for('login'))
        else:
            # ADDING HASH AND SALT PASSWORD:
            # Here we are using generate_password_hash() function of Werkzeug.
            # In the beginning we added:
            # from werkzeug.security import generate_password_hash, check_password_hash
            hash_and_salted_password = generate_password_hash(
                request.form.get('password'),
                method='pbkdf2:sha256',
                salt_length=8
            )
            # We create a new user for our database and add it.
            # We are taking the info about our user from form inputs using input name.
            # We passing to our new user our hashed password:
            new_user = User(
                email=request.form.get("email"),
                name=request.form.get("name"),
                password=hash_and_salted_password,

            )
            db.session.add(new_user)
            db.session.commit()

            # After adding new user to db, we send him to secrets.html page and pass there info about
            # our user:
            return render_template('secrets.html', user=new_user)

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():

    # If we press the button "LET me in":
    if request.method == "POST":
        # We get the information from email input from login.html page:
        email = request.form.get("email")
        password = request.form.get("password")

        # Finding our user with such email in our Database:
        existed_user = User.query.filter_by(email=email).first()

        # USING FLASK FLASH MESSAGES:
        # If there is no such user in our database:
        if not existed_user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))

        # USING werkzeug.security check_password_hash() function:
        # If there is no such password in our database (hashed and salt password)
        elif not check_password_hash(existed_user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        # Email exists and password correct
        else:
            login_user(existed_user)
            return redirect(url_for('secrets'))

    return render_template("login.html", logged_in=current_user.is_authenticated)


# Adding Flask_login function login_required():
@app.route('/secrets')
@login_required
def secrets():
    # Current_user function we are taking from Flask_Login
    # Flask make the analyse of routes and check which user is using it now
    print(current_user.name)
    return render_template("secrets.html", user=current_user)


@app.route('/logout')
def logout():
    # To logout our user we are using logout_user() function from Flask_Login
    # The user will be logged out, and any cookies for his session will be cleaned up.
    logout_user()
    return redirect(url_for('home'))


# TO DOWNLOAD SOME FILE:
# using Flask method send_from_directory: https://flask.palletsprojects.com/en/1.1.x/api/#flask.send_from_directory
# https://gist.github.com/angelabauer/fb9e657162a881d02a6b2c0024de7c15
@app.route('/download/<path:filename>')
# using a login_required function from Flask_Login
@login_required
def download(filename):
    return send_from_directory(
        directory="static/files",
        path=filename,
        # as_attachment=True - this will download the file to our computer
        as_attachment=False

    )


if __name__ == "__main__":
    app.run(debug=True)
