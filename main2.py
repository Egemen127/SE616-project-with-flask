from flask import Flask,render_template, redirect, url_for,request,flash ,session
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta
from sqlalchemy.sql import func
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user,UserMixin, LoginManager

app= Flask(__name__)

app.secret_key = "hello"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.sqlite3'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

class Users(db.Model,UserMixin):
    __tablename__='users'
    id = db.Column(db.Integer, primary_key = True)
    firstname= db.Column(db.String(100))
    lastname = db.Column(db.String(100))
    email = db.Column(db.String(100), nullable=False, unique = True)
    password = db.Column(db.String(100))
    summary = db.Column(db.String(1200))
    
    reviews = db.relationship('Review')
    

class Review(db.Model):
    __tablename__='review'
    id = db.Column(db.Integer, primary_key=True)
    review = db.Column(db.String(1000))
    sender_name= db.Column(db.String(150))
    star = db.Column(db.Integer)
    user_id = db.Column(db.Integer,db.ForeignKey('users.id'))
    date = db.Column(db.DateTime(timezone=True), default=func.now())
    @app.route('/logout')
    @login_required
    def logout():
        session.pop("email", None)
        logout_user()
        flash("Logged out!", category="info")
        return redirect(url_for('login'))
    @login_manager.user_loader
    def load_user(id):
        return Users.query.get(int(id))

    @app.route("/")
    def home():
        return render_template("index.html", user= current_user)
    @app.route("/aboutus")
    def aboutus():
        return render_template("aboutus.html" , user=current_user)
    @app.route("/login", methods = ["GET","POST"])
    def login():
        if current_user.is_active:
            flash("Already logged in!")
            return redirect(url_for('profil'))
        elif request.method =="POST":
            email = request.form.get('email')
            password = request.form.get('password')
            user = Users.query.filter_by(email=email).first()
            if user:
                if check_password_hash(user.password, password):
                    flash('Logged in successfully!', category='success')
                    login_user(user, remember=True)
                    session["email"] = user.email
                    return redirect(url_for('profil'))
                else:
                    flash('Incorrect password, try again.', category='error')
            else:
                flash('Email does not exist.', category='error')
        return render_template("login.html", user=current_user)
    @app.route("/signup", methods = ["GET", "POST"])
    def signup():
        if request.method== "POST":
            first_name = request.form.get("firstname").upper()
            last_name = request.form.get("lastname").upper()
            email = request.form.get("email")
            password = request.form.get("password")
            password2 = request.form.get("password2")
            # flash(f"{first_name} {last_name} {email} {password}")
            user = Users.query.filter_by(email=email).first()
            if user:
                flash('Email already exists.', category='error')
            elif len(email) < 4:
                flash('Email must be greater than 3 characters.', category='error')
            elif len(first_name) < 2:
                flash('First name must be greater than 1 character.', category='error')
            elif password != password2:
                flash('Passwords don\'t match.', category='error')
            elif len(password) < 7:
                flash('Password must be at least 7 characters.', category='error')
            else:
                new_user = Users(email=email, firstname=first_name, lastname=last_name,
                password=generate_password_hash(
                    password, method='sha256'))
                db.session.add(new_user)
                db.session.commit()
                login_user(new_user, remember=True)
                flash('Account created!', category='success')
                return redirect(url_for('home'))

        return render_template("signup.html", user=current_user)
  
            
    @app.route("/profil", methods = ["GET", "POST"])
    @login_required
    def profil():
        values = []
        if current_user.is_active is False:
            flash("Please login.")
            return redirect(url_for('login'))
        elif request.method =="POST":
            
            firstname=request.form["firstname"].upper()
            lastname= request.form["lastname"].upper()
            
            if firstname:
                values= Users.query.filter_by(firstname=firstname).all()
                if lastname:
                    values= [l for l in values if l.lastname ==lastname]
            elif lastname:
                values= Users.query.filter_by(lastname=lastname).all()
            
            
        return render_template("profiles.html", user=current_user, values = values)
    @app.route("/myprofile", methods = ["GET", "POST"])
    @login_required
    def myprofile():
        if current_user.is_active is False:
            flash("Please login.")
            return redirect(url_for('login'))
        else:
            reviews = Review.query.filter_by(user_id = current_user.id).all()
            reviews.reverse()
            
            if request.method =="POST":
                email = request.form["email"]
                _summary = request.form["summary"]
                user1 = Users.query.filter_by(email=email).first()
                
                
                
                if email:
                    if user1:
                        flash("Email already exists")
                    else:
                        current_user.email=email
                        db.session.commit()
                        flash("Email has been updated!")
                if _summary:
                    
                    current_user.summary=_summary
                    db.session.commit()
                    flash("Summary has been updated!")
                    return redirect(url_for("myprofile"))
                
            
        return render_template("myprofile.html", user=current_user, reviews = reviews)
    @app.route("/userprofile/<userid>", methods=['GET','POST'])
    @login_required
    def userprofile(userid):
        usr=Users.query.get(int(userid))
        if usr == current_user:
            return redirect(url_for("myprofile"))
        else:
            
            
            reviews = Review.query.filter_by(user_id = userid).all()
            reviews.reverse()

            if request.method=="POST":
                review=request.form["review"]
                star=request.form["star"]
                
                if review and star:
                    
                    # sname= f"{fname} {lname}"
                    new_review=Review(review=review, star=star, user_id=userid, sender_name=f"{current_user.firstname} {current_user.lastname}")
                    
                    db.session.add(new_review)
                    db.session.commit()
                    flash("Your review has been sent!")
                else: 
                    flash("Please type a review!")
                return redirect(url_for("userprofile", userid=userid))
            return render_template("userprofile.html", user=current_user, usr=usr, reviews=reviews)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)


