from __future__ import annotations
from typing import List

from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text, ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")


class Base(DeclarativeBase):
    pass


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///users.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


class User(db.Model, UserMixin):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))
    pics = relationship("PicUrl", back_populates="author")


class PicUrl(db.Model):
    __tablename__ = "pic_url"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    pic_url = mapped_column(String(400))
    author = relationship("User", back_populates="pics")

with app.app_context():
    db.create_all()


class UserData(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign Me Up!")


class Login(FlaskForm):
    email = StringField("email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class PostUrl(FlaskForm):
    post_url = StringField("url", validators=[URL()])
    submit = SubmitField("Post")


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    form = UserData()
    if form.validate_on_submit():
        hash_and_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hash_and_salted_password
        )
        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for("pic_url"))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = Login()
    # if form.validate_on_submit():
    #     user = db.session.execute(db.select(User).where(User.email == form.email.data)).scalar()
    #     if user and check_password_hash(user.password, form.password.data):
    #         login_user(user)
    #         return redirect(url_for('pic_url'))
    #     else:
    #         flash("Invalid email or password", "error")
    #         return redirect(url_for('login'))
    # return render_template('login.html', form=form)
    if form.validate_on_submit():
        password = form.password.data
        result = db.session.execute(db.select(User).where(User.email == form.email.data))
        user = result.scalar()
        if not user:
            flash("Email or password not correct")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Email or password not correct")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect('pic_url')
    return render_template('login.html', form=form)


@app.route('/pic_url', methods=["GET", "POST"])
def pic_url():
    form = PostUrl()
    if form.validate_on_submit():
        new_pic = PicUrl(
            pic_url=form.post_url.data,
            author_id=current_user.id
        )
        db.session.add(new_pic)
        db.session.commit()
        return redirect(url_for('user_pics', user_id=current_user.id))
    return render_template('pic_url.html', form=form)


@app.route('/success')
def success():
    return render_template('success.html')


@app.route('/show_all')
@login_required
def show_all():
    result = db.session.execute(db.select(User))
    posts = result.scalars().all()
    return render_template('show_all.html', users=posts)


@app.route('/all_pics')
@login_required
def all_pics():
    pics = db.session.execute(db.select(PicUrl)).scalars().all()
    return render_template('pics.html', pics=pics)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/user/<int:user_id>')
@login_required
def user_pics(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("show_all"))

    return render_template("user_pics.html", user=user)



@app.route('/delete/<int:pic_id>', methods=["POST"])
@login_required
def delete_pic(pic_id):
    pic = db.session.get(PicUrl, pic_id)
    if not pic:
        flash("Picture not found.", "error")
        return redirect(url_for('user_pics', user_id=current_user.id))

    if pic.author_id != current_user.id:
        flash("You are not authorized to delete this picture.", "error")
        return redirect(url_for('user_pic', user_id=current_user.id))

    db.session.delete(pic)
    db.session.commit()

    flash("Picture deleted successfully", "success")
    return redirect(url_for('user_pics', user_id=current_user.id))


if __name__ == "__main__":
    app.run(debug=False)
