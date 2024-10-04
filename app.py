import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import UserMixin, login_user, login_required, logout_user, current_user, LoginManager
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import RequestEntityTooLarge
from wtforms import TextAreaField, FileField


def handle_large_file(e):
    flash('File size exceeds the allowed limit of 2MB.', 'danger')
    return redirect(request.url)



class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is already taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = SubmitField('Remember me')
    submit = SubmitField('Login')
    
class AddPostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Blog Content', validators=[DataRequired()])
    file = FileField('Upload Image', validators=[DataRequired()])
    submit = SubmitField('Post Blog')



app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = 'sqlite:///blogs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'thisisasecretkey'
UPLOAD_FOLDER = 'static/uploads' 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
csrf=CSRFProtect(app)


app.config['MAX_CONTENT_LENGTH'] = 2 * 1024 * 1024  # 2MB limit

@app.errorhandler(RequestEntityTooLarge)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Models
class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(50))
    author = db.Column(db.String(20))
    post_date = db.Column(db.DateTime)
    image_filename = db.Column(db.String(200), nullable=True)  # Add this line
    content = db.Column(db.Text)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

# Routes
@app.route("/")
def home():
    articles = Article.query.order_by(Article.post_date.desc()).all()
    if current_user.is_anonymous:
        name = 'guest'
    else:
        name = current_user.username
    return render_template("home.html", articles=articles, name=name)

@app.route('/about')
def about():
    return render_template('about.html')



@app.route('/add_post', methods=['GET', 'POST'])
@login_required
def add_post():
    form = AddPostForm()  # Use AddPostForm

    if form.validate_on_submit():  # Check if the form is submitted and valid
        user = current_user
        title = form.title.data
        content = form.content.data
        author = user.username

        # Handle file upload
        file = form.file.data
        if file and allowed_file(file.filename):
            image_filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], image_filename))
        else:
            flash("Invalid file type!", "danger")
            return redirect(request.url)

        # Create a new Article object
        new_article = Article(
            title=title,
            author=author,
            content=content,
            image_filename=image_filename,  # Save the filename to the database
            post_date=datetime.now()
        )

        # Add the new article to the database
        db.session.add(new_article)
        db.session.commit()

        flash("Post added successfully!", "success")
        return redirect(url_for('home'))

    # Render form if GET request or form invalid
    return render_template('add_post.html', form=form)

    


class UpdatePostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Update Post')

@app.route('/update/<int:id>', methods=['POST', 'GET'])
@login_required
def update(id):
    post = Article.query.get_or_404(id)
    
    # Ensure only the author can edit the post
    if post.author != current_user.username:
        flash("You can only edit your own posts!", "danger")
        return redirect(url_for('home'))

    form = UpdatePostForm()  # Instantiate the form

    if form.validate_on_submit():  # Check if the form is valid on submit
        post.title = form.title.data
        post.content = form.content.data
        db.session.commit()  # Save changes to the database
        flash("Post updated successfully!", "success")
        return redirect(url_for('home'))

    # Pre-populate the form fields with the existing post data
    form.title.data = post.title
    form.content.data = post.content
    
    return render_template('update.html', form=form, edit=post)



@app.route('/delete/<int:id>')
@login_required
def delete(id):
    post = Article.query.get_or_404(id)

    # Ensure only the author can delete the post
    if post.author != current_user.username:
        flash("You can only delete your own posts!", "danger")
        return redirect(url_for('home'))

    db.session.delete(post)
    db.session.commit()
    flash("Post deleted successfully!", "success")
    return redirect(url_for('home'))


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    form = LoginForm()  # Instantiate the form

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user, remember=form.remember.data)
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password.", "danger")
    
    return render_template("login.html", form=form)




@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        # Hash the password before storing it
        hashed_password = generate_password_hash(form.password.data)
        
        # Create a new User object
        new_user = User(username=form.username.data, password=hashed_password)
        
        # Add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        # Flash a success message and redirect to the login page
        flash(f'Account created for {form.username.data}! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)



# blog page
@app.route("/post/<int:article_id>")
def post(article_id):
    article = Article.query.get_or_404(article_id)
    return render_template("post.html", article=article)



@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

# dashboard for user
@app.route('/dashboard')
@login_required
def dashboard():
    user_posts = Article.query.filter_by(author=current_user.username).all()  # Fetch the user's posts
    return render_template('dashboard.html', user=current_user, posts=user_posts)



# Create tables
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=True)
