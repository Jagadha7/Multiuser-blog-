from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, User, Post, Comment
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import hashlib
from collections import Counter
from flask import abort


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Setup LoginManager
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

# Load user callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Initialize DB
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    posts = Post.query.order_by(Post.id.desc()).all()

    return render_template('home.html', posts=posts)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please log in.')
            return redirect(url_for('login'))

        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'info')
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    posts = Post.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', user=current_user, posts=posts)

@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_post():
    if request.method == 'POST':
        title = request.form['title']
        category = request.form.get('category')
        content = request.form['content']
        post = Post(title=title, category=category, content=content, author=current_user)
        db.session.add(post)
        db.session.commit()
        flash('Post created!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('create_post.html')


@app.route('/edit/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    if request.method == 'POST':
        post.title = request.form['title']
        post.category = request.form.get('category')
        post.content = request.form['content']
        db.session.commit()
        flash('Post updated successfully!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('edit_post.html', post=post)


@app.route('/delete/<int:post_id>')
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.user_id != current_user.id:
        flash('Unauthorized', 'error')
        return redirect(url_for('dashboard'))
    db.session.delete(post)
    db.session.commit()
    flash('Post deleted!', 'info')
    return redirect(url_for('dashboard'))

@app.route('/post/<int:post_id>', methods=['GET', 'POST'])
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    author = User.query.get(post.user_id)

    if request.method == 'POST':
        if not current_user.is_authenticated:
            flash('You must be logged in to comment.', 'error')
            return redirect(url_for('login'))
        content = request.form['content']
        comment = Comment(content=content, user_id=current_user.id, post_id=post.id)
        db.session.add(comment)
        db.session.commit()
        flash('Comment added!', 'success')
        return redirect(url_for('view_post', post_id=post.id))

    comments = Comment.query.filter_by(post_id=post.id).order_by(Comment.created_at.desc()).all()
    return render_template('view_post.html', post=post, author=author, comments=comments)

@app.template_filter('gravatar')
def gravatar(email, size=200):
    hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{hash}?s={size}&d=identicon"

@app.route('/report')
@login_required
def report():
    # Dummy data (replace with actual analysis)
    user_posts = Post.query.filter_by(user_id=current_user.id).all()
    total_posts = len(user_posts)

    # Example: Count posts per category
    category_count = {}
    for post in user_posts:
        category = post.category or 'Uncategorized'
        category_count[category] = category_count.get(category, 0) + 1

    return render_template('report.html', total_posts=total_posts, category_count=category_count)

if __name__ == '__main__':
    app.run(debug=True)
