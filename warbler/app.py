import os

from flask import Flask, render_template, request, flash, redirect, session, g, url_for
from flask_debugtoolbar import DebugToolbarExtension
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import joinedload
from functools import wraps

from forms import UserAddForm, LoginForm, MessageForm, EditProfileForm, ConfirmPasswordForm
from models import db, connect_db, User, Message, Likes, Follows

CURR_USER_KEY = "curr_user"

app = Flask(__name__)

# Get DB_URI from environ variable (useful for production/testing) or,
# if not set there, use development local db.
app.config['SQLALCHEMY_DATABASE_URI'] = (
    os.environ.get('DATABASE_URL', 'postgresql:///warbler'))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ECHO'] = False
app.config['DEBUG_TB_INTERCEPT_REDIRECTS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', "it's a secret")
app.config['TESTING'] = False

connect_db(app)


##############################################################################
# User signup/login/logout


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash("Access unauthorized.", "danger")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def add_user_to_g():
    """If we're logged in, add curr user to Flask global."""

    if CURR_USER_KEY in session:
        g.user = User.query.get(session[CURR_USER_KEY])

    else:
        g.user = None


def do_login(user):
    """Log in user."""

    session[CURR_USER_KEY] = user.id


def do_logout():
    """Logout user."""

    if CURR_USER_KEY in session:
        del session[CURR_USER_KEY]


@app.route('/signup', methods=["GET", "POST"])
def signup():
    """Handle user signup.

    Create new user and add to DB. Redirect to home page.

    If form not valid, present form.

    If the there already is a user with that username: flash message
    and re-present form.
    """

    form = UserAddForm()

    if form.validate_on_submit():
        try:
            user = User.signup(
                username=form.username.data,
                password=form.password.data,
                email=form.email.data,
                image_url=form.image_url.data or User.image_url.default.arg,
            )
            db.session.commit()

        except IntegrityError:
            flash("Username already taken", 'danger')
            return render_template('users/signup.html', form=form)

        do_login(user)

        return redirect("/")

    else:
        return render_template('users/signup.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    """Handle user login."""

    form = LoginForm()

    if form.validate_on_submit():
        user = User.authenticate(form.username.data,
                                 form.password.data)

        if user:
            do_login(user)
            flash(f"Hello, {user.username}!", "success")
            return redirect("/")

        flash("Invalid credentials.", 'danger')

    return render_template('users/login.html', form=form)

#me: implement logout route
@app.route('/logout')
def logout():
    do_logout()
    flash("You have successfully logged out.", "success")
    return redirect("/")


##############################################################################
# General user routes:

@app.route('/users')
def list_users():
    """Page with listing of users.

    Can take a 'q' param in querystring to search by that username.
    """

    search = request.args.get('q')

    if not search:
        users = User.query.all()
    else:
        users = User.query.filter(User.username.like(f"%{search}%")).all()

    return render_template('users/index.html', users=users)

#Shows user profile


@app.route('/users/<int:user_id>')
@login_required
def users_show(user_id):
    user = User.query.get_or_404(user_id)
    messages = (Message
                .query
                .filter_by(user_id=user_id)
                .order_by(Message.timestamp.desc())
                .limit(100)
                .all())
    likes_count = Likes.query.filter_by(user_id = user_id).count()
    return render_template('users/show.html', user=user, messages=messages, likes_count=likes_count)

#Shows liked messages for current user

@app.route('/users/<int:user_id>/likes')
@login_required
def users_likes(user_id):
    user = User.query.options(joinedload('likes')).get_or_404(user_id) #joinedload to prevent N+1 queries
    likes = user.likes  # Get the liked messages by the user
    likes_count = Likes.query.filter_by(user_id=user_id).count()
    return render_template('users/likes.html', user=user, likes=likes, likes_count=likes_count)


@app.route('/users/<int:user_id>/following')
@login_required
def show_following(user_id):
    """Show list of people this user is following."""
    user = User.query.options(joinedload('likes')).get_or_404(user_id)
    likes_count = Likes.query.filter_by(user_id=user_id).count()
    return render_template('users/following.html', user=user, likes_count=likes_count)

@app.route('/users/<int:user_id>/followers')
@login_required
def users_followers(user_id):
    """Show list of followers of this user."""
    user = User.query.options(joinedload('likes')).get_or_404(user_id)
    likes_count = Likes.query.filter_by(user_id=user_id).count()
    return render_template('users/followers.html', user=user, likes_count=likes_count)

@app.route('/users/follow/<int:follow_id>', methods=['POST'])
@login_required
def add_follow(follow_id):
    """Add a follow for the currently-logged-in user."""
    followed_user = User.query.get_or_404(follow_id)
    g.user.following.append(followed_user)
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")


@app.route('/users/stop-following/<int:follow_id>', methods=['POST'])
@login_required
def stop_following(follow_id):
    """Have currently-logged-in-user stop following this user."""
    followed_user = User.query.get(follow_id)
    g.user.following.remove(followed_user)
    db.session.commit()

    return redirect(f"/users/{g.user.id}/following")

# Add like for current user. The button for this is in home.html
# If user has already liked message, remove like
@app.route('/users/add_like/<int:message_id>', methods=['POST'])
@login_required
def add_like(message_id):
    
    liked_message = Message.query.get_or_404(message_id) 
    like = Likes.query.filter_by(user_id=g.user.id, message_id=liked_message.id).first() #check if user has already liked message

    if like:
        db.session.delete(like)
    else:
        db.session.add(Likes(user_id=g.user.id, message_id=liked_message.id))

    db.session.commit()

    return redirect("/")

#Update profile for current user
@app.route('/users/profile', methods=["GET", "POST"])
@login_required
def profile():

    form = EditProfileForm(obj=g.user) #populate form with current user info
    confirm_form = ConfirmPasswordForm()

    if form.validate_on_submit() and confirm_form.validate_on_submit():
        # Check if password is correct
        if User.authenticate(g.user.username, confirm_form.password.data):
            g.user.username = form.username.data
            g.user.email = form.email.data
            g.user.image_url = form.image_url.data or g.user.image_url #if no image_url, use current image_url
            g.user.header_image_url = form.header_image_url.data or g.user.header_image_url
            g.user.bio = form.bio.data
            db.session.commit()

            return redirect(f"/users/{g.user.id}")
        else:
            flash("Invalid password, please try again.", "danger")
            return redirect("/users/profile")
    
    return render_template("users/edit.html", form=form, confirm_form=confirm_form)

   

@app.route('/users/delete', methods=["POST"])
@login_required
def delete_user():
    """Delete user."""

    user_to_delete = g.user

    db.session.delete(user_to_delete)
    db.session.commit()

    do_logout()

    return redirect("/signup")


##############################################################################
# Messages routes:

@app.route('/messages/new', methods=["GET", "POST"])
@login_required
def messages_add():
    """Add a message:

    Show form if GET. If valid, update message and redirect to user page.
    """
    form = MessageForm()

    if form.validate_on_submit():
        msg = Message(text=form.text.data)
        g.user.messages.append(msg)
        db.session.commit()

        return redirect(f"/users/{g.user.id}")

    return render_template('messages/new.html', form=form)


@app.route('/messages/<int:message_id>', methods=["GET"])
def messages_show(message_id):
    """Show a message."""

    msg = Message.query.get(message_id)
    return render_template('messages/show.html', message=msg)

@app.route('/messages/<int:message_id>/delete', methods=["POST"])
@login_required
def messages_destroy(message_id):
    """Delete a message."""

    msg = Message.query.get(message_id)

    if msg.user_id != g.user.id:
        flash("Access unauthorized.", "danger")
        return redirect("/")
    
    db.session.delete(msg)
    db.session.commit()

    return redirect(f"/users/{g.user.id}")


##############################################################################
# Homepage and error pages


# Returns:
#   - If user is logged in: list of message objects, set of message ids that user has liked

@app.route('/')
def homepage():

    if g.user:
        followed_users_ids = [u.id for u in g.user.following] #list of ids of followings
        followed_users_ids.append(g.user.id)
        messages = (Message
                    .query
                    .options(joinedload('user')) #eager load user
                    .filter(Message.user_id.in_(followed_users_ids)) #filter by followings
                    .order_by(Message.timestamp.desc())
                    .limit(100) #100 most recent messages of followings
                    .all()
                    )
        likes = {like.message_id for like in Likes.query.filter_by(user_id=g.user.id)} #set is O(1), we only need to check if an element exists
        return render_template('home.html', messages=messages, likes=likes)
    else:
        return render_template('home-anon.html')


##############################################################################
# Turn off all caching in Flask
#   (useful for dev; in production, this kind of stuff is typically
#   handled elsewhere)
#
# https://stackoverflow.com/questions/34066804/disabling-caching-in-flask

@app.after_request
def add_header(req):
    """Add non-caching headers on every request."""

    req.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    req.headers["Pragma"] = "no-cache"
    req.headers["Expires"] = "0"
    req.headers['Cache-Control'] = 'public, max-age=0'
    return req
