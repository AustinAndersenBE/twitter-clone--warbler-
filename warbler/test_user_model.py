"""User model tests."""

# run these tests like:
#
#    python -m unittest test_user_model.py


import os
from unittest import TestCase

from models import db, User, Message, Follows
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt



# BEFORE we import our app, let's set an environmental variable
# to use a different database for tests (we need to do this
# before we import our app, since that will have already
# connected to the database

os.environ['DATABASE_URL'] = "postgresql:///warbler-test"


# Now we can import app

from app import app

bcrypt = Bcrypt(app)

# Create our tables (we do this here, so we only create the tables
# once for all tests --- in each test, we'll delete the data
# and create fresh new clean test data

db.create_all()


class UserModelTestCase(TestCase):
    """Test views for messages."""

    def setUp(self):
        """Create test client, add sample data."""

        try:
            User.query.delete()
            Message.query.delete()
            Follows.query.delete()

            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

        self.client = app.test_client()
    
    def tearDown(self):
        """Clean up any fouled transaction."""

        db.session.rollback()

    def test_user_model(self):
        """Does basic model work?"""

        u = User.signup(
        email="test@test.com",
        username="testuser",
        password="HASHED_PASSWORD",
        image_url="http://example.com/image.jpg"
        )

        db.session.add(u)
        db.session.commit()

        # User should have no messages & no followers
        self.assertEqual(len(u.messages), 0)
        self.assertEqual(len(u.followers), 0)
    
    def test_user_repr(self):

        u = User(
            email="test@test.com",
            username="testuser",
            password="HASHED_PASSWORD"
        )

        db.session.add(u)
        db.session.commit()

        # Check if the repr method returns the expected result
        self.assertEqual(repr(u), f"<User #{u.id}: {u.username}, {u.email}>")

    def test_is_following(self):

        u1 = User(
            email="test1@test.com",
            username="testuser1",
            password="HASHED_PASSWORD"
        )

        u2 = User(
            email="test2@test.com",
            username="testuser2",
            password="HASHED_PASSWORD"
        )

        db.session.add_all([u1, u2])
        db.session.commit()

        # User 1 follows User 2
        u1.following.append(u2)
        db.session.commit()

        # Check if is_following method returns True when u1 is following u2
        self.assertTrue(u1.is_following(u2))

        # Check if is_following method returns False when u1 is not following u2
        u1.following.remove(u2)
        db.session.commit()
        self.assertFalse(u1.is_following(u2))
    
    def test_is_followed_by(self):
        """Does is_followed_by successfully detect when user1 is followed by user2?"""

        u1 = User(
            email="test1@test.com",
            username="testuser1",
            password="HASHED_PASSWORD"
        )

        u2 = User(
            email="test2@test.com",
            username="testuser2",
            password="HASHED_PASSWORD"
        )

        db.session.add_all([u1, u2])
        db.session.commit()

        # User 2 follows User 1
        u2.following.append(u1)
        db.session.commit()

        # Check if is_followed_by method returns True when u1 is followed by u2
        self.assertTrue(u1.is_followed_by(u2))

        # Check if is_followed_by method returns False when u1 is not followed by u2
        u2.following.remove(u1)
        db.session.commit()
        self.assertFalse(u1.is_followed_by(u2))

    def test_user_create(self):
        """Does User.create successfully create a new user given valid credentials?"""

        u = User.signup(
        email="test@test.com",
        username="testuser",
        password="HASHED_PASSWORD",
        image_url="http://example.com/image.jpg"
        )

        db.session.add(u)
        db.session.commit()

        # Check if the user was successfully created
        u_test = User.query.filter_by(username="testuser").first()
        self.assertIsNotNone(u_test)

    def test_user_create_fail(self):
        """Does User.create fail to create a new user if any of the validations (e.g. uniqueness, non-nullable fields) fail?"""

        u1 = User.signup(
        email="test@test.com",
        username="testuser",
        password="HASHED_PASSWORD",
        image_url="http://example.com/image.jpg"
        )

        db.session.add(u1)
        db.session.commit()

        # Try to create a user with the same username
        u2 = User.signup(
        email="test@test.com",
        username="testuser",
        password="HASHED_PASSWORD",
        image_url="http://example.com/image.jpg"
        )

        with self.assertRaises(IntegrityError):
            db.session.add(u2)
            db.session.commit()

    def test_user_authenticate(self):
        """Does User.authenticate successfully return a user when given a valid username and password?"""

        u = User.signup(
        email="test@test.com",
        username="testuser",
        password="HASHED_PASSWORD",
        image_url="http://example.com/image.jpg"
        )

        db.session.add(u)
        db.session.commit()

        # Check if authenticate method returns the user when given a valid username and password
        auth_user = User.authenticate("testuser", "HASHED_PASSWORD")
        self.assertEqual(u, auth_user)

    def test_user_authenticate_invalid_username(self):
        """Does User.authenticate fail to return a user when the username is invalid?"""

        u = User.signup(
        email="test@test.com",
        username="testuser",
        password="HASHED_PASSWORD",
        image_url="http://example.com/image.jpg"
        )

        db.session.add(u)
        db.session.commit()

        # Check if authenticate method fails when the username is invalid
        auth_user = User.authenticate("invalidusername", "HASHED_PASSWORD")
        self.assertFalse(auth_user)

    def test_user_authenticate_invalid_password(self):
        """Does User.authenticate fail to return a user when the password is invalid?"""

        u = User.signup(
        email="test@test.com",
        username="testuser",
        password="HASHED_PASSWORD",
        image_url="http://example.com/image.jpg"
        )

        db.session.add(u)
        db.session.commit()

        # Check if authenticate method fails when the password is invalid
        auth_user = User.authenticate("testuser", "invalidpassword")
        self.assertFalse(auth_user)