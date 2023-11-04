import os
from unittest import TestCase

from models import db, User, Message, Follows
from sqlalchemy.exc import IntegrityError
from flask_bcrypt import Bcrypt

os.environ['DATABASE_URL'] = "postgresql:///warbler-test"

from app import app

bcrypt = Bcrypt(app)

# Create our tables (we do this here, so we only create the tables
# once for all tests --- in each test, we'll delete the data
# and create fresh new clean test data

db.create_all()


class MessageModelTestCase(TestCase):
    """Test views for messages."""

    def setUp(self):
        """Create test client, add sample data."""

        User.query.delete()
        Message.query.delete()

        self.client = app.test_client()

    def tearDown(self):

        db.session.rollback()

    def test_message_create(self):
        """Does Message.create successfully create a new message given valid credentials?"""

        u = User.signup(
            email="test@test.com",
            username="testuser",
            password="HASHED_PASSWORD",
            image_url="http://example.com/image.jpg"
        )

        db.session.add(u)
        db.session.commit()

        msg = Message(text="Hello, World!", user_id=u.id)

        db.session.add(msg)
        db.session.commit()

        # Check if the message was successfully created
        m_test = Message.query.filter_by(text="Hello, World!").first()
        self.assertIsNotNone(m_test)

    def test_message_create_no_text(self):
        """Does Message.create fail to create a new message when no text is provided?"""

        u = User.signup(
            email="test@test.com",
            username="testuser",
            password="HASHED_PASSWORD",
            image_url="http://example.com/image.jpg"
        )

        db.session.add(u)
        db.session.commit()

        msg = Message(text=None, user_id=u.id)

        db.session.add(msg)
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_message_create_no_user_id(self):
        """Does Message.create fail to create a new message when no user_id is provided?"""

        msg = Message(text="Hello, World!", user_id=None)

        db.session.add(msg)
        with self.assertRaises(IntegrityError):
            db.session.commit()