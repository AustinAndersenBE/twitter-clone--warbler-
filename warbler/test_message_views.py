"""Message View tests."""

# run these tests like:
#
#    FLASK_ENV=production python -m unittest test_message_views.py


import os
from unittest import TestCase

from models import db, connect_db, Message, User

# BEFORE we import our app, let's set an environmental variable
# to use a different database for tests (we need to do this
# before we import our app, since that will have already
# connected to the database

os.environ['DATABASE_URL'] = "postgresql:///warbler-test"


# Now we can import app

from app import app, CURR_USER_KEY

# Create our tables (we do this here, so we only create the tables
# once for all tests --- in each test, we'll delete the data
# and create fresh new clean test data

db.create_all()

# Don't have WTForms use CSRF at all, since it's a pain to test

app.config['WTF_CSRF_ENABLED'] = False


class MessageViewTestCase(TestCase):
    """Test views for messages."""

    def setUp(self):
        """Create test client, add sample data."""

        User.query.delete()
        Message.query.delete()

        self.client = app.test_client()

        self.testuser = User.signup(username="testuser",
                                    email="test@test.com",
                                    password="testuser",
                                    image_url=None)

        db.session.commit()

    def test_add_message(self):
        """Can use add a message?"""

        # Since we need to change the session to mimic logging in,
        # we need to use the changing-session trick:

        with self.client as c:
            with c.session_transaction() as sess:
                sess[CURR_USER_KEY] = self.testuser.id

            # Now, that session setting is saved, so we can have
            # the rest of ours test

            resp = c.post("/messages/new", data={"text": "Hello"})

            # Make sure it redirects
            self.assertEqual(resp.status_code, 302)

            msg = Message.query.one()
            self.assertEqual(msg.text, "Hello")
    
    def test_add_message_not_logged_in(self):
        """Does app prevent a user from creating a message when not logged in?"""

        with self.client as c:
            resp = c.post("/messages/new", data={"text": "Hello"}, follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Access unauthorized", str(resp.data))

    def test_unauthorized_message_delete(self):
        """Does app prevent a user from deleting a message that they did not post?"""

        # Create another user
        user2 = User.signup(username="testuser2",
                            email="test2@test.com",
                            password="testuser2",
                            image_url=None)
        db.session.commit()

        # User2 posts a message
        msg = Message(text="Hello from user2", user_id=user2.id)
        db.session.add(msg)
        db.session.commit()

        msg_id = msg.id

        with self.client as c:
            with c.session_transaction() as sess:
                # Log in as testuser, not user2
                sess[CURR_USER_KEY] = self.testuser.id

            resp = c.post(f"/messages/{msg.id}/delete", follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Access unauthorized", str(resp.data))


            # Check that the message still exists
            msg = Message.query.get(msg_id)
            self.assertIsNotNone(msg)
            self.assertEqual(msg.text, "Hello from user2")
    
    def test_delete_message_logged_out(self):
        """Does app prevent a user from deleting a message when not logged in?"""

        # User posts a message
        msg = Message(text="Hello from testuser", user_id=self.testuser.id)
        db.session.add(msg)
        db.session.commit()

        msg_id = msg.id

        with self.client as c:
            resp = c.post(f"/messages/{msg.id}/delete", follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Access unauthorized", str(resp.data))

            # Check that the message still exists
            msg = Message.query.get(msg_id)
            self.assertIsNotNone(msg)
            self.assertEqual(msg.text, "Hello from testuser")
    
    def test_add_message_as_another_user(self):
        """Does app prevent a logged in user from adding a message as another user?"""

        # Create another user
        user2 = User.signup(username="testuser2",
                            email="test2@test.com",
                            password="testuser2",
                            image_url=None)
        
        user2_id = user2.id
        db.session.commit()

        with self.client as c:
            with c.session_transaction() as sess:
                # Log in as testuser, not user2
                sess[CURR_USER_KEY] = self.testuser.id

            resp = c.post("/messages/new", data={"text": "Hello", "user_id": user2_id})

            # Make sure it redirects
            self.assertEqual(resp.status_code, 302)

            msg = Message.query.one()
            self.assertEqual(msg.text, "Hello")
            # Make sure the message is posted by testuser, not user2
            self.assertEqual(msg.user_id, self.testuser.id)
            
    def test_unauthorized_message_delete(self):
        """Does app prevent a user from deleting a message that they did not post?"""

        # Create another user
        user2 = User.signup(username="testuser2",
                            email="test2@test.com",
                            password="testuser2",
                            image_url=None)
        db.session.commit()

        # User2 posts a message
        msg = Message(text="Hello from user2", user_id=user2.id)
        db.session.add(msg)
        db.session.commit()

        msg_id = msg.id

        with self.client as c:
            with c.session_transaction() as sess:
                # Log in as testuser, not user2
                sess[CURR_USER_KEY] = self.testuser.id

            resp = c.post(f"/messages/{msg.id}/delete", follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Access unauthorized", str(resp.data))

            # Check that the message still exists
            msg = Message.query.get(msg_id)
            self.assertIsNotNone(msg)
            self.assertEqual(msg.text, "Hello from user2")