import os
from unittest import TestCase

from models import db, connect_db, Message, User


os.environ['DATABASE_URL'] = "postgresql:///warbler-test"

from app import app, CURR_USER_KEY

db.create_all()

app.config['WTF_CSRF_ENABLED'] = False

class UserViewTestCase(TestCase):
    """Test views for users."""

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

    def test_show_following_logged_in(self):
        """When logged in, can user see the following pages for any user?"""

        # Login as test user
        with self.client as c:
            with c.session_transaction() as sess:
                sess[CURR_USER_KEY] = self.testuser.id

            # Make a request to the following page for the user
            resp = c.get(f"/users/{self.testuser.id}/following")

            # The response should have a status of 200 (OK)
            self.assertEqual(resp.status_code, 200)

    def test_show_following_logged_out(self):
        """Are you disallowed from visiting a user's following pages when logged out?"""

        with self.client as c:
            resp = c.get(f"/users/{self.testuser.id}/following", follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Access unauthorized", str(resp.data))

    def test_show_followers_logged_in(self):
        """When logged in, can user see the followers pages for any user?"""

        # Login as test user
        with self.client as c:
            with c.session_transaction() as sess:
                sess[CURR_USER_KEY] = self.testuser.id

            # Make a request to the followers page for the user
            resp = c.get(f"/users/{self.testuser.id}/followers")

            # The response should have a status of 200 (OK)
            self.assertEqual(resp.status_code, 200)

    def test_show_followers_logged_out(self):
        """Are you disallowed from visiting a user's followers pages when logged out?"""

        with self.client as c:
            resp = c.get(f"/users/{self.testuser.id}/followers", follow_redirects=True)
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Access unauthorized", str(resp.data))