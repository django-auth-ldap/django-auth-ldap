import os
from unittest import TestCase


class TestLoading(TestCase):
    def test_django_not_ready(self):
        orig_env = os.environ.copy()

        def reset_env():
            os.environ = orig_env

        self.addCleanup(reset_env)

        os.environ["DJANGO_SETTINGS_MODULE"] = "tests.settings"

        import django_auth_ldap.backend  # noqa: F401
