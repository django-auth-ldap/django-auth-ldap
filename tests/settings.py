SECRET_KEY = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

INSTALLED_APPS = ("django.contrib.auth", "django.contrib.contenttypes", "tests")

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3"}}

AUTHENTICATION_BACKENDS = ["django_auth_ldap.backend.LDAPBackend"]
