SECRET_KEY = "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"

INSTALLED_APPS = ("django.contrib.auth", "django.contrib.contenttypes", "tests")

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3"}}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTHENTICATION_BACKENDS = ["django_auth_ldap.backend.LDAPBackend"]


CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "default-cache",
    },
    "ldap": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "alternate-cache",
    },
}
