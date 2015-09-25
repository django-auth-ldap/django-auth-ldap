# For older versions of Djano
DATABASE_ENGINE = 'sqlite3'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}

ALLOWED_HOSTS = []

TIME_ZONE = 'UTC'
LANGUAGE_CODE = 'en-us'
USE_I18N = False
USE_L10N = False
USE_TZ = True

SECRET_KEY = 'nt56v8)moa)37ta5z7dd=if-@y#k@l7+t8lct*c8m730lpd=so'

ROOT_URLCONF = 'urls'

INSTALLED_APPS = (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',

    'django_auth_ldap',
)

MIDDLEWARE_CLASSES = []

AUTH_USER_MODEL = 'auth.User'
