try:
    from django.conf.defaults import patterns
except ImportError:
    patterns = list


urlpatterns = patterns('')
