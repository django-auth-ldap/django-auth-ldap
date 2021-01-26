try:
    from .version import version
except ImportError:
    __version__ = None
else:
    __version__ = version
