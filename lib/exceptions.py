__author__ = 'yoyosan'


class Error(Exception):
    """
    Base class for exceptions in this module.
    """
    pass


class SessionError(Error):
    """
    Exception raised when an user session expired.
    """
    pass
