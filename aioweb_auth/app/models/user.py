class AbstractUser(object):

    @property
    def id(self):
        return None

    @property
    def is_authenticated(self):
        return False

    def __getattr__(self, item):
        return None
