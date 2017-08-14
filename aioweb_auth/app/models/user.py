from orator.orm import has_many, belongs_to_many

from aioweb.core.model import OratorModel, mutator, accessor, Model
from passlib.handlers.sha2_crypt import sha256_crypt
from ..models import permission
from ..models import group


class AbstractUser(object):

    def is_authenticated(self):
        return False

    def get_id(self):
        return None


class AuthenticatedUser(AbstractUser, Model):

    __fields__ = ['password', 'email', 'phone']

    def __init__(self, user_id, **kwargs):
        self.id = user_id

        for field in self.__fields__:
            setattr(self, field, None)

        for arg, val in kwargs.items():
            if arg in self.__fields__:
                # if arg == 'password':
                #     setattr(self, arg, AuthenticatedUser.hash_password(val))
                #     continue
                setattr(self, arg, val)

    @staticmethod
    def hash_password(value):
        # TODO: configurable hash type
        return sha256_crypt.hash(value)

    def username(self):
        return self.phone if self.phone else self.email

    def __str__(self):
        return self.username

    def is_authenticated(self):
        return True

    def get_id(self):
        return self.id


class User(OratorModel, AbstractUser):

    __guarded__ = ['id']
    __hidden__ = ['password']

    def __init__(self, _attributes=None, **attributes):
        if 'password' in attributes:
            if attributes['password']:
                attributes['password'] = User.hash_password(attributes['password'])
            else:
                attributes['password'] = None
        super().__init__(_attributes, **attributes)

    async def get_by_username(self, username):
        return self.where('email', username).or_where('phone', username).first_or_fail()

    async def get_by_id(self, id):
        return self.where('id', id).first_or_fail()

    def get_id(self):
        return self.id

    @staticmethod
    def hash_password(value):
        # TODO: configurable hash type
        return sha256_crypt.hash(value)

    @mutator
    def password(self, value):
        if value:
            self.set_raw_attribute('password', User.hash_password(value))
        else:
            self.set_raw_attribute('password', None)

    def can(self, permission):
        # TODO: check it
        return self.permissions.has(permission).get()  # or self.groups.perimissions.has(permission).get()

    @belongs_to_many('user_permissions')
    def permissions(self):
        return permission.Permission

    @belongs_to_many('user_groups')
    def groups(self):
        return group.Group

    @accessor
    def username(self):
        return self.phone if self.phone else self.email

    def __str__(self):
        return self.username
