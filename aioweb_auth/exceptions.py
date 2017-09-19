class AuthError(Exception):
    pass


class UserNotFoundError(AuthError):
    pass


class PasswordDoesNotMatchError(AuthError):
    pass
