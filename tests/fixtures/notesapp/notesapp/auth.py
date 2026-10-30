import hmac

from .storage import USERS


class AuthError(Exception):
    pass


def current_user(request):
    """Resolve the caller from the bearer token. Raises AuthError if absent or invalid."""
    header = request.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        raise AuthError("missing token")
    token = header[len("Bearer "):]
    for user in USERS.values():
        if hmac.compare_digest(user["token"], token):
            return user
    raise AuthError("invalid token")


def require_owner(user, note):
    if note["owner"] != user["id"]:
        raise AuthError("forbidden")
