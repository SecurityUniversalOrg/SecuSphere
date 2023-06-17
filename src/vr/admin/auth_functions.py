import jwt
from time import time
from vr.functions.mysql_db import connect_to_db


# Error handler
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


def get_token_auth_header(request):
    """Obtains the access token from the Authorization Header
    """
    auth = request.headers.get("Authorization", None)
    try:
        if not auth:
            raise AuthError({"code": "authorization_header_missing",
                            "description":
                                "Authorization header is expected"}, 401)

        parts = auth.split()

        if parts[0].lower() != "bearer":
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Authorization header must start with"
                                " Bearer"}, 401)
        elif len(parts) == 1:
            raise AuthError({"code": "invalid_header",
                            "description": "Token not found"}, 401)
        elif len(parts) > 2:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Authorization header must be"
                                " Bearer token"}, 401)

        token = parts[1]
    except RuntimeError:
        token = ''
    return token

def create_api_key(user_id, otp_secret, expires_in=2592000):
    api_key = jwt.encode({'user_id': user_id, 'otp_secret': otp_secret, 'exp': time() + expires_in}, otp_secret, algorithm='HS256')
    return api_key

def verify_api_key(token):
    try:
        cur, db = connect_to_db()
        sql = 'SELECT oc.user_id, u.is_admin FROM oauth2_client oc JOIN oauth2_token ot ON oc.client_id=ot.client_id JOIN User u ON oc.user_id=u.id WHERE ot.id=%s'
        args = (token.id,)
        cur.execute(sql, args)
        row = cur.fetchone()
        if row:
            user_id = row[0]
            is_admin = row[1]
            return 'valid', user_id, is_admin
        else:
            return '', '', ''
    except RuntimeError:
        return '', '', ''