from functools import wraps
from flask import render_template, session


def requires_role(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Assuming user_roles is stored in the session
            user_roles = session.get('roles', [])
            if required_role not in user_roles:
                # Redirect to an unauthorized page if the user doesn't have the required role
                return render_template('403.html', user="", NAV="")
            return f(*args, **kwargs)
        return decorated_function
    return decorator