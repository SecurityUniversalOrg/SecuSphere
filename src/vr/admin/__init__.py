from flask import Blueprint


admin = Blueprint('admin', __name__)


from vr.admin.routes import api_register
from vr.admin.routes import login
from vr.admin.routes import logout
from vr.admin.routes import register
from vr.admin.routes import unauth_403
from vr.admin.routes import forgotpw
from vr.admin.routes import forgotun
from vr.admin.routes import users
from vr.admin.routes import onboarding
from vr.admin.routes import messages
from vr.admin.routes import documentation
from vr.admin.routes import settings

from vr.admin.routes.userprofile import edit_profile
from vr.admin.routes.userprofile import profile

