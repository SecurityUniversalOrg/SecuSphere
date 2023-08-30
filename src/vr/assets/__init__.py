from flask import Blueprint

assets = Blueprint('assets', __name__)


from vr.assets.web import applications
from vr.assets.web import infrastructure
from vr.assets.web import integrations
from vr.assets.web import regulations
from vr.assets.web import settings
from vr.assets.web import support_groups
