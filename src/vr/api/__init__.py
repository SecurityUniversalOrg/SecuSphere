from flask import Blueprint

api = Blueprint('api', __name__)

from vr.api.admin import api_oauth_flow

from vr.api.sourcecode import lines_of_code

from vr.api.vulns import security_quality_gate
from vr.api.vulns import vulnerabilities
