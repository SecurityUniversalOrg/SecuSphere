from flask import Blueprint

api = Blueprint('api', __name__)

from vr.api.admin import api_oauth_flow

from vr.api.sourcecode import lines_of_code

from vr.api.vulns import security_quality_gate
from vr.api.vulns import vulnerabilities
from vr.api.vulns import jenkins_webhook
from vr.api.vulns import application_profiler
from vr.api.vulns import dora_extended

from vr.api.integrations import servicenow
