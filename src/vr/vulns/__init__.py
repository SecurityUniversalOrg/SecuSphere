from flask import Blueprint

vulns = Blueprint('vulns', __name__)


from vr.vulns.web import dashboard
from vr.vulns.web import devopsscorecard
from vr.vulns.web import findings
from vr.vulns.web import metrics
from vr.vulns.web import securitygatescorecard
from vr.vulns.web import testing
from vr.vulns.web import visual_pipeline
from vr.vulns.web import vulnerabilities
