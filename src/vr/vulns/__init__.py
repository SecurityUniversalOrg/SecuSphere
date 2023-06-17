from flask import Blueprint

vulns = Blueprint('vulns', __name__)


from vr.vulns.web import dashboard
from vr.vulns.web import pipeline_jobs
from vr.vulns.web import cicd_pipelines
from vr.vulns.web import integrations
from vr.vulns.web import vulnerabilities
from vr.vulns.web import applications
from vr.vulns.web import regulations
from vr.vulns.web import support_groups
from vr.vulns.web import metrics
from vr.vulns.web import testing
from vr.vulns.web import findings
from vr.vulns.web import benchmarks
from vr.vulns.web import settings
from vr.vulns.web import infrastructure
from vr.vulns.web import devopsscorecard
from vr.vulns.web import securitygatescorecard

