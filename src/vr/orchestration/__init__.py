from flask import Blueprint

orchestration = Blueprint('orchestration', __name__)


from vr.orchestration.web import dockerimages
from vr.orchestration.web import cicd_pipelines
from vr.orchestration.web import pipeline_jobs
