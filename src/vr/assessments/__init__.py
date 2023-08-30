from flask import Blueprint

assessments = Blueprint('assessments', __name__)


from vr.assessments.web import benchmarks
