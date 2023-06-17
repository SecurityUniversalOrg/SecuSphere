from flask import Blueprint

orchestration = Blueprint('orchestration', __name__)


from vr.orchestration.web import dockerimages

