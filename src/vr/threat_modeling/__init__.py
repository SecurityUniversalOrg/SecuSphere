from flask import Blueprint

threat_modeling = Blueprint('threat_modeling', __name__)

from vr.threat_modeling.routes import threat_modeler
