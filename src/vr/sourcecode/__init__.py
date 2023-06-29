from flask import Blueprint

sourcecode = Blueprint('sourcecode', __name__)

from vr.sourcecode.web import git_repos
from vr.sourcecode.web import service_tickets
from vr.sourcecode.web import imported_code
from vr.sourcecode.web import branches
from vr.sourcecode.web import cheat_sheets
from vr.sourcecode.web import sourcecode_files
