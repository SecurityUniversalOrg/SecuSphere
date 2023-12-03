from vr import db, app
from flask import request
from vr.api import api
from vr.sourcecode.model.appcodecomposition import AppCodeComposition
from vr.admin.functions import db_connection_handler
from vr.api.vulns.vulnerabilities import get_app_id
from vr.admin.oauth2 import require_oauth


EXTENSION_LANGUAGE_MAP = {
    "js": "JavaScript",
    "py": "Python",
    "java": "Java",
    "cs": "C-Sharp",
    "cpp": "C Plus Plus",
    "cxx": "C Plus Plus",
    "cc": "C Plus Plus",
    "c++": "C Plus Plus",
    "php": "PHP",
    "ts": "TypeScript",
    "swift": "Swift",
    "rb": "Ruby",
    "c": "C",
    "kt": "Kotlin",
    "kts": "Kotlin",
    "go": "Go",
    "dart": "Dart",
    "scala": "Scala",
    "sh": "Shell",
    "bash": "Shell",
    "r": "R",
    "lua": "Lua",
    "groovy": "Groovy",
    "pl": "Perl",
    "pm": "Perl",
    "rs": "Rust",
    "m": "MATLAB",
    "jl": "Julia",
    "f": "Fortran",
    "f90": "Fortran",
    "f95": "Fortran",
    "f03": "Fortran",
    "f08": "Fortran",
    "m": "Objective-C",
    "h": "Objective-C",
    "ex": "Elixir",
    "exs": "Elixir",
    "hs": "Haskell",
    "lhs": "Haskell",
    "elm": "Elm",
    "fs": "F-Sharp",
    "fsx": "F-Sharp",
    "fsi": "F-Sharp",
    "clj": "Clojure",
    "cljs": "Clojure",
    "cljc": "Clojure",
    "cob": "COBOL",
    "cbl": "COBOL",
    "cpy": "COBOL"
}

@api.route('/api/add_loc', methods=['POST'])
@require_oauth('write:vulnerabilities')
def add_loc():
    form = request.get_json()
    loc_data = form['data']
    language_stats = {}

    for item in loc_data:
        loc = item['loc']
        files = item['fileCount']
        extension = item['language']

        if extension in EXTENSION_LANGUAGE_MAP:
            language = EXTENSION_LANGUAGE_MAP[extension]
            if f"{language}Files" not in language_stats:
                language_stats[f"{language}Files"] = 0
            if f"{language}Loc" not in language_stats:
                language_stats[f"{language}Loc"] = 0
            language_stats[f"{language}Files"] += files
            language_stats[f"{language}Loc"] += loc

    app_name = form['appName']
    git_branch = form['gitBranch']
    application_id = get_app_id(app_name, None)
    new_entry = AppCodeComposition(ApplicationID=application_id, BranchName=git_branch, **language_stats)
    db.session.add(new_entry)
    db_connection_handler(db)

    return {"status": "success"}, 200
