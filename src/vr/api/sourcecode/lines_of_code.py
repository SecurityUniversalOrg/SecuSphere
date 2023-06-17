from vr import db, app
from flask import request
from sqlalchemy import text
from vr.api import api
from vr.assets.model.businessapplications import BusinessApplications
from vr.sourcecode.model.appcodecomposition import AppCodeComposition


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

@api.route('/add_loc', methods=['POST'])
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
    app = BusinessApplications.query.filter(text(f"ApplicationName='{app_name}'")).first()
    application_id = app.ID
    new_entry = AppCodeComposition(ApplicationID=application_id, **language_stats)
    db.session.add(new_entry)
    db.session.commit()

    return {"status": "success"}, 200
