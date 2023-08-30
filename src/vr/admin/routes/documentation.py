from flask import render_template
# Start of Entity-specific Imports
from vr.admin import admin


@admin.route("/api/documentation")
def api_documentation():
    try:
        return render_template('api/api_documentation.html')
    except RuntimeError:
        return render_template('500.html'), 500
