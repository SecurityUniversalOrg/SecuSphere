from vr import app
import random
import string
import datetime
import os
from vr.admin.oauth2 import config_oauth
from config_engine import ENV, INSECURE_OAUTH


if ENV == 'test' or INSECURE_OAUTH:
    os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '1'
else:
    os.environ['AUTHLIB_INSECURE_TRANSPORT'] = '0'
config_oauth(app)
STRING_LEN = 40
app.secret_key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(STRING_LEN))
app.permanent_session_lifetime = datetime.timedelta(minutes=100)
app.run(debug=True,host='0.0.0.0',port=5080, use_reloader=False)
