#!/usr/bin/python3

import logging
import sys
import random
import string
import datetime


logging.basicConfig(stream=sys.stderr)
sys.path.insert(0, '/var/www/html/src')

from vr import app as application
from vr.admin.oauth2 import config_oauth
config_oauth(application)
STRING_LEN = 40
application.secret_key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(STRING_LEN))
application.permanent_session_lifetime = datetime.timedelta(minutes=100)
