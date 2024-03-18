import mysql.connector
import sqlite3
import os


def get_client(app):
    if app.config['RUNTIME_ENV'] == 'test':
        cur_path = os.getcwd()
        if 'www' in cur_path and 'html' in cur_path:
            db_uri = '/var/www/html/src/instance/database.db'
        else:
            db_uri = 'instance/database.db'
        db = sqlite3.connect(db_uri)
        cur = db.cursor()
        return cur, db
    else:
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        main_part = db_uri.split('://')[1]
        un = main_part.split(':', 1)[0]
        db_name = main_part.rsplit('/', 1)[1]
        host_and_port = main_part.rsplit('@', 1)[1].replace(f"/{db_name}", '')
        host = host_and_port.split(':')[0]
        port = int(host_and_port.split(':')[1])
        pw = main_part.split(':', 1)[1].replace(f"@{host}", '').replace(f"/{db_name}", '').replace(f":{port}", "")
        db = mysql.connector.connect(host=host, database=db_name, user=un, password=pw, port=port)
        cur = db.cursor()
        return cur, db


def createNewTables(app):
    cur, db = get_client(app)
    if app.config['RUNTIME_ENV'] == 'test':
        sql = "PRAGMA table_info('AppConfig')"
    else:
        sql = "SELECT column_name FROM information_schema.columns WHERE table_schema = 'vulnremediator' AND table_name = 'AppConfig'"
    cur.execute(sql)
    rows = cur.fetchall()
    fields = []
    for i in rows:
        if app.config['RUNTIME_ENV'] == 'test':
            fields.append(i[1])
        else:
            fields.append(i[0])
    new_fields = [
        {"name": "APP_EXT_URL", "type": "VARCHAR", "char_num": 200},
        {"name": "AUTH_TYPE", "type": "VARCHAR", "char_num": 200},
        {"name": "AZAD_AUTHORITY", "type": "VARCHAR", "char_num": 200},
        {"name": "AZAD_CLIENT_ID", "type": "VARCHAR", "char_num": 200},
        {"name": "AZAD_CLIENT_SECRET", "type": "VARCHAR", "char_num": 200},
        {"name": "AZURE_KEYVAULT_NAME", "type": "VARCHAR", "char_num": 200},
        {"name": "ENV", "type": "VARCHAR", "char_num": 200},
        {"name": "INSECURE_OAUTH", "type": "VARCHAR", "char_num": 200},
        {"name": "JENKINS_HOST", "type": "VARCHAR", "char_num": 200},
        {"name": "JENKINS_KEY", "type": "VARCHAR", "char_num": 200},
        {"name": "JENKINS_PROJECT", "type": "VARCHAR", "char_num": 200},
        {"name": "JENKINS_STAGING_PROJECT", "type": "VARCHAR", "char_num": 200},
        {"name": "JENKINS_TOKEN", "type": "VARCHAR", "char_num": 200},
        {"name": "JENKINS_USER", "type": "VARCHAR", "char_num": 200},
        {"name": "LDAP_BASE_DN", "type": "VARCHAR", "char_num": 200},
        {"name": "LDAP_BIND_USER_DN", "type": "VARCHAR", "char_num": 200},
        {"name": "LDAP_BIND_USER_PASSWORD", "type": "VARCHAR", "char_num": 200},
        {"name": "LDAP_GROUP_DN", "type": "VARCHAR", "char_num": 200},
        {"name": "LDAP_HOST", "type": "VARCHAR", "char_num": 200},
        {"name": "LDAP_PORT", "type": "VARCHAR", "char_num": 200},
        {"name": "LDAP_USER_DN", "type": "VARCHAR", "char_num": 200},
        {"name": "LDAP_USER_LOGIN_ATTR", "type": "VARCHAR", "char_num": 200},
        {"name": "LDAP_USER_RDN_ATTR", "type": "VARCHAR", "char_num": 200},
        {"name": "PROD_DB_URI", "type": "VARCHAR", "char_num": 200},
        {"name": "SMTP_ADMIN_EMAIL", "type": "VARCHAR", "char_num": 200},
        {"name": "SMTP_HOST", "type": "VARCHAR", "char_num": 200},
        {"name": "SMTP_PASSWORD", "type": "VARCHAR", "char_num": 200},
        {"name": "SMTP_USER", "type": "VARCHAR", "char_num": 200},
        {"name": "SNOW_CLIENT_ID", "type": "VARCHAR", "char_num": 200},
        {"name": "SNOW_CLIENT_SECRET", "type": "VARCHAR", "char_num": 200},
        {"name": "SNOW_INSTANCE_NAME", "type": "VARCHAR", "char_num": 200},
        {"name": "SNOW_PASSWORD", "type": "VARCHAR", "char_num": 200},
        {"name": "SNOW_USERNAME", "type": "VARCHAR", "char_num": 200},
        {"name": "VERSION", "type": "VARCHAR", "char_num": 200},
        {"name": "JENKINS_ENABLED", "type": "VARCHAR", "char_num": 200},
        {"name": "SNOW_ENABLED", "type": "VARCHAR", "char_num": 200}
    ]

    for i in new_fields:
        if i['name'] not in fields:
            if app.config['RUNTIME_ENV'] == 'test':
                if i['type'] == 'VARCHAR':
                    var_stmt = f"VARCHAR({i['char_num']})"
                sql = "ALTER TABLE AppConfig ADD COLUMN" + i['name'] + var_stmt
            else:
                if i['type'] == 'VARCHAR':
                    var_stmt = "TEXT"
                sql = "ALTER TABLE AppConfig ADD COLUMN" + i['name'] + var_stmt
            cur.execute(sql)
            db.commit()

