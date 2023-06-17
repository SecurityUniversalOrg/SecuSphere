import mysql.connector
from vr import app
import sqlite3


if app.config['RUNTIME_ENV'] == 'test':
    def connect_to_db():
        db_uri = 'instance/database.db'
        db = sqlite3.connect(db_uri)
        cur = db.cursor()
        return cur, db
else:
    def connect_to_db():
        db_uri = app.config['SQLALCHEMY_DATABASE_URI']
        main_part = db_uri.split('://')[1]
        un = main_part.split(':', 1)[0]
        db_name = main_part.rsplit('/', 1)[1]
        host_and_port = main_part.rsplit('@', 1)[1].replace(f"/{db_name}", '')
        host = host_and_port.split(':')[0]
        port = int(host_and_port.split(':')[1])
        pw = main_part.split(':', 1)[1].replace(f"@{host}", '').replace(f"/{db_name}", '').replace(f":{port}", "")
        db = mysql.connector.connect(host=host,database=db_name,user=un,password=pw,port=port)
        cur = db.cursor()
        return cur, db

