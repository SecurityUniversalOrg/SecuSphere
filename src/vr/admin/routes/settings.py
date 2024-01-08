from flask import session, redirect, url_for, render_template
from flask_login import login_required
from vr import db, app
import os
# Start of Entity-specific Imports
from vr.admin import admin
from vr.admin.functions import _auth_user, check_menu_tour_init
from config_engine import ENV, PROD_DB_URI, AUTH_TYPE, APP_EXT_URL, LDAP_HOST, LDAP_PORT, LDAP_BASE_DN, \
    LDAP_USER_DN, LDAP_GROUP_DN, LDAP_USER_RDN_ATTR, LDAP_USER_LOGIN_ATTR, LDAP_BIND_USER_DN, LDAP_BIND_USER_PASSWORD, \
    AZAD_CLIENT_ID, AZAD_CLIENT_SECRET, AZAD_AUTHORITY, JENKINS_USER, AZURE_KEYVAULT_NAME, INSECURE_OAUTH, \
    JENKINS_HOST, JENKINS_KEY, JENKINS_PROJECT, JENKINS_STAGING_PROJECT, JENKINS_TOKEN, SMTP_ADMIN_EMAIL, \
    SMTP_HOST, SMTP_PASSWORD, SMTP_USER, SNOW_CLIENT_ID, SNOW_CLIENT_SECRET, SNOW_INSTANCE_NAME, SNOW_PASSWORD, \
    SNOW_USERNAME, VERSION
from flask_sqlalchemy import SQLAlchemy

NAV = {
    'CAT': { "name": "Settings", "url": "admin.admin_dashboard"}
}

@admin.route('/settings', methods=['GET'])
@login_required
def settings():
    NAV['curpage'] = {"name": "Settings"}
    user, status, user_roles = _auth_user(session, 'No Role')
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, nav_cat={}, nav_subcat='', \
                               nav_subsubcat='', nav_curpage={"name": "Unauthorized"})
    current_settings = {
        "APP_EXT_URL": APP_EXT_URL,
        "AUTH_TYPE": AUTH_TYPE,
        "AZAD_AUTHORITY":AZAD_AUTHORITY,
        "AZAD_CLIENT_ID": AZAD_CLIENT_ID,
        "AZAD_CLIENT_SECRET": AZAD_CLIENT_SECRET,
        "AZURE_KEYVAULT_NAME": AZURE_KEYVAULT_NAME,
        "ENV": ENV,
        "INSECURE_OAUTH": INSECURE_OAUTH,
        "JENKINS_HOST": JENKINS_HOST,
        "JENKINS_KEY": JENKINS_KEY,
        "JENKINS_PROJECT": JENKINS_PROJECT,
        "JENKINS_STAGING_PROJECT": JENKINS_STAGING_PROJECT,
        "JENKINS_TOKEN": JENKINS_TOKEN,
        "JENKINS_USER": JENKINS_USER,
        "LDAP_BASE_DN": LDAP_BASE_DN,
        "LDAP_BIND_USER_DN": LDAP_BIND_USER_DN,
        "LDAP_BIND_USER_PASSWORD": LDAP_BIND_USER_PASSWORD,
        "LDAP_GROUP_DN": LDAP_GROUP_DN,
        "LDAP_HOST": LDAP_HOST,
        "LDAP_PORT": LDAP_PORT,
        "LDAP_USER_DN": LDAP_USER_DN,
        "LDAP_USER_LOGIN_ATTR": LDAP_USER_LOGIN_ATTR,
        "LDAP_USER_RDN_ATTR": LDAP_USER_RDN_ATTR,
        "PROD_DB_URI": PROD_DB_URI,
        "SMTP_ADMIN_EMAIL": SMTP_ADMIN_EMAIL,
        "SMTP_HOST": SMTP_HOST,
        "SMTP_PASSWORD": SMTP_PASSWORD,
        "SMTP_USER": SMTP_USER,
        "SNOW_CLIENT_ID": SNOW_CLIENT_ID,
        "SNOW_CLIENT_SECRET": SNOW_CLIENT_SECRET,
        "SNOW_INSTANCE_NAME": SNOW_INSTANCE_NAME,
        "SNOW_PASSWORD": SNOW_PASSWORD,
        "SNOW_USERNAME": SNOW_USERNAME,
        "VERSION": VERSION,
    }
    return render_template('admin/settings.html', user_roles=user_roles, NAV=NAV,
                           user=user, settings=current_settings)

@admin.route('/dangerous/delete_all', methods=['POST'])
def delete_all_data():
    NAV['curpage'] = {"name": "Settings"}
    user, status, user_roles = _auth_user(session, 'No Role')
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, nav_cat={}, nav_subcat='', \
                               nav_subsubcat='', nav_curpage={"name": "Unauthorized"})

    try:
        if ENV == 'test':
            # Ensure all connections to the database are closed
            db.session.close()
            db.engine.dispose()

            # Path to the SQLite database file
            db_path = "instance/" + app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')

            # Delete the database file
            if os.path.exists(db_path):
                os.remove(db_path)
            else:
                print("The file does not exist")
        else:
            # Reflect the current database schema
            db.reflect()

            # Retrieve all table names
            table_names = db.engine.table_names()

            # Drop each table
            for table_name in reversed(table_names):
                db.engine.execute(f'DROP TABLE IF EXISTS {table_name} CASCADE')

        # Recreate all tables based on the current models
        from vr.functions.mysql_db import connect_to_db
        cur, db_obj = connect_to_db()
        sql = '''CREATE TABLE "User" (id INTEGER NOT NULL, is_active BOOLEAN DEFAULT '1' NOT NULL, is_admin BOOLEAN DEFAULT '0' NOT NULL, is_security BOOLEAN DEFAULT '0' NOT NULL, username VARCHAR(100), password VARCHAR(255), auth_type VARCHAR(20), mfa_enabled BOOLEAN DEFAULT '0' NOT NULL, otp_secret VARCHAR(16), email VARCHAR(255) NOT NULL, email_confirmed_at DATETIME, first_name VARCHAR(100) DEFAULT '' NOT NULL, last_name VARCHAR(100) DEFAULT '' NOT NULL, jobtitle VARCHAR(100), dept VARCHAR(100), user_type VARCHAR(100), avatar_path VARCHAR(100), email_updates VARCHAR(1), app_updates VARCHAR(1), text_updates VARCHAR(1), registration_date DATETIME, loc_zipcode VARCHAR(20), loc_city VARCHAR(100), loc_state VARCHAR(50), about_me VARCHAR(2000), web_tz VARCHAR(100), phone_no VARCHAR(40), support_id VARCHAR(50), support_key VARCHAR(50), support_contact_id INTEGER, auth_token VARCHAR(300), onboarding_confirmed VARCHAR(1), PRIMARY KEY (id), UNIQUE (email))'''
        cur.execute(sql)
        db_obj.commit()
        sql = 'CREATE TABLE "AppConfig" (id INTEGER NOT NULL, first_access BOOLEAN NOT NULL,PRIMARY KEY (id))'
        cur.execute(sql)
        db_obj.commit()
        sql = 'CREATE TABLE "EntityPermissions" ("ID" INTEGER NOT NULL, "AddDate" DATETIME NOT NULL, "UserID" INTEGER, "EntityType" VARCHAR(100), "EntityID" VARCHAR(100), PRIMARY KEY ("ID"), FOREIGN KEY("UserID") REFERENCES "User" (id) ON DELETE CASCADE)'
        cur.execute(sql)
        db_obj.commit()
        sql = 'CREATE TABLE "SourceCodeFile" ("ID" INTEGER NOT NULL, "AddDate" DATETIME, "GitRepoId" INTEGER, "FileName" VARCHAR(300), "FileLocation" VARCHAR(300), "FileType" VARCHAR(300), PRIMARY KEY ("ID"))'
        cur.execute(sql)
        db_obj.commit()
        sql = 'CREATE TABLE "TmControls" ("ID" INTEGER NOT NULL, "AddDate" DATETIME NOT NULL, "Control" TEXT, "Type" VARCHAR(8), "Description" TEXT, "Lambda" VARCHAR(1), "Process" VARCHAR(1), "Server" VARCHAR(1), "Dataflow" VARCHAR(1), "Datastore" VARCHAR(1), "ExternalEntity" VARCHAR(1), PRIMARY KEY ("ID"))'
        cur.execute(sql)
        db_obj.commit()
        sql = 'CREATE TABLE "UserRoleAssignments" (id INTEGER NOT NULL, user_id INTEGER, role_id INTEGER, PRIMARY KEY (id), FOREIGN KEY(user_id) REFERENCES "User" (id) ON DELETE CASCADE, FOREIGN KEY(role_id) REFERENCES "UserRoles" (id) ON DELETE CASCADE)'
        cur.execute(sql)
        db_obj.commit()
        sql = 'CREATE TABLE "UserRoles" (id INTEGER NOT NULL, name VARCHAR(50), description VARCHAR(200), PRIMARY KEY (id), UNIQUE (name))'
        cur.execute(sql)
        db_obj.commit()
        db_obj.close()


        return "All tables dropped successfully", 200
    except Exception as e:
        # Log the exception for debugging purposes
        print(e)
        db.session.rollback()
        return "Error occurred during table deletion", 500
