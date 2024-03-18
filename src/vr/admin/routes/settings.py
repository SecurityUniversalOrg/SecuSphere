from flask import session, redirect, url_for, render_template, request
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
    SNOW_USERNAME, VERSION, JENKINS_ENABLED, SNOW_ENABLED
from flask_sqlalchemy import SQLAlchemy
from vr.admin.models import AppConfig
from vr.admin.functions import db_connection_handler
from sqlalchemy import text


NAV = {
    'CAT': { "name": "Settings", "url": "admin.admin_dashboard"}
}

@admin.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    NAV['curpage'] = {"name": "Settings"}
    user, status, user_roles = _auth_user(session, 'No Role')
    if status == 401:
        return redirect(url_for('admin.login'))
    elif status == 403:
        return render_template('403.html', user=user, nav_cat={}, nav_subcat='', \
                               nav_subsubcat='', nav_curpage={"name": "Unauthorized"})
    if request.method == 'POST':
        app_config = AppConfig.query.first()

        all = request.form
        update_json = {
                AppConfig.JENKINS_ENABLED: all["JENKINS_ENABLED"],
                AppConfig.SNOW_ENABLED: all["SNOW_ENABLED"],
                AppConfig.APP_EXT_URL: all["APP_EXT_URL"],
                AppConfig.AUTH_TYPE: all["AUTH_TYPE"],
                AppConfig.AZAD_AUTHORITY: all["AZAD_AUTHORITY"],
                AppConfig.AZAD_CLIENT_ID: all["AZAD_CLIENT_ID"],
                AppConfig.AZAD_CLIENT_SECRET: all["AZAD_CLIENT_SECRET"],
                AppConfig.AZURE_KEYVAULT_NAME: all["AZURE_KEYVAULT_NAME"],
                AppConfig.ENV: all["ENV"],
                AppConfig.INSECURE_OAUTH: all["INSECURE_OAUTH"],
                AppConfig.JENKINS_HOST: all["JENKINS_HOST"],
                AppConfig.JENKINS_KEY: all["JENKINS_KEY"],
                AppConfig.JENKINS_PROJECT: all["JENKINS_PROJECT"],
                AppConfig.JENKINS_STAGING_PROJECT: all["JENKINS_STAGING_PROJECT"],
                AppConfig.JENKINS_TOKEN: all["JENKINS_TOKEN"],
                AppConfig.JENKINS_USER: all["JENKINS_USER"],
                AppConfig.LDAP_BASE_DN: all["LDAP_BASE_DN"],
                AppConfig.LDAP_BIND_USER_DN: all["LDAP_BIND_USER_DN"],
                AppConfig.LDAP_BIND_USER_PASSWORD: all["LDAP_BIND_USER_PASSWORD"],
                AppConfig.LDAP_GROUP_DN: all["LDAP_GROUP_DN"],
                AppConfig.LDAP_HOST: all["LDAP_HOST"],
                AppConfig.LDAP_PORT: all["LDAP_PORT"],
                AppConfig.LDAP_USER_DN: all["LDAP_USER_DN"],
                AppConfig.LDAP_USER_LOGIN_ATTR: all["LDAP_USER_LOGIN_ATTR"],
                AppConfig.LDAP_USER_RDN_ATTR: all["LDAP_USER_RDN_ATTR"],
                AppConfig.PROD_DB_URI: all["PROD_DB_URI"],
                AppConfig.SMTP_ADMIN_EMAIL: all["SMTP_ADMIN_EMAIL"],
                AppConfig.SMTP_HOST: all["SMTP_HOST"],
                AppConfig.SMTP_PASSWORD: all["SMTP_PASSWORD"],
                AppConfig.SMTP_USER: all["SMTP_USER"],
                AppConfig.SNOW_CLIENT_ID: all["SNOW_CLIENT_ID"],
                AppConfig.SNOW_CLIENT_SECRET: all["SNOW_CLIENT_SECRET"],
                AppConfig.SNOW_INSTANCE_NAME: all["SNOW_INSTANCE_NAME"],
                AppConfig.SNOW_PASSWORD: all["SNOW_PASSWORD"],
                AppConfig.SNOW_USERNAME: all["SNOW_USERNAME"],
                AppConfig.VERSION: all["VERSION"],
            }
        if not app_config.settings_initialized:
            update_json[AppConfig.settings_initialized] = True
        db.session.query(AppConfig) \
            .update(update_json, synchronize_session=False)
        db_connection_handler(db)
        set_env_variables(all)
        current_settings = {
            "JENKINS_ENABLED": all["JENKINS_ENABLED"],
            "SNOW_ENABLED": all["SNOW_ENABLED"],
            "APP_EXT_URL": all["APP_EXT_URL"],
            "AUTH_TYPE": all["AUTH_TYPE"],
            "AZAD_AUTHORITY": all["AZAD_AUTHORITY"],
            "AZAD_CLIENT_ID": all["AZAD_CLIENT_ID"],
            "AZAD_CLIENT_SECRET": all["AZAD_CLIENT_SECRET"],
            "AZURE_KEYVAULT_NAME": all["AZURE_KEYVAULT_NAME"],
            "ENV": all["ENV"],
            "INSECURE_OAUTH": all["INSECURE_OAUTH"],
            "JENKINS_HOST": all["JENKINS_HOST"],
            "JENKINS_KEY": all["JENKINS_KEY"],
            "JENKINS_PROJECT": all["JENKINS_PROJECT"],
            "JENKINS_STAGING_PROJECT": all["JENKINS_STAGING_PROJECT"],
            "JENKINS_TOKEN": all["JENKINS_TOKEN"],
            "JENKINS_USER": all["JENKINS_USER"],
            "LDAP_BASE_DN": all["LDAP_BASE_DN"],
            "LDAP_BIND_USER_DN": all["LDAP_BIND_USER_DN"],
            "LDAP_BIND_USER_PASSWORD": all["LDAP_BIND_USER_PASSWORD"],
            "LDAP_GROUP_DN": all["LDAP_GROUP_DN"],
            "LDAP_HOST": all["LDAP_HOST"],
            "LDAP_PORT": all["LDAP_PORT"],
            "LDAP_USER_DN": all["LDAP_USER_DN"],
            "LDAP_USER_LOGIN_ATTR": all["LDAP_USER_LOGIN_ATTR"],
            "LDAP_USER_RDN_ATTR": all["LDAP_USER_RDN_ATTR"],
            "PROD_DB_URI": all["PROD_DB_URI"],
            "SMTP_ADMIN_EMAIL": all["SMTP_ADMIN_EMAIL"],
            "SMTP_HOST": all["SMTP_HOST"],
            "SMTP_PASSWORD": all["SMTP_PASSWORD"],
            "SMTP_USER": all["SMTP_USER"],
            "SNOW_CLIENT_ID": all["SNOW_CLIENT_ID"],
            "SNOW_CLIENT_SECRET": all["SNOW_CLIENT_SECRET"],
            "SNOW_INSTANCE_NAME": all["SNOW_INSTANCE_NAME"],
            "SNOW_PASSWORD": all["SNOW_PASSWORD"],
            "SNOW_USERNAME": all["SNOW_USERNAME"],
            "VERSION": all["VERSION"],
        }
    else:
        app_config = AppConfig.query.first()
        if app_config.settings_initialized:
            current_settings = {
                "JENKINS_ENABLED": app_config.JENKINS_ENABLED,
                "SNOW_ENABLED": app_config.SNOW_ENABLED,
                "APP_EXT_URL": app_config.APP_EXT_URL,
                "AUTH_TYPE": app_config.AUTH_TYPE,
                "AZAD_AUTHORITY": app_config.AZAD_AUTHORITY,
                "AZAD_CLIENT_ID": app_config.AZAD_CLIENT_ID,
                "AZAD_CLIENT_SECRET": app_config.AZAD_CLIENT_SECRET,
                "AZURE_KEYVAULT_NAME": app_config.AZURE_KEYVAULT_NAME,
                "ENV": app_config.ENV,
                "INSECURE_OAUTH": app_config.INSECURE_OAUTH,
                "JENKINS_HOST": app_config.JENKINS_HOST,
                "JENKINS_KEY": app_config.JENKINS_KEY,
                "JENKINS_PROJECT": app_config.JENKINS_PROJECT,
                "JENKINS_STAGING_PROJECT": app_config.JENKINS_STAGING_PROJECT,
                "JENKINS_USER": app_config.JENKINS_USER,
                "JENKINS_TOKEN": app_config.JENKINS_TOKEN,
                "LDAP_BASE_DN": app_config.LDAP_BASE_DN,
                "LDAP_BIND_USER_DN": app_config.LDAP_BIND_USER_DN,
                "LDAP_BIND_USER_PASSWORD": app_config.LDAP_BIND_USER_PASSWORD,
                "LDAP_GROUP_DN": app_config.LDAP_GROUP_DN,
                "LDAP_HOST": app_config.LDAP_HOST,
                "LDAP_PORT": app_config.LDAP_PORT,
                "LDAP_USER_DN": app_config.LDAP_USER_DN,
                "LDAP_USER_LOGIN_ATTR": app_config.LDAP_USER_LOGIN_ATTR,
                "LDAP_USER_RDN_ATTR": app_config.LDAP_USER_RDN_ATTR,
                "PROD_DB_URI": app_config.PROD_DB_URI,
                "SMTP_ADMIN_EMAIL": app_config.SMTP_ADMIN_EMAIL,
                "SMTP_HOST": app_config.SMTP_HOST,
                "SMTP_USER": app_config.SMTP_USER,
                "SMTP_PASSWORD": app_config.SMTP_PASSWORD,
                "SNOW_CLIENT_ID": app_config.SNOW_CLIENT_ID,
                "SNOW_CLIENT_SECRET": app_config.SNOW_CLIENT_SECRET,
                "SNOW_INSTANCE_NAME": app_config.SNOW_INSTANCE_NAME,
                "SNOW_USERNAME": app_config.SNOW_USERNAME,
                "SNOW_PASSWORD": app_config.SNOW_PASSWORD,
                "VERSION": app_config.VERSION,
            }
        else:
            current_settings = {
                "JENKINS_ENABLED": JENKINS_ENABLED,
                "SNOW_ENABLED": SNOW_ENABLED,
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
                "JENKINS_USER": JENKINS_USER,
                "JENKINS_TOKEN": JENKINS_TOKEN,
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
                "SMTP_USER": SMTP_USER,
                "SMTP_PASSWORD": SMTP_PASSWORD,
                "SNOW_CLIENT_ID": SNOW_CLIENT_ID,
                "SNOW_CLIENT_SECRET": SNOW_CLIENT_SECRET,
                "SNOW_INSTANCE_NAME": SNOW_INSTANCE_NAME,
                "SNOW_USERNAME": SNOW_USERNAME,
                "SNOW_PASSWORD": SNOW_PASSWORD,
                "VERSION": VERSION,
            }
    cat_general = [
        'APP_EXT_URL',
        'AUTH_TYPE',
        'ENV',
        'INSECURE_OAUTH',
        'PROD_DB_URI',
        'VERSION',
        'AZURE_KEYVAULT_NAME'
    ]
    cat_azad = [
        'AZAD_AUTHORITY',
        'AZAD_CLIENT_ID',
        'AZAD_CLIENT_SECRET'
    ]
    cat_jenkins = [
        'JENKINS_ENABLED',
        'JENKINS_HOST',
        'JENKINS_KEY',
        'JENKINS_PROJECT',
        'JENKINS_STAGING_PROJECT',
        'JENKINS_TOKEN',
        'JENKINS_USER'
    ]
    cat_ldap = [
        'LDAP_BASE_DN',
        'LDAP_BIND_USER_DN',
        'LDAP_BIND_USER_PASSWORD',
        'LDAP_GROUP_DN',
        'LDAP_HOST',
        'LDAP_PORT',
        'LDAP_USER_DN',
        'LDAP_USER_LOGIN_ATTR',
        'LDAP_USER_RDN_ATTR'
    ]
    smtp_settings = [
        'SMTP_ADMIN_EMAIL',
        'SMTP_HOST',
        'SMTP_PASSWORD',
        'SMTP_USER'
    ]
    snow_settings = [
        'SNOW_ENABLED',
        'SNOW_CLIENT_ID',
        'SNOW_CLIENT_SECRET',
        'SNOW_INSTANCE_NAME',
        'SNOW_PASSWORD',
        'SNOW_USERNAME'
    ]
    return render_template('admin/settings.html', user_roles=user_roles, NAV=NAV,
                           user=user, settings=current_settings, cat_general=cat_general,
                           cat_azad=cat_azad, cat_jenkins=cat_jenkins, cat_ldap=cat_ldap,
                           smtp_settings=smtp_settings, snow_settings=snow_settings)

def set_env_variables(form):
    os.environ['APP_EXT_URL'] = form["APP_EXT_URL"]
    os.environ['AUTH_TYPE'] = form["AUTH_TYPE"]
    os.environ['AZAD_AUTHORITY'] = form["AZAD_AUTHORITY"]
    os.environ['AZAD_CLIENT_ID'] = form["AZAD_CLIENT_ID"]
    os.environ['AZAD_CLIENT_SECRET'] = form["AZAD_CLIENT_SECRET"]
    os.environ['AZURE_KEYVAULT_NAME'] = form["AZURE_KEYVAULT_NAME"]
    os.environ['ENV'] = form["ENV"]
    os.environ['INSECURE_OAUTH'] = form["INSECURE_OAUTH"]
    os.environ['JENKINS_ENABLED'] = form["JENKINS_ENABLED"]
    os.environ['JENKINS_HOST'] = form["JENKINS_HOST"]
    os.environ['JENKINS_KEY'] = form["JENKINS_KEY"]
    os.environ['JENKINS_PROJECT'] = form["JENKINS_PROJECT"]
    os.environ['JENKINS_STAGING_PROJECT'] = form["JENKINS_STAGING_PROJECT"]
    os.environ['JENKINS_TOKEN'] = form["JENKINS_TOKEN"]
    os.environ['JENKINS_USER'] = form["JENKINS_USER"]
    os.environ['LDAP_BASE_DN'] = form["LDAP_BASE_DN"]
    os.environ['LDAP_BIND_USER_DN'] = form["LDAP_BIND_USER_DN"]
    os.environ['LDAP_BIND_USER_PASSWORD'] = form["LDAP_BIND_USER_PASSWORD"]
    os.environ['LDAP_GROUP_DN'] = form["LDAP_GROUP_DN"]
    os.environ['LDAP_HOST'] = form["LDAP_HOST"]
    os.environ['LDAP_PORT'] = form["LDAP_PORT"]
    os.environ['LDAP_USER_DN'] = form["LDAP_USER_DN"]
    os.environ['LDAP_USER_LOGIN_ATTR'] = form["LDAP_USER_LOGIN_ATTR"]
    os.environ['LDAP_USER_RDN_ATTR'] = form["LDAP_USER_RDN_ATTR"]
    os.environ['PROD_DB_URI'] = form["PROD_DB_URI"]
    os.environ['SMTP_ADMIN_EMAIL'] = form["SMTP_ADMIN_EMAIL"]
    os.environ['SMTP_HOST'] = form["SMTP_HOST"]
    os.environ['SMTP_PASSWORD'] = form["SMTP_PASSWORD"]
    os.environ['SMTP_USER'] = form["SMTP_USER"]
    os.environ['SNOW_ENABLED'] = form["SNOW_ENABLED"]
    os.environ['SNOW_CLIENT_ID'] = form["SNOW_CLIENT_ID"]
    os.environ['SNOW_CLIENT_SECRET'] = form["SNOW_CLIENT_SECRET"]
    os.environ['SNOW_INSTANCE_NAME'] = form["SNOW_INSTANCE_NAME"]
    os.environ['SNOW_PASSWORD'] = form["SNOW_PASSWORD"]
    os.environ['SNOW_USERNAME'] = form["SNOW_USERNAME"]
    os.environ['VERSION'] = form["VERSION"]


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
