from vr import db
from flask import request, render_template, session, redirect, url_for
from vr.admin import admin
from flask_login import login_required
from vr.admin.functions import _auth_user, _entity_permissions_filter, _entity_page_permissions_filter, _add_page_permissions_filter
from vr.admin.functions import db_connection_handler
from vr.admin.models import User, Messages, MessagesSchema, MessagesStatus
from math import ceil
from vr.functions.table_functions import load_table, update_table
from sqlalchemy import text
from vr.vulns.model.vulnerabilities import Vulnerabilities


NAV = {
    'CAT': { "name": "Admin", "url": "admin.dashboard"}
}
SERVER_ERR_STATUS = "500.html"


@admin.route("/messages", methods=['GET', 'POST'])
@login_required
def messages():
    try:
        NAV['curpage'] = {"name": "Messages"}
        user, status, user_roles = _auth_user(session, 'No Role')
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        key = 'Messages.ReceiverUserId'
        val = user.id
        filter_list = f"{key} = {val}"

        new_dict = {
            'db_name': 'Messages',
            "sort_field": "ID"
        }

        if request.method == 'POST':
            # sort
            page, per_page, orderby_dict, orderby = update_table(request, new_dict, direction="desc")
            allowed_columns = ["ID", "AddDate", "MessageType"]  # Example whitelist
            allowed_directions = ["asc", "desc"]
            column, direction = orderby.split() if " " in orderby else (orderby, "asc")
            if column not in allowed_columns or direction.lower() not in allowed_directions:
                raise ValueError("Invalid orderby value")
            safe_orderby = f"{column} {direction.lower()}"
        else:
            page, per_page, orderby_dict, orderby = load_table(new_dict, direction="desc")

        base_filter = " AND (MessagesStatus.Status <> 'Closed' OR MessagesStatus.Status IS NULL)"

        if user.is_admin or user.is_security:
            msg_filter = "(" + filter_list + " OR Messages.ReceiverUserId IS NULL)" + base_filter
        else:
            msg_filter = filter_list + base_filter

        messages_all = Messages.query.with_entities(
            Messages.ID, Messages.SenderUserId, Messages.ReceiverUserId, Messages.AddDate, Messages.MessageType,
            Messages.Message, User.username, Messages.EntityType, Messages.EntityID, Vulnerabilities.ApplicationId
        )\
            .join(MessagesStatus, MessagesStatus.MessageId == Messages.ID, isouter=True) \
            .join(Vulnerabilities, Vulnerabilities.VulnerabilityID == Messages.EntityID, isouter=True) \
            .join(User, User.id == Messages.SenderUserId) \
            .filter(text(msg_filter)) \
            .order_by(text(safe_orderby)) \
            .yield_per(per_page) \
            .paginate(page=page, per_page=per_page, error_out=False)

        pg_cnt = ceil((messages_all.total / per_page))
        schema = MessagesSchema(many=True)
        assets = schema.dump(messages_all.items)


        table_details = {
            "pg_cnt": pg_cnt,
            "page": int(page),
            "item_tot": messages_all.total,
            "per_page": per_page,
            "orderby": orderby,
            "rec_start": (int(page) - 1) * per_page + 1 if int(page) != 1 else 1,
            "rec_end": int(page) * per_page if (int(page) * per_page) < messages_all.total else messages_all.total
        }
        return render_template('admin/messages.html', entities=assets, user=user, NAV=NAV,
                               table_details=table_details)
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS), 500


@admin.route("/suppress_msg", methods=['POST'])
@login_required
def suppress_msg():
    try:
        NAV['curpage'] = {"name": "Messages"}
        user, status, user_roles = _auth_user(session, 'No Role')
        if status == 401:
            return redirect(url_for('admin.login'))
        elif status == 403:
            return render_template('403.html', user=user, NAV=NAV)

        key = 'Messages.ReceiverUserId'
        val = user.id

        msg_id = request.form.get('msg_id')
        filter_list = f"{key} = {val} AND Messages.ID={msg_id}"
        msg = Messages.query.\
            with_entities(Messages.ID, Messages.SenderUserId, Messages.ReceiverUserId, Messages.AddDate,
                          Messages.MessageType, Messages.Message, MessagesStatus.Status).\
            join(MessagesStatus, MessagesStatus.MessageId==Messages.ID, isouter=True).filter(text(filter_list)).first()
        if msg:
            if msg.Status != None:
                db.session.query(MessagesStatus).filter(text(f"MessagesStatus.MessageId={msg_id}")) \
                    .update({MessagesStatus.Status: "Closed"}, synchronize_session=False)
                db_connection_handler(db)
            else:
                new_msg = MessagesStatus(
                    MessageId=msg_id,
                    Status="Closed",
                    UserId=msg.ReceiverUserId
                )
                db.session.add(new_msg)
                db_connection_handler(db)
            return {
                       "Status": "Success"
                   }, 200
    except RuntimeError:
        return render_template(SERVER_ERR_STATUS)
