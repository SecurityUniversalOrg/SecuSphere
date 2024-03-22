import smtplib
from email.mime import multipart
from email.mime import text as mimetext
from vr import app


def send_email(msg_fromaddr, msg_toaddr, msg_subject, msg_body):
    message = msg_body
    msg = multipart.MIMEMultipart('related')
    msg['From'] = msg_fromaddr
    msg['To'] = msg_toaddr
    msg['Subject'] = msg_subject
    msg.attach(mimetext.MIMEText(message, 'html'))
    server = smtplib.SMTP(app.config['SMTP_HOST'])
    server.starttls()
    server.login(app.config['SMTP_USER'], app.config['SMTP_PASSWORD'])
    server.ehlo()
    text = msg.as_string()
    server.sendmail(msg_fromaddr, msg_toaddr, text)


# Send Registration token
def send_registration_email(ext_url, username, first_name, last_name, token, email_to):
    msg_subject = "SecuSphere User Registration"
    msg_body = generate_registration_msg(ext_url, username, first_name, last_name, token)
    try:
        send_email(app.config['SMTP_ADMIN_EMAIL'], email_to, msg_subject, msg_body)
    except:
        return 'error'


# Global Message Formatting
html_header = '<!DOCTYPE html>\
    <html>\
    <head>\
    <style>\
    * {\
      box-sizing: border-box;\
    }\
    \
    body {\
      font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;\
      padding: 10px;\
      background: #f1f1f1;\
    }\
    \
    /* Header/Blog Title */\
    .header {\
      padding: 2px;\
      text-align: center;\
      background: white;\
    }\
    \
    .header h1 {\
      font-size: 50px;\
    }\
    \
    /* Create two unequal columns that floats next to each other */\
    /* Left column */\
    .leftcolumn {   \
      float: left;\
      width: 100%;\
    }\
    \
    /* Right column */\
    .rightcolumn {\
      float: left;\
      width: 25%;\
      background-color: #f1f1f1;\
      padding-left: 20px;\
    }\
    \
    /* Fake image */\
    .fakeimg {\
       background-color: #aaa;\
       width: 100%;\
       padding: 20px;\
    }\
    \
    /* Add a card effect for articles */\
    .card {\
      background-color: white;\
      padding: 20px;\
      margin-top: 20px;\
    }\
    \
    /* Clear floats after the columns */\
    .row:after {\
      content: "";\
      display: table;\
      clear: both;\
    }\
    \
    /* Footer */\
    .footer {\
      padding: 20px;\
      text-align: center;\
      background: #ddd;\
      margin-top: 20px;\
      font-size: 12px;\
    }\
    \
    /* Responsive layout - when the screen is less than 800px wide, make the two columns stack on top of each other instead of next to each other */\
    @media screen and (max-width: 800px) {\
      .leftcolumn, .rightcolumn {   \
        width: 100%;\
        padding: 0;\
      }\
    }\
    \
    /* Responsive layout - when the screen is less than 400px wide, make the navigation links stack on top of each other instead of next to each other */\
    @media screen and (max-width: 400px) {\
      .topnav a {\
        float: none;\
        width: 100%;\
      }\
    }'

msg_header = '<body>\
    \
    <div class="header">\
      <h1><a href="https://www.securityuniversal.com/secusphere"><img src="https://www.securityuniversal.com/static/images/secusphere.png" height="80" width="80" alt="logo" border="0"></a></h1>\
    </div>\
    \
    <div class="topnav">\
    \
    </div>'

html_footer = '<div class="footer">\
  <p>\u00a9 Security Universal, 8 The Green Ste A, Dover, DE 19901</p>\
  <p>You received this email because you are subscribed to Email Alerts from Security Universal. The information in this email may not be reused or redistributed without express written consent of Security Universal.</p>\
  <a href="#">Unsubscribe</a>\
  <a href="#">Privacy</a>\
  <a href="#">Terms</a>\
  <a href="#">FAQ</a>\
  </div>\
  \
  </body>\
  </html>'


def generate_evnt_msg(msg_subject, evnt_ts, evnt_list, action_list, st):
    evt_style = '#events {\
        font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;\
        border-collapse: collapse;\
        width: 100%;\
        }\
        #events td, #events th {\
        border: 1px solid #ddd;\
        padding: 8px;\
        }\
        \
        #events tr:nth-child(even){background-color: #f2f2f2;}\
        \
        #events tr:hover {background-color: #ddd;}\
        \
        #events th {\
        padding-top: 12px;\
        padding-bottom: 12px;\
        text-align: left;\
        background-color: #86878a;\
        color: white;\
        }\
        /* Include the padding and border in an elements total width and height */\
        * {\
        box-sizing: border-box;\
        }\
        \
        /* Remove margins and padding from the list */\
        ul {\
        margin: 0;\
        padding: 0;\
        }\
        \
        /* Style the list items */\
        ul li {\
        cursor: pointer;\
        position: relative;\
        padding: 12px 8px 12px 40px;\
        list-style-type: none;\
        background: #eee;\
        font-size: 18px;\
        transition: 0.2s;\
        \
        /* make the list items unselectable */\
        -webkit-user-select: none;\
        -moz-user-select: none;\
        -ms-user-select: none;\
        user-select: none;\
        }\
        \
        /* Set all odd list items to a different color (zebra-stripes) */\
        ul li:nth-child(odd) {\
        background: #f9f9f9;\
        }\
        \
        /* Darker background-color on hover */\
        ul li:hover {\
        background: #ddd;\
        }\
        \
        /* When clicked on, add a background color and strike out text */\
        ul li.checked {\
        background: #888;\
        color: #fff;\
        text-decoration: line-through;\
        }\
        \
        /* Add a "checked" mark when clicked on */\
        ul li.checked::before {\
        content: '';\
        position: absolute;\
        border-color: #fff;\
        border-style: solid;\
        border-width: 0 2px 2px 0;\
        top: 10px;\
        left: 16px;\
        transform: rotate(45deg);\
        height: 15px;\
        width: 7px;\
        }\
        \
        /* Style the close button */\
        .close {\
        position: absolute;\
        right: 0;\
        top: 0;\
        padding: 12px 16px 12px 16px;\
        }\
        \
        .close:hover {\
        background-color: #f44336;\
        color: white;\
        }\
        \
        /* Style the input */\
        input {\
        margin: 0;\
        border: none;\
        border-radius: 0;\
        width: 75%;\
        padding: 10px;\
        float: left;\
        font-size: 16px;\
        }\
        \
        /* Style the "Add" button */\
        .addBtn {\
        padding: 10px;\
        width: 25%;\
        background: #d9d9d9;\
        color: #555;\
        float: left;\
        text-align: center;\
        font-size: 16px;\
        cursor: pointer;\
        transition: 0.3s;\
        border-radius: 0;\
        }\
        \
        .addBtn:hover {\
        background-color: #bbb;\
        }\
        </style>\
        </head>'
    evt_msg = '<div class="row"><div class="leftcolumn"><div class="card"><h2>{}</h2><h5>Event Time: {}</h5><table id="events"><tr>'.format(
        msg_subject.upper(), evnt_ts)
    if evnt_list:
        for i in evnt_list[0].keys():
            evt_msg = evt_msg + '<th>{}</th>'.format(i.replace('_', ' ').upper())
        evt_msg = evt_msg + '</tr>'
        for i in evnt_list:
            evt_msg = evt_msg + '<tr>'
            for j in range(0, len(i.keys())):
                evt_msg = evt_msg + '<td>{}</td>'.format(i[list(i.keys())[j]])
            evt_msg = evt_msg + '</tr>'
        evt_msg = evt_msg + '</table></div>'
    else:
        evt_msg = evt_msg + '</tr></table></div>'
    recom_action = '<div class="card">\
      <h2>RECOMMENDED ACTION</h2>'
    if st:
        recom_action = recom_action + f"<h5>Service Ticket: <a href=\"/service_ticket_details_{st}\">IR-{st}</a></h5>"
    recom_action = recom_action + '<ul id="myUL">'
    for i in action_list:
        recom_action = recom_action + '<li>{}</li>'.format(i)
    recom_action = recom_action + '</ul></div></div></div>'

    evt_msg = evt_msg + recom_action
    msg_body = html_header + evt_style + msg_header + evt_msg + html_footer
    return msg_body


def generate_registration_msg(ext_url, username, first_name, last_name, token):
    evt_style = '#events {\
        font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;\
        border-collapse: collapse;\
        width: 100%;\
        }\
        #events td, #events th {\
        border: 1px solid #ddd;\
        padding: 8px;\
        }\
        \
        #events tr:nth-child(even){background-color: #f2f2f2;}\
        \
        #events tr:hover {background-color: #ddd;}\
        \
        #events th {\
        padding-top: 12px;\
        padding-bottom: 12px;\
        text-align: left;\
        background-color: #86878a;\
        color: white;\
        }\
        /* Include the padding and border in an elements total width and height */\
        * {\
        box-sizing: border-box;\
        }\
        \
        /* Remove margins and padding from the list */\
        ul {\
        margin: 0;\
        padding: 0;\
        }\
        \
        /* Style the list items */\
        ul li {\
        cursor: pointer;\
        position: relative;\
        padding: 12px 8px 12px 40px;\
        list-style-type: none;\
        background: #eee;\
        font-size: 18px;\
        transition: 0.2s;\
        \
        /* make the list items unselectable */\
        -webkit-user-select: none;\
        -moz-user-select: none;\
        -ms-user-select: none;\
        user-select: none;\
        }\
        \
        /* Set all odd list items to a different color (zebra-stripes) */\
        ul li:nth-child(odd) {\
        background: #f9f9f9;\
        }\
        \
        /* Darker background-color on hover */\
        ul li:hover {\
        background: #ddd;\
        }\
        \
        /* When clicked on, add a background color and strike out text */\
        ul li.checked {\
        background: #888;\
        color: #fff;\
        text-decoration: line-through;\
        }\
        \
        /* Add a "checked" mark when clicked on */\
        ul li.checked::before {\
        content: '';\
        position: absolute;\
        border-color: #fff;\
        border-style: solid;\
        border-width: 0 2px 2px 0;\
        top: 10px;\
        left: 16px;\
        transform: rotate(45deg);\
        height: 15px;\
        width: 7px;\
        }\
        \
        /* Style the close button */\
        .close {\
        position: absolute;\
        right: 0;\
        top: 0;\
        padding: 12px 16px 12px 16px;\
        }\
        \
        .close:hover {\
        background-color: #f44336;\
        color: white;\
        }\
        \
        /* Style the input */\
        input {\
        margin: 0;\
        border: none;\
        border-radius: 0;\
        width: 75%;\
        padding: 10px;\
        float: left;\
        font-size: 16px;\
        }\
        \
        /* Style the "Add" button */\
        .addBtn {\
        padding: 10px;\
        width: 25%;\
        background: #d9d9d9;\
        color: #555;\
        float: left;\
        text-align: center;\
        font-size: 16px;\
        cursor: pointer;\
        transition: 0.3s;\
        border-radius: 0;\
        }\
        \
        .addBtn:hover {\
        background-color: #bbb;\
        }\
        </style>\
        </head>'
    msg_subject = 'SecuSphere - User Account Registration'
    evt_msg = '<div class="row"><div class="leftcolumn"><div class="card"><h2>{}</h2>'.format(msg_subject.upper())
    if token:
        evt_msg = evt_msg + f"<p>Dear {first_name} {last_name},</p><p>You have been invited to complete your SecuSphere User Account Registration.  To complete your Account Registration, <a href=\"http://{ext_url}/register_user/{token}\">click here</a>.  </p><p><strong>Login Username:</strong> {username}</p><br><br><p>PLEASE NOTE: This one-time registration link will expire 30 minutes after your account activation signup.</p>"
    else:
        evt_msg = evt_msg + f"<p>Dear {first_name} {last_name},</p><p>Thank you for completing the initial SecuSphere Administrator User Account Registration.  </p><p><strong>Login Username:</strong> {username}</p><br><br>"
    msg_body = html_header + evt_style + msg_header + evt_msg + html_footer
    return msg_body
