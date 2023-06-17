import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class IssueNotes(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'IssueNotes'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    VulnerabilityID = db.Column(db.Integer, db.ForeignKey('Vulnerabilities.VulnerabilityID', ondelete='CASCADE'))
    UserID = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'))
    Private = db.Column(db.Integer)
    Note = db.Column(LONGTEXT)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<IssueNotes(name={self.AddDate!r})>'.format(self=self)


class IssueNotesSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    VulnerabilityID = fields.Int()
    UserID = fields.Int()
    Private = fields.Int()
    Note = fields.Str()


class MakeIssueNotesSchema(IssueNotesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return IssueNotes(**data)



