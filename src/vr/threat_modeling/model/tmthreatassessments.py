import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class TmThreatAssessments(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'TmThreatAssessments'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    SubmitUserID = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'))
    Status = db.Column(db.String(30))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<TmThreatAssessments(name={self.AddDate!r})>'.format(self=self)


class TmThreatAssessmentsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    ApplicationID = fields.Int()
    SubmitUserID = fields.Int()
    Status = fields.Str()
    username = fields.Str()
    findings_cnt = fields.Int()
    ApplicationName = fields.Str()


class MakeTmThreatAssessmentsSchema(TmThreatAssessmentsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return TmThreatAssessments(**data)



