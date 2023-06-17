import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class TmIdentifiedThreats(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'TmIdentifiedThreats'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    ThreatAssessmentID = db.Column(db.Integer, db.ForeignKey('TmThreatAssessments.ID', ondelete='CASCADE'))
    ThreatID = db.Column(db.Integer, db.ForeignKey('TmThreats.ID', ondelete='CASCADE'))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<TmIdentifiedThreats(name={self.AddDate!r})>'.format(self=self)


class TmIdentifiedThreatsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    ApplicationID = fields.Int()
    ThreatAssessmentID = fields.Int()
    ThreatID = fields.Int()


class MakeTmIdentifiedThreatsSchema(TmIdentifiedThreatsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return TmIdentifiedThreats(**data)



