import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class TmIdentifiedSolutions(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'TmIdentifiedSolutions'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    ThreatAssessmentID = db.Column(db.Integer, db.ForeignKey('TmThreatAssessments.ID', ondelete='CASCADE'))
    SolutionID = db.Column(db.Integer)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<TmIdentifiedSolutions(name={self.AddDate!r})>'.format(self=self)


class TmIdentifiedSolutionsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    ApplicationID = fields.Int()
    ThreatAssessmentID = fields.Int()
    SolutionID = fields.Int()


class MakeTmIdentifiedSolutionsSchema(TmIdentifiedSolutionsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return TmIdentifiedSolutions(**data)



