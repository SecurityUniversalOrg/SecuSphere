import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class TmAnsweredQuestions(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'TmAnsweredQuestions'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    ThreatAssessmentID = db.Column(db.Integer, db.ForeignKey('TmThreatAssessments.ID', ondelete='CASCADE'))
    QuestionID = db.Column(db.Integer, db.ForeignKey('TmQuestions.ID', ondelete='CASCADE'))
    Response = db.Column(LONGTEXT)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<TmAnsweredQuestions(name={self.AddDate!r})>'.format(self=self)


class TmAnsweredQuestionsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    ApplicationID = fields.Int()
    ThreatAssessmentID = fields.Int()
    QuestionID = fields.Int()
    Response = fields.Str()


class MakeTmAnsweredQuestionsSchema(TmAnsweredQuestionsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return TmAnsweredQuestions(**data)



