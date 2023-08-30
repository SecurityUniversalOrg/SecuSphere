import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class AssessmentBenchmarkAssessments(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AssessmentBenchmarkAssessments'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    BenchmarkID = db.Column(db.Integer, db.ForeignKey('AssessmentBenchmarks.ID', ondelete='CASCADE'))
    UserID = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'))
    Notes = db.Column(LONGTEXT)
    Type = db.Column(db.String(100))
    TargetLevel = db.Column(db.String(100))
    Status = db.Column(db.String(100))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AssessmentBenchmarkAssessments(name={self.AddDate!r})>'.format(self=self)


class AssessmentBenchmarkAssessmentsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    ApplicationID = fields.Int()
    BenchmarkID = fields.Int()
    UserID = fields.Int()
    Notes = fields.Str()
    Type = fields.Str()
    TargetLevel = fields.Str()
    Status = fields.Str()
    Name = fields.Str()
    Version = fields.Str()
    username = fields.Str()
    findings_cnt = fields.Int()


class MakeAssessmentBenchmarkAssessmentsSchema(AssessmentBenchmarkAssessmentsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AssessmentBenchmarkAssessments(**data)



