import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class AssessmentBenchmarkRuleAudits(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AssessmentBenchmarkRuleAudits'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    RuleID = db.Column(db.Integer, db.ForeignKey('AssessmentBenchmarkRules.ID', ondelete='CASCADE'))
    AssessmentID = db.Column(db.Integer, db.ForeignKey('AssessmentBenchmarkAssessments.ID', ondelete='CASCADE'))
    PassingLevels = db.Column(db.String(500))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AssessmentBenchmarkRuleAudits(name={self.AddDate!r})>'.format(self=self)


class AssessmentBenchmarkRuleAuditsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    ApplicationID = fields.Int()
    RuleID = fields.Int()
    AssessmentID = fields.Int()
    PassingLevels = fields.Str()


class MakeAssessmentBenchmarkRuleAuditsSchema(AssessmentBenchmarkRuleAuditsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AssessmentBenchmarkRuleAudits(**data)



