import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class AssessmentBenchmarkRules(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AssessmentBenchmarkRules'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    BenchmarkID = db.Column(db.Integer, db.ForeignKey('AssessmentBenchmarks.ID', ondelete='CASCADE'))
    Number = db.Column(db.String(50))
    Description = db.Column(LONGTEXT)
    ImplementationLevels = db.Column(db.String(500))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AssessmentBenchmarkRules(name={self.AddDate!r})>'.format(self=self)


class AssessmentBenchmarkRulesSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    BenchmarkID = fields.Int()
    Number = fields.Str()
    Description = fields.Str()
    ImplementationLevels = fields.Str()


class MakeAssessmentBenchmarkRulesSchema(AssessmentBenchmarkRulesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AssessmentBenchmarkRules(**data)



