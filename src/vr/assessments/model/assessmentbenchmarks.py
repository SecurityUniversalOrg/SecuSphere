import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class AssessmentBenchmarks(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AssessmentBenchmarks'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    Name = db.Column(db.String(500))
    Description = db.Column(LONGTEXT)
    Version = db.Column(db.String(50))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AssessmentBenchmarks(name={self.AddDate!r})>'.format(self=self)


class AssessmentBenchmarksSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    Name = fields.Str()
    Description = fields.Str()
    Version = fields.Str()


class MakeAssessmentBenchmarksSchema(AssessmentBenchmarksSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AssessmentBenchmarks(**data)



