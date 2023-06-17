import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class TmQuestions(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'TmQuestions'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    Question = db.Column(LONGTEXT)
    Condition = db.Column(LONGTEXT)
    Options = db.Column(LONGTEXT)
    Type = db.Column(db.String(100))
    Prereqs = db.Column(LONGTEXT)
    Targets = db.Column(db.String(100))
    Produces = db.Column(db.String(100))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<TmQuestions(name={self.AddDate!r})>'.format(self=self)


class TmQuestionsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    Question = fields.Str()
    Condition = fields.Str()
    Options = fields.Str()
    Type = fields.Str()
    Prereqs = fields.Str()
    Targets = fields.Str()
    Produces = fields.Str()


class MakeTmQuestionsSchema(TmQuestionsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return TmQuestions(**data)



