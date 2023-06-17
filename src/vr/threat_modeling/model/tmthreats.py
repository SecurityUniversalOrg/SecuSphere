import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class TmThreats(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'TmThreats'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    Target = db.Column(db.String(100))
    Description = db.Column(LONGTEXT)
    Details = db.Column(LONGTEXT)
    LikelihoodOfAttack = db.Column(db.String(30))
    Severity = db.Column(db.String(30))
    cCondition = db.Column(LONGTEXT)
    Prerequisites = db.Column(LONGTEXT)
    Mitigations = db.Column(LONGTEXT)
    Example = db.Column(LONGTEXT)
    rReferences = db.Column(LONGTEXT)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<TmThreats(name={self.AddDate!r})>'.format(self=self)


class TmThreatsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    Target = fields.Str()
    Description = fields.Str()
    Details = fields.Str()
    LikelihoodOfAttack = fields.Str()
    Severity = fields.Str()
    cCondition = fields.Str()
    Prerequisites = fields.Str()
    Mitigations = fields.Str()
    Example = fields.Str()
    rReferences = fields.Str()


class MakeTmThreatsSchema(TmThreatsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return TmThreats(**data)



