import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class Regulations(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'Regulations'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    Regulation = db.Column(db.String(300))
    Acronym = db.Column(db.String(300))
    Jurisdiction = db.Column(db.String(300))
    Category = db.Column(db.String(300))
    Reference = db.Column(db.String(300))
    Description = db.Column(LONGTEXT)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<Regulations(name={self.AddDate!r})>'.format(self=self)


class RegulationsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    Regulation = fields.Str()
    Acronym = fields.Str()
    Jurisdiction = fields.Str()
    Category = fields.Str()
    Reference = fields.Str()
    Description = fields.Str()


class MakeRegulationsSchema(RegulationsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return Regulations(**data)



