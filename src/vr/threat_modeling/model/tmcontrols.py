import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class TmControls(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'TmControls'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    Control = db.Column(LONGTEXT)
    Type = db.Column(db.String(8))
    Description = db.Column(LONGTEXT)
    Lambda = db.Column(db.String(1))
    Process = db.Column(db.String(1))
    Server = db.Column(db.String(1))
    Dataflow = db.Column(db.String(1))
    Datastore = db.Column(db.String(1))
    ExternalEntity = db.Column(db.String(1))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<TmControls(name={self.AddDate!r})>'.format(self=self)


class TmControlsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    Control = fields.Str()
    Type = fields.Str()
    Description = fields.Str()
    Lambda = fields.Str()
    Process = fields.Str()
    Server = fields.Str()
    Dataflow = fields.Str()
    Datastore = fields.Str()
    ExternalEntity = fields.Str()


class MakeTmControlsSchema(TmControlsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return TmControls(**data)



