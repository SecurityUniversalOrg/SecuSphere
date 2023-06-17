import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class TmSolutions(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'TmSolutions'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    Targets = db.Column(db.String(60))
    Attributes = db.Column(LONGTEXT)
    Description = db.Column(LONGTEXT)
    FixType = db.Column(db.String(100))
    Fix = db.Column(LONGTEXT)
    Solution = db.Column(LONGTEXT)
    Validation = db.Column(db.String(100))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<TmSolutions(name={self.AddDate!r})>'.format(self=self)


class TmSolutionsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    Targets = fields.Str()
    Attributes = fields.Str()
    Description = fields.Str()
    FixType = fields.Str()
    Fix = fields.Str()
    Solution = fields.Str()
    Validation = fields.Str()


class MakeTmSolutionsSchema(TmSolutionsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return TmSolutions(**data)



