import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class ReleaseVersions(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'ReleaseVersions'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    ReleaseName = db.Column(db.String(300))
    ReleaseDate = db.Column(db.DateTime, nullable=True)
    Description = db.Column(LONGTEXT)
    Source = db.Column(db.String(300))
    SourceID = db.Column(db.Integer)
    Released = db.Column(db.String(1))
    Status = db.Column(db.String(30))
    RetireDate = db.Column(db.DateTime, nullable=True)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<ReleaseVersions(name={self.AddDate!r})>'.format(self=self)

class ReleaseVersionsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    ApplicationID = fields.Int()
    ReleaseName = fields.Str()
    ReleaseDate = fields.DateTime()
    Description = fields.Str()
    Source = fields.Str()
    SourceID = fields.Int()
    Released = fields.Str()
    Status = fields.Str()
    RetireDate = fields.DateTime()

class MakeReleaseVersionsSchema(ReleaseVersionsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return ReleaseVersions(**data)



