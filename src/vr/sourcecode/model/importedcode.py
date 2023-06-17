import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class ImportedCode(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'ImportedCode'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    PackageName = db.Column(db.String(300))
    PackageVersion = db.Column(db.String(300))
    ImportMethod = db.Column(db.String(300))
    ImportFile = db.Column(db.String(300))
    Status = db.Column(db.String(30))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<ImportedCode(name={self.AddDate!r})>'.format(self=self)


class ImportedCodeSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    ApplicationID = fields.Int()
    PackageName = fields.Str()
    PackageVersion = fields.Str()
    ImportMethod = fields.Str()
    ImportFile = fields.Str()
    Status = fields.Str()


class MakeImportedCodeSchema(ImportedCodeSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return ImportedCode(**data)



