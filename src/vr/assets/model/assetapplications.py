from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class AssetApplications(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AssetApplications'
    ID = db.Column(db.Integer, primary_key=True)
    TechnologyID = db.Column(db.Integer)
    ApplicationID = db.Column(db.Integer)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AssetApplications(name={self.TechnologyID!r})>'.format(self=self)


class AssetApplicationsSchema(Schema):
    ID = fields.Int()
    TechnologyID = fields.Int()
    ApplicationID = fields.Int()


class MakeAssetApplicationsSchema(AssetApplicationsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AssetApplications(**data)


