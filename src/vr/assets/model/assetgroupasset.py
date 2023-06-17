from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class AssetGroupAsset(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AssetGroupAsset'
    ID = db.Column(db.Integer, primary_key=True)
    AssetGroupID = db.Column(db.Integer)
    TechnologyID = db.Column(db.Integer)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AssetGroupAsset(name={self.AssetGroupID!r})>'.format(self=self)

class AssetGroupAssetSchema(Schema):
    ID = fields.Int()
    AssetGroupID = fields.Int()
    TechnologyID = fields.Int()

class MakeAssetGroupAssetSchema(AssetGroupAssetSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AssetGroupAsset(**data)



