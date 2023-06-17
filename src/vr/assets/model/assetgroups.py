from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class AssetGroups(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AssetGroups'
    ID = db.Column(db.Integer, primary_key=True)
    AssetGroupName = db.Column(db.String(60))
    AssetGroupDesc = db.Column(db.String(200))
    RegDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AssetGroups(name={self.AssetGroupName!r})>'.format(self=self)

class AssetGroupsSchema(Schema):
    ID = fields.Int()
    AssetGroupName = fields.Str()
    AssetGroupDesc = fields.Str()
    RegDate = fields.DateTime()

class MakeAssetGroupsSchema(AssetGroupsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AssetGroups(**data)



