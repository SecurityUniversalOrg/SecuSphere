from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class AssetNetworkServices(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AssetNetworkServices'
    ID = db.Column(db.Integer, primary_key=True)
    AssetID = db.Column(db.Integer)
    ServiceID = db.Column(db.Integer)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AssetNetworkServices(name={self.AssetID!r})>'.format(self=self)


class AssetNetworkServicesSchema(Schema):
    ID = fields.Int()
    AssetID = fields.Int()
    ServiceID = fields.Int()


class MakeAssetNetworkServicesSchema(AssetNetworkServicesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AssetNetworkServices(**data)



