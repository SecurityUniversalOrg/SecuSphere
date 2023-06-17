from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class PrivateNetworks(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'PrivateNetworks'
    ID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(100))
    CIDR = db.Column(db.String(30))
    SubnetMask = db.Column(db.String(16))
    Description = db.Column(db.String(200))
    RegDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    PHI = db.Column(db.Integer)
    PII = db.Column(db.Integer)
    PCI = db.Column(db.Integer)
    MiscCustomerData = db.Column(db.Integer)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


    def __repr__(self):
        return '<PrivateNetworks(name={self.Name!r})>'.format(self=self)


class PrivateNetworksSchema(Schema):
    ID = fields.Int()
    Name = fields.Str()
    CIDR = fields.Str()
    SubnetMask = fields.Str()
    Description = fields.Str()
    RegDate = fields.DateTime()
    PHI = fields.Int()
    PII = fields.Int()
    PCI = fields.Int()
    MiscCustomerData = fields.Int()


class MakePrivateNetworksSchema(PrivateNetworksSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return PrivateNetworks(**data)



