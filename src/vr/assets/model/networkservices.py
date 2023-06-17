from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class NetworkServices(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'NetworkServices'
    ID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(100))
    Port = db.Column(db.String(10))
    Product = db.Column(db.String(100))
    Protocol = db.Column(db.String(10))
    Vendor = db.Column(db.String(100))
    Version = db.Column(db.String(100))
    RegDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<NetworkServices(name={self.Name!r})>'.format(self=self)


class NetworkServicesSchema(Schema):
    ID = fields.Int()
    Name = fields.Str()
    Port = fields.Str()
    Product = fields.Str()
    Protocol = fields.Str()
    Vendor = fields.Str()
    Version = fields.Str()
    RegDate = fields.DateTime()


class MakeNetworkServicesSchema(NetworkServicesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return NetworkServices(**data)



