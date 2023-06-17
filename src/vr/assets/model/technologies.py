from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class Technologies(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'Technologies'
    TechnologyID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String(200))
    Part = db.Column(db.String(20))
    Vendor = db.Column(db.String(20))
    Product = db.Column(db.String(20))
    Version = db.Column(db.String(20))
    UpdateVer = db.Column(db.String(20))
    Edition = db.Column(db.String(20))
    Language = db.Column(db.String(20))
    TechnologyValue = db.Column(db.String(20))
    BusinessUnit = db.Column(db.String(20))
    Owner = db.Column(db.String(50))
    Custodian = db.Column(db.String(50))
    Classification = db.Column(db.String(20))
    UniqueID = db.Column(db.String(200))
    UniqueIDType = db.Column(db.String(20))
    Description = db.Column(db.String(200))
    RegComplete = db.Column(db.String(1))
    RegDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)


    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<Technologies(name={self.TechnologyID!r})>'.format(self=self)


class TechnologiesSchema(Schema):
    TechnologyID = fields.Int()
    Name = fields.Str()
    Part = fields.Str()
    Vendor = fields.Str()
    Product = fields.Str()
    Version = fields.Str()
    UpdateVer = fields.Str()
    Edition = fields.Str()
    Language = fields.Str()
    TechnologyValue = fields.Str()
    BusinessUnit = fields.Str()
    Owner = fields.Str()
    Custodian = fields.Str()
    Classification = fields.Str()
    UniqueID = fields.Str()
    UniqueIDType = fields.Str()
    Description = fields.Str()
    RegComplete = fields.Str()
    RegDate = fields.DateTime()


class MakeTechnologiesSchema(TechnologiesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return Technologies(**data)



