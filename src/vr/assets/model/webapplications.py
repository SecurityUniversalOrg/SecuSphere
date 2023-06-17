from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class WebApplications(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'WebApplications'
    ID = db.Column(db.Integer, primary_key=True)
    TechnologyID = db.Column(db.Integer)
    ApplicationName = db.Column(db.String(200), nullable=False)
    Version = db.Column(db.String(40))
    Vendor = db.Column(db.String(40))
    Language = db.Column(db.String(40))
    InHouseDev = db.Column(db.Integer)
    VendorDev = db.Column(db.Integer)
    Customization = db.Column(db.Integer)
    DatabaseName = db.Column(db.String(40))
    AppValue = db.Column(db.String(20))
    Owner = db.Column(db.String(40))
    Custodian = db.Column(db.String(40))
    Hosting = db.Column(db.String(20))
    Description = db.Column(db.String(100))
    PHI = db.Column(db.String(3))
    PII = db.Column(db.String(3))
    PCI = db.Column(db.String(3))
    MiscCustomerData = db.Column(db.String(3))
    Type = db.Column(db.String(40))
    RegDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    Edition = db.Column(db.String(40))
    WebEnabled = db.Column(db.String(3))
    ApplicationURL = db.Column(db.String(200), nullable=False)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<WebApplications(name={self.TechnologyID!r})>'.format(self=self)


class WebApplicationsSchema(Schema):
    ID = fields.Int()
    TechnologyID = fields.Int()
    ApplicationName = fields.Str()
    Version = fields.Str()
    Vendor = fields.Str()
    Language = fields.Str()
    InHouseDev = fields.Int()
    VendorDev = fields.Int()
    Customization = fields.Int()
    DatabaseName = fields.Str()
    AppValue = fields.Str()
    Owner = fields.Str()
    Custodian = fields.Str()
    Hosting = fields.Str()
    Description = fields.Str()
    PHI = fields.Str()
    PII = fields.Str()
    PCI = fields.Str()
    MiscCustomerData = fields.Str()
    Type = fields.Str()
    RegDate = fields.DateTime()
    Edition = fields.Str()
    WebEnabled = fields.Str()
    ApplicationURL = fields.Str()


class MakeWebApplicationsSchema(WebApplicationsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return WebApplications(**data)



