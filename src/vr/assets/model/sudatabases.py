from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class SUDatabases(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'SUDatabases'
    ID = db.Column(db.Integer, primary_key=True)
    TechnologyID = db.Column(db.Integer, db.ForeignKey('Technologies.TechnologyID', ondelete='CASCADE'))
    DatabaseName = db.Column(db.String(200), nullable=False)
    Vendor = db.Column(db.String(40))
    DatabaseValue = db.Column(db.String(20))
    Owner = db.Column(db.String(40))
    Custodian = db.Column(db.String(40))
    Hosting = db.Column(db.String(20))
    Description = db.Column(db.String(100))
    PHI = db.Column(db.String(3))
    PII = db.Column(db.String(3))
    PCI = db.Column(db.String(3))
    MiscCustomerData = db.Column(db.String(3))
    HostSystem = db.Column(db.String(40))
    RegDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    NetworkConnector = db.Column(db.String(40))
    DatabaseHostname = db.Column(db.String(200))
    Assignment = db.Column(db.String(100))
    AssignmentChanged = db.Column(db.DateTime, index=True)
    Status = db.Column(db.String(60))
    AssetTag = db.Column(db.String(30))
    DbInstanceName = db.Column(db.String(100))
    DbServiceName = db.Column(db.String(100))
    DbType = db.Column(db.String(100))
    DbVersion = db.Column(db.String(60))
    FNMSDiscoveredVer = db.Column(db.String(60))
    DbPatchInstall = db.Column(db.String(60))
    DbPatchLevel = db.Column(db.String(60))
    ServersDbInstalledOn = db.Column(db.String(200))
    MalAppsOwningDb = db.Column(db.String(200))
    HighestCriticality = db.Column(db.String(200))
    RoadmapCompliance = db.Column(db.String(200))
    AssetSystem = db.Column(db.String(40))
    SupportabilityLevelDb = db.Column(db.String(20))
    SupportabilityLevelDbEoslDate = db.Column(db.DateTime, index=True)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<SUDatabases(name={self.TechnologyID!r})>'.format(self=self)

class SUDatabasesSchema(Schema):
    ID = fields.Int()
    TechnologyID = fields.Int()
    DatabaseName = fields.Str()
    Vendor = fields.Str()
    DatabaseValue = fields.Str()
    Owner = fields.Str()
    Custodian = fields.Str()
    Hosting = fields.Str()
    Description = fields.Str()
    PHI = fields.Str()
    PII = fields.Str()
    PCI = fields.Str()
    MiscCustomerData = fields.Str()
    HostSystem = fields.Str()
    RegDate = fields.DateTime()
    NetworkConnector = fields.Str()
    DatabaseHostname = fields.Str()
    Assignment = fields.Str()
    AssignmentChanged = fields.DateTime()
    Status = fields.Str()
    AssetTag = fields.Str()
    DbInstanceName = fields.Str()
    DbServiceName = fields.Str()
    DbType = fields.Str()
    DbVersion = fields.Str()
    FNMSDiscoveredVer = fields.Str()
    DbPatchInstall = fields.Str()
    DbPatchLevel = fields.Str()
    ServersDbInstalledOn = fields.Str()
    MalAppsOwningDb = fields.Str()
    HighestCriticality = fields.Str()
    RoadmapCompliance = fields.Str()
    AssetSystem = fields.Str()
    SupportabilityLevelDb = fields.Str()
    SupportabilityLevelDbEoslDate = fields.DateTime()

class MakeSUDatabasesSchema(SUDatabasesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return SUDatabases(**data)



