from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class ApplicationProfiles(db.Model):
    __tablename__ = 'ApplicationProfiles'
    ID = db.Column(db.Integer, primary_key=True)
    AppID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    SecretScanReq = db.Column(db.String(1))
    SecretScanData = db.Column(LONGTEXT)
    SCAReq = db.Column(db.String(1))
    SCAData = db.Column(LONGTEXT)
    SASTReq = db.Column(db.String(1))
    SASTData = db.Column(LONGTEXT)
    IACReq = db.Column(db.String(1))
    IACData = db.Column(LONGTEXT)
    ContainerReq = db.Column(db.String(1))
    ContainerData = db.Column(LONGTEXT)
    InfrastructureScanReq = db.Column(db.String(1))
    InfrastructureScanData = db.Column(LONGTEXT)
    DASTReq = db.Column(db.String(1))
    DASTData = db.Column(LONGTEXT)
    DASTApiReq = db.Column(db.String(1))
    DASTApiData = db.Column(LONGTEXT)
    CICDConfigLocations = db.Column(LONGTEXT)
    CICDConfigData = db.Column(LONGTEXT)

    def __init__(self, AppID=None, AddDate=None, SecretScanReq=None, SecretScanData=None, SCAReq=None, SCAData=None, SASTReq=None, SASTData=None, IACReq=None, IACData=None, ContainerReq=None, ContainerData=None, InfrastructureScanReq=None, InfrastructureScanData=None, DASTReq=None, DASTData=None, DASTApiReq=None, DASTApiData=None, CICDConfigLocations=None, CICDConfigData=None, ID=None):
        if ID:
            self.ID = ID
        if AppID:
            self.AppID = AppID
        if AddDate:
            self.AddDate = AddDate
        if SecretScanReq:
            self.SecretScanReq = SecretScanReq
        if SecretScanData:
            self.SecretScanData = SecretScanData
        if SCAReq:
            self.SCAReq = SCAReq
        if SCAData:
            self.SCAData = SCAData
        if SASTReq:
            self.SASTReq = SASTReq
        if SASTData:
            self.SASTData = SASTData
        if IACReq:
            self.IACReq = IACReq
        if IACData:
            self.IACData = IACData
        if ContainerReq:
            self.ContainerReq = ContainerReq
        if ContainerData:
            self.ContainerData = ContainerData
        if InfrastructureScanReq:
            self.InfrastructureScanReq = InfrastructureScanReq
        if InfrastructureScanData:
            self.InfrastructureScanData = InfrastructureScanData
        if DASTReq:
            self.DASTReq = DASTReq
        if DASTData:
            self.DASTData = DASTData
        if DASTApiReq:
            self.DASTApiReq = DASTApiReq
        if DASTApiData:
            self.DASTApiData = DASTApiData
        if CICDConfigLocations:
            self.CICDConfigLocations = CICDConfigLocations
        if CICDConfigData:
            self.CICDConfigData = CICDConfigData

    def __repr__(self):
        return '<ApplicationProfiles(name={self.AppID!r})>'.format(self=self)

class ApplicationProfilesSchema(Schema):
    ID = fields.Int()
    AppID = fields.Int()
    AddDate = fields.Date()
    SecretScanReq = fields.Str()
    SecretScanData = fields.Str()
    SCAReq = fields.Str()
    SCAData = fields.Str()
    SASTReq = fields.Str()
    SASTData = fields.Str()
    IACReq = fields.Str()
    IACData = fields.Str()
    ContainerReq = fields.Str()
    ContainerData = fields.Str()
    InfrastructureScanReq = fields.Str()
    InfrastructureScanData = fields.Str()
    DASTReq = fields.Str()
    DASTData = fields.Str()
    DASTApiReq = fields.Str()
    DASTApiData = fields.Str()
    CICDConfigLocations = fields.Str()
    CICDConfigData = fields.Str()

class MakeApplicationProfilesSchema(ApplicationProfilesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return ApplicationProfiles(**data)

