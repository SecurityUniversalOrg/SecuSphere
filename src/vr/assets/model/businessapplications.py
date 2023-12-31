from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class BusinessApplications(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'BusinessApplications'
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
    Description = db.Column(LONGTEXT)
    PHI = db.Column(db.String(3))
    PII = db.Column(db.String(3))
    PCI = db.Column(db.String(3))
    MiscCustomerData = db.Column(db.String(3))
    Type = db.Column(db.String(40))
    RegDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    Edition = db.Column(db.String(40))
    WebEnabled = db.Column(db.String(3))
    ApplicationURL = db.Column(db.String(200))
    RepoURL = db.Column(db.String(200))
    ApplicationType = db.Column(db.String(40))
    ProductType = db.Column(db.String(40))
    Lifecycle = db.Column(db.String(40))
    Origin = db.Column(db.String(40))
    UserRecords = db.Column(db.String(40))
    Revenue = db.Column(db.String(40))
    SysgenID = db.Column(db.String(40))
    ApplicationAcronym = db.Column(db.String(100))
    LctlAppID = db.Column(db.String(80))
    Assignment = db.Column(db.String(40))
    AssignmentChangedDate = db.Column(db.DateTime, index=True, nullable=False)
    LifecycleStatus = db.Column(db.String(80))
    Disposition = db.Column(db.String(40))
    TAWG = db.Column(db.String(100))
    Criticality = db.Column(db.String(20))
    PrioritizedForStability = db.Column(db.String(1))
    BiaCritical = db.Column(db.String(1))
    SoxCritical = db.Column(db.String(1))
    Region = db.Column(db.String(20))
    HostingPlatform = db.Column(db.String(100))
    PrimaryLob = db.Column(db.String(40))
    UsedByMultipleLob = db.Column(db.String(40))
    MalListingAddDate = db.Column(db.DateTime, index=True, nullable=False)
    PreprodDate = db.Column(db.DateTime, index=True)
    ProductionDate = db.Column(db.DateTime, index=True)
    RetirementDate = db.Column(db.DateTime, index=True)
    TargetRetirementDate = db.Column(db.DateTime, index=True)
    AppSupportType = db.Column(db.String(10))
    BusinessImpactDesc = db.Column(LONGTEXT)
    WorkaroundDesc = db.Column(LONGTEXT)
    AssetSystem = db.Column(db.String(20))
    LogicalAccessControlUrl = db.Column(db.String(200))
    MalAddReason = db.Column(db.String(100))
    MalAddReasonDetails = db.Column(LONGTEXT)
    SupportEngApprReq = db.Column(db.String(1))
    QaActivelyTested = db.Column(db.String(1))
    PrimaryProdUrl = db.Column(db.String(200))
    AppMetricCat = db.Column(db.String(100))
    OfficialBusinessRecord = db.Column(db.String(100))
    RetentionPeriod = db.Column(db.String(40))
    SubjectToLegalHold = db.Column(db.String(1))
    EmployeeData = db.Column(db.String(1))
    UserAccessRestrictions = db.Column(db.String(30))
    UserAccessControl = db.Column(db.String(30))
    PMUCNUSGOVT = db.Column(db.String(1))
    RopaExists = db.Column(db.String(40))
    AccountProvisionAndDeprovision = db.Column(db.String(60))
    AccountProvisionSupportGrp = db.Column(db.String(200))
    CicdStatus = db.Column(db.String(40))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<BusinessApplications(name={self.TechnologyID!r})>'.format(self=self)


class BusinessApplicationsSchema(Schema):
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
    RepoURL = fields.Str()
    ApplicationType = fields.Str()
    ProductType = fields.Str()
    Lifecycle = fields.Str()
    Origin = fields.Str()
    UserRecords = fields.Str()
    Revenue  = fields.Str()
    SysgenID = fields.Str()
    ApplicationAcronym = fields.Str()
    LctlAppID = fields.Str()
    Assignment = fields.Str()
    AssignmentChangedDate = fields.DateTime()
    LifecycleStatus = fields.Str()
    Disposition = fields.Str()
    TAWG = fields.Str()
    Criticality = fields.Str()
    PrioritizedForStability = fields.Str()
    BiaCritical = fields.Str()
    SoxCritical = fields.Str()
    Region = fields.Str()
    HostingPlatform = fields.Str()
    PrimaryLob = fields.Str()
    UsedByMultipleLob = fields.Str()
    MalListingAddDate = fields.DateTime()
    PreprodDate = fields.DateTime()
    ProductionDate = fields.DateTime()
    RetirementDate = fields.DateTime()
    TargetRetirementDate = fields.DateTime()
    AppSupportType = fields.Str()
    BusinessImpactDesc = fields.Str()
    WorkaroundDesc = fields.Str()
    AssetSystem = fields.Str()
    LogicalAccessControlUrl = fields.Str()
    MalAddReason = fields.Str()
    MalAddReasonDetails = fields.Str()
    SupportEngApprReq = fields.Str()
    QaActivelyTested = fields.Str()
    PrimaryProdUrl = fields.Str()
    AppMetricCat = fields.Str()
    OfficialBusinessRecord = fields.Str()
    RetentionPeriod = fields.Str()
    SubjectToLegalHold = fields.Str()
    EmployeeData = fields.Str()
    UserAccessRestrictions = fields.Str()
    UserAccessControl = fields.Str()
    PMUCNUSGOVT = fields.Str()
    RopaExists = fields.Str()
    AccountProvisionAndDeprovision = fields.Str()
    AccountProvisionSupportGrp = fields.Str()
    CicdStatus = fields.Str()

class MakeBusinessApplicationsSchema(BusinessApplicationsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return BusinessApplications(**data)



