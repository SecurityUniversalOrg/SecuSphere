from datetime import datetime
from sqlalchemy.types import TEXT, DECIMAL
from config_engine import ENV
if ENV == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects import mysql
from flask_login import UserMixin
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
import time


Integer = mysql.INTEGER
USER_ID = "User.id"
TECH_ID = "Technologies.TechnologyID"
BUSINESS_APP_ID = "BusinessApplications.ID"
VULN_ID = "Vulnerabilities.VulnerabilityID"
IP_ASSETS_ID = "IPAssets.ID"
BENCHMARKS_ID = "AssessmentBenchmarks.ID"
THREAT_ASSESSMENT_ID = "TmThreatAssessments.ID"


def _init_db(db=None, app=None):
    if not db:
        db = SQLAlchemy(app)


    class User(UserMixin, db.Model):
        __tablename__ = 'User'
        extend_existing = True
        id = db.Column(db.Integer, primary_key=True)
        is_active = db.Column('is_active', db.Boolean(), nullable=False, server_default='1')
        is_admin = db.Column('is_admin', db.Boolean(), nullable=False, server_default='0')
        is_security = db.Column('is_security', db.Boolean(), nullable=False, server_default='0')
        username = db.Column(db.String(100))
        password = db.Column(db.String(255))
        auth_type = db.Column(db.String(20))
        mfa_enabled = db.Column(db.Boolean(), nullable=False, server_default='0')
        otp_secret = db.Column(db.String(16))
        email = db.Column(db.String(255), nullable=False, unique=True)
        email_confirmed_at = db.Column(db.DateTime())
        first_name = db.Column(db.String(100), nullable=False, server_default='')
        last_name = db.Column(db.String(100), nullable=False, server_default='')
        jobtitle = db.Column(db.String(100))
        dept = db.Column(db.String(100))
        user_type = db.Column(db.String(100))
        avatar_path = db.Column(db.String(100))
        email_updates = db.Column(db.String(1))
        app_updates = db.Column(db.String(1))
        text_updates = db.Column(db.String(1))
        registration_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)
        loc_zipcode = db.Column(db.String(20))
        loc_city = db.Column(db.String(100))
        loc_state = db.Column(db.String(50))
        about_me = db.Column(db.String(2000))
        web_tz = db.Column(db.String(100))
        phone_no = db.Column(db.String(40))
        support_id = db.Column(db.String(50))
        support_key = db.Column(db.String(50))
        support_contact_id = db.Column(db.Integer)
        auth_token = db.Column(db.String(300))
        onboarding_confirmed = db.Column(db.String(1))

        def __repr__(self):
            return '<User {}>'.format(self.username)

    User()

    class UserAPIKeys(db.Model):
        __tablename__ = 'UserAPIKeys'
        ID = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'), nullable=False)
        Name = db.Column(db.String(200))
        Otp = db.Column(db.String(200))
        ApiKey = db.Column(db.String(500))
        RegDate = db.Column(db.DateTime, index=True, nullable=False, default=datetime.utcnow)

    UserAPIKeys()

    class UserStatus(db.Model):
        __tablename__ = 'UserStatus'
        id = db.Column(db.Integer(), primary_key=True)
        status = db.Column(db.String(200))
        user_id = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'), nullable=False)
        update_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    UserStatus()

    # Define the Role data-model
    class UserRoles(db.Model):
        __tablename__ = 'UserRoles'
        id = db.Column(db.Integer(), primary_key=True)
        name = db.Column(db.String(50), unique=True)
        description = db.Column(db.String(200))

    UserRoles()

    # Define the UserRoles association table
    class UserRoleAssignments(db.Model):
        __tablename__ = 'UserRoleAssignments'
        id = db.Column(db.Integer(), primary_key=True)
        user_id = db.Column(db.Integer(), db.ForeignKey(USER_ID, ondelete='CASCADE'))
        role_id = db.Column(db.Integer(), db.ForeignKey('UserRoles.id', ondelete='CASCADE'))

    UserRoleAssignments()

    class AuthAttempts(db.Model):
        __tablename__ = 'AuthAttempts'
        id = db.Column(db.Integer, primary_key=True)
        timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
        user_id = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        username = db.Column(db.String(100))
        success = db.Column(db.Boolean(), nullable=False)

    AuthAttempts()

    class AuthLockouts(db.Model):
        __tablename__ = 'AuthLockouts'
        id = db.Column(db.Integer, primary_key=True)
        timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
        user_id = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        username = db.Column(db.String(100))

    AuthLockouts()

    class Technologies(db.Model):
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

    Technologies()

    class AssetApplications(db.Model):
        __tablename__ = 'AssetApplications'
        ID = db.Column(db.Integer, primary_key=True)
        TechnologyID = db.Column(db.Integer)  # Should be IPAssets.ID
        ApplicationID = db.Column(db.Integer)

    AssetApplications()

    class AssetDatabases(db.Model):
        __tablename__ = 'AssetDatabases'
        ID = db.Column(db.Integer, primary_key=True)
        TechnologyID = db.Column(db.Integer)
        DatabaseID = db.Column(db.Integer)

    AssetDatabases()

    class AssetGroupAsset(db.Model):
        __tablename__ = 'AssetGroupAsset'
        ID = db.Column(db.Integer, primary_key=True)
        AssetGroupID = db.Column(db.Integer)
        TechnologyID = db.Column(db.Integer)

    AssetGroupAsset()

    class AssetGroups(db.Model):
        __tablename__ = 'AssetGroups'
        ID = db.Column(db.Integer, primary_key=True)
        AssetGroupName = db.Column(db.String(60))
        AssetGroupDesc = db.Column(db.String(200))
        RegDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)

    AssetGroups()

    class AssetNetworkServices(db.Model):
        __tablename__ = 'AssetNetworkServices'
        ID = db.Column(db.Integer, primary_key=True)
        AssetID = db.Column(db.Integer)
        ServiceID = db.Column(db.Integer)

    AssetNetworkServices()

    class BusinessApplications(db.Model):
        __tablename__ = 'BusinessApplications'
        ID = db.Column(db.Integer, primary_key=True)
        TechnologyID = db.Column(db.Integer)
        ApplicationName = db.Column(db.String(200), nullable=False)
        Version = db.Column(db.String(40))
        Vendor = db.Column(db.String(40))
        Language = db.Column(db.String(400))
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

    BusinessApplications()

    class IPAssets(db.Model):
        __tablename__ = 'IPAssets'
        ID = db.Column(db.Integer, primary_key=True)
        TechnologyID = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))
        IPAddress = db.Column(db.String(20), nullable=False)
        MacAddress = db.Column(db.String(30))
        Type = db.Column(db.String(50))
        EntityID = db.Column(db.String(80))
        Hostname = db.Column(db.String(80))
        OS = db.Column(db.String(80))
        OSArchitecture = db.Column(db.String(80))
        OSFamily = db.Column(db.String(80))
        OSID = db.Column(db.String(80))
        OSProduct = db.Column(db.String(80))
        OSSystemName = db.Column(db.String(80))
        OSType = db.Column(db.String(80))
        OSVendor = db.Column(db.String(80))
        OSVersion = db.Column(db.String(80))
        Description = db.Column(db.String(100))
        Domain = db.Column(db.String(100))
        Location = db.Column(db.String(30))
        Active = db.Column(db.String(1))
        RegComplete = db.Column(db.String(1))
        RegDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        SubnetID = db.Column(db.Integer, db.ForeignKey('PrivateNetworks.ID', ondelete='CASCADE'))
        Authorized = db.Column(db.Integer)
        OSUpdate = db.Column(db.String(80))
        OSEdition = db.Column(db.String(80))
        OSCPE = db.Column(db.String(200))
        MacVendor = db.Column(db.String(200))
        ServerName = db.Column(db.String(200))
        ComponentID = db.Column(db.String(200))
        Assignment = db.Column(db.String(50))
        Status = db.Column(db.String(50))
        AssetTag = db.Column(db.String(40))
        SerialNumber = db.Column(db.String(200))
        Brand = db.Column(db.String(200))
        Model = db.Column(db.String(200))
        ModelCategory = db.Column(db.String(60))
        AbbreviatedModel = db.Column(db.String(200))
        CPUsPhysical = db.Column(db.Integer)
        CPUsCores = db.Column(db.Integer)
        CPUsHWThreads = db.Column(db.Integer)
        SupportGroup = db.Column(db.String(60))
        LocationCode = db.Column(db.String(30))
        AssetSystem = db.Column(db.String(60))

    IPAssets()

    class NetworkServices(db.Model):
        __tablename__ = 'NetworkServices'
        ID = db.Column(db.Integer, primary_key=True)
        Name = db.Column(db.String(100))
        Port = db.Column(db.String(10))
        Product = db.Column(db.String(100))
        Protocol = db.Column(db.String(10))
        Vendor = db.Column(db.String(100))
        Version = db.Column(db.String(100))
        RegDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)

    NetworkServices()

    class PrivateNetworks(db.Model):
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

    PrivateNetworks()

    class SUDatabases(db.Model):
        __tablename__ = 'SUDatabases'
        ID = db.Column(db.Integer, primary_key=True)
        TechnologyID = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))
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

    SUDatabases()

    class WebApplications(db.Model):
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

    WebApplications()

    class BusinessApplicationWeaknesses(db.Model):
        __tablename__ = 'BusinessApplicationWeaknesses'
        ID = db.Column(db.Integer, primary_key=True)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        TechnologyID = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))
        CWEID = db.Column(db.String(30))
        DiscoveredDate = db.Column(db.DateTime, index=True)
        DiscoveredBy = db.Column(db.String(40))
        Status = db.Column(db.String(30))
        Priority = db.Column(db.String(20))
        Type = db.Column(db.String(50))
        MitigationDate = db.Column(db.DateTime, index=True)
        MitigatedBy = db.Column(db.String(50))

    BusinessApplicationWeaknesses()

    class CVSSBaseScores(db.Model):
        __tablename__ = 'CVSSBaseScores'
        ID = db.Column(db.Integer, primary_key=True)
        VulnerabilityID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        GeneratedOn = db.Column(db.DateTime, index=True)
        OverallCVSSScore = db.Column(DECIMAL(13,4))
        CVSSBaseScore = db.Column(DECIMAL(13,4))
        CVSSTemporalScore = db.Column(DECIMAL(13,4))
        CVSSEnvironmentalScore = db.Column(DECIMAL(13,4))
        AccessVector = db.Column(db.String(10))
        AccessComplexity = db.Column(db.String(10))
        Authentication = db.Column(db.String(10))
        ConfidentialityImpact = db.Column(db.String(10))
        IntegrityImpact = db.Column(db.String(10))
        AvailabilityImpact = db.Column(db.String(10))
        ImpactBias = db.Column(db.String(10))
        CollateralDamagePotential = db.Column(db.String(10))
        TargetDistribution = db.Column(db.String(10))
        Exploitability = db.Column(db.String(10))
        RemediationLevel = db.Column(db.String(10))
        ReportConfidence = db.Column(db.String(10))

    CVSSBaseScores()

    class CVSSBaseScoresV2(db.Model):
        __tablename__ = 'CVSSBaseScoresV2'
        ID = db.Column(db.Integer, primary_key=True)
        VulnerabilityID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        cvssV2vectorString = db.Column(db.String(50))
        cvssV2accessVector = db.Column(db.String(20))
        cvssV2accessComplexity = db.Column(db.String(20))
        cvssV2authentication = db.Column(db.String(20))
        cvssV2confidentialityImpact = db.Column(db.String(20))
        cvssV2integrityImpact = db.Column(db.String(20))
        cvssV2availabilityImpact = db.Column(DECIMAL(13, 4))
        cvssV2baseScore = db.Column(DECIMAL(13, 4))
        cvssV2severity = db.Column(db.String(20))
        cvssV2exploitabilityScore = db.Column(DECIMAL(13, 4))
        cvssV2impactScore = db.Column(DECIMAL(13, 4))
        cvssV2acInsufInfo = db.Column(db.String(5))
        cvssV2obtainAllPrivilege = db.Column(db.String(5))
        cvssV2obtainUserPrivilege = db.Column(db.String(5))
        cvssV2obtainOtherPrivilege = db.Column(db.String(5))
        cvssV2userInteractionRequired = db.Column(db.String(5))

    CVSSBaseScoresV2()

    class CVSSBaseScoresV2Extensions(db.Model):
        __tablename__ = 'CVSSBaseScoresV2Extensions'
        ID = db.Column(db.Integer, primary_key=True)
        VulnerabilityID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        TechnologyID = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))
        cvssV2remediationLevel = db.Column(db.String(30))
        cvssV2reportConfidence = db.Column(db.String(30))
        cvssV2temporalScore = db.Column(DECIMAL(13, 4))
        cvssV2collateralDamagePotential = db.Column(db.String(20))
        cvssV2targetDistribution = db.Column(db.String(20))
        cvssV2confidentialityRequirements = db.Column(db.String(20))
        cvssV2integrityRequirements = db.Column(db.String(20))
        cvssV2availabilityRequirements = db.Column(db.String(20))
        cvssV2environmentalScore = db.Column(DECIMAL(13, 4))
        cvssV2adjustedTemporalScore = db.Column(DECIMAL(13, 4))
        cvssV2adjustedImpactScore = db.Column(DECIMAL(13, 4))

    CVSSBaseScoresV2Extensions()

    class CVSSBaseScoresV3(db.Model):
        __tablename__ = 'CVSSBaseScoresV3'
        ID = db.Column(db.Integer, primary_key=True)
        VulnerabilityID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        cvssV3vectorString = db.Column(db.String(50))
        cvssV3attackVector = db.Column(db.String(20))
        cvssV3attackComplexity = db.Column(db.String(20))
        cvssV3privilegesRequired = db.Column(db.String(20))
        cvssV3userInteraction = db.Column(db.String(20))
        cvssV3scope = db.Column(db.String(20))
        cvssV3confidentialityImpact = db.Column(db.String(20))
        cvssV3integrityImpact = db.Column(db.String(20))
        cvssV3availabilityImpact = db.Column(db.String(20))
        cvssV3baseScore = db.Column(DECIMAL(13,4))
        cvssV3baseSeverity = db.Column(db.String(20))
        cvssV3exploitabilityScore = db.Column(DECIMAL(13, 4))
        cvssV3impactScore = db.Column(DECIMAL(13, 4))

    CVSSBaseScoresV3()

    class CVSSBaseScoresV3Extensions(db.Model):
        __tablename__ = 'CVSSBaseScoresV3Extensions'
        ID = db.Column(db.Integer, primary_key=True)
        VulnerabilityID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        TechnologyID = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))
        cvssV3exploitCodeMaturity = db.Column(db.String(30))
        cvssV3remediationLevel = db.Column(db.String(30))
        cvssV3reportConfidence = db.Column(db.String(30))
        cvssV3confidentialityRequirements = db.Column(db.String(20))
        cvssV3integrityRequirements = db.Column(db.String(20))
        cvssV3availabilityRequirements = db.Column(db.String(20))
        cvssV3temporalScore = db.Column(DECIMAL(13, 4))
        cvssV3environmentalScore = db.Column(DECIMAL(13, 4))
        cvssV3impactScore = db.Column(DECIMAL(13, 4))

    CVSSBaseScoresV3Extensions()

    class IdentifiedVulnerabilities(db.Model):
        __tablename__ = 'IdentifiedVulnerabilities'
        ID = db.Column(db.Integer, primary_key=True)
        TechnologyID = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        VulnerabilityID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        DateOfDetection = db.Column(db.DateTime, index=True)
        DetectionMethod = db.Column(db.String(10))
        ScanID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        VulnerabilityStatus = db.Column(db.String(30))
        StatusDate = db.Column(db.DateTime, index=True)

    IdentifiedVulnerabilities()

    class PatchActivity(db.Model):
        __tablename__ = 'PatchActivity'
        ID = db.Column(db.Integer, primary_key=True)
        PatchID = db.Column(db.Integer, db.ForeignKey('PatchInfo.ID', ondelete='CASCADE'))
        TechnologyID = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))
        DateOfInstall = db.Column(db.DateTime, index=True)
        PatchStatus = db.Column(db.String(60))
        Priority = db.Column(db.String(30))

    PatchActivity()

    class PatchActivityReview(db.Model):
        __tablename__ = 'PatchActivityReview'
        ID = db.Column(db.Integer, primary_key=True)
        PatchActivityID = db.Column(db.Integer, db.ForeignKey('PatchActivity.ID', ondelete='CASCADE'))
        ReviewedBy = db.Column(db.String(50))
        Compliant = db.Column(db.String(1))
        PatchEffort = db.Column(db.Integer)

    PatchActivityReview()

    class PatchInfo(db.Model):
        __tablename__ = 'PatchInfo'
        ID = db.Column(db.Integer, primary_key=True)
        VulnerabilityID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        PatchSource = db.Column(db.String(50))
        PatchName = db.Column(db.String(60))
        CriticalityLevel = db.Column(db.String(10))
        OrgCriticalityLevel = db.Column(db.String(30))
        DateOfNotification = db.Column(db.DateTime, index=True)
        DateOfAvailability = db.Column(db.DateTime, index=True)
        DateOfPatchApproval = db.Column(db.DateTime, index=True)
        PatchType = db.Column(db.String(30))

    PatchInfo()

    class TopProgrammingErrors(db.Model):
        __tablename__ = 'TopProgrammingErrors'
        ID = db.Column(db.Integer, primary_key=True)
        CWEID = db.Column(db.String(20))
        Name = db.Column(db.String(60))
        WeaknessPrevalence = db.Column(db.String(15))
        RemediationCost = db.Column(db.String(10))
        AttackFrequency = db.Column(db.String(10))
        Consequences = db.Column(db.String(25))
        EaseOfDetection = db.Column(db.String(10))
        AttackerAwareness = db.Column(db.String(10))
        Discussion = db.Column(db.String(200))
        Prevention = db.Column(db.String(200))

    TopProgrammingErrors()

    class Vulnerabilities(db.Model):
        __tablename__ = 'Vulnerabilities'
        VulnerabilityID = db.Column(db.Integer, primary_key=True)
        VulnerabilityName = db.Column(db.String(300))
        CVEID = db.Column(db.String(30))
        CWEID = db.Column(db.String(200))
        Description = db.Column(LONGTEXT)
        ReleaseDate = db.Column(db.DateTime, index=True)
        Severity = db.Column(db.String(200))
        Classification = db.Column(db.String(20))
        Source = db.Column(db.String(200))
        LastModifiedDate = db.Column(db.DateTime, index=True)
        ReferenceName = db.Column(TEXT)
        ReferenceUrl = db.Column(TEXT)
        ReferenceTags = db.Column(TEXT)
        AddDate = db.Column(db.DateTime, index=True)
        SourceCodeFileId = db.Column(db.Integer, db.ForeignKey('SourceCodeFile.ID', ondelete='CASCADE'))
        SourceCodeFileStartLine = db.Column(db.Integer)
        SourceCodeFileStartCol = db.Column(db.Integer)
        SourceCodeFileEndLine = db.Column(db.Integer)
        SourceCodeFileEndCol = db.Column(db.Integer)
        DockerImageId = db.Column(db.Integer, db.ForeignKey('DockerImages.ID', ondelete='CASCADE'))
        ApplicationId = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        HostId = db.Column(db.Integer, db.ForeignKey(IP_ASSETS_ID, ondelete='CASCADE'))
        Uri = db.Column(TEXT)
        HtmlMethod = db.Column(db.String(20))
        Param = db.Column(TEXT)
        Attack = db.Column(TEXT)
        Evidence = db.Column(TEXT)
        Solution = db.Column(TEXT)
        VulnerablePackage = db.Column(db.String(300))
        VulnerableFileName = db.Column(TEXT)
        VulnerableFilePath = db.Column(TEXT)
        Status = db.Column(db.String(300), default='Open-New')
        MitigationDate = db.Column(db.DateTime, index=True)
        ScanId = db.Column(db.Integer, db.ForeignKey('VulnerabilityScans.ID', ondelete='CASCADE'))
        InitialScanId = db.Column(db.Integer, db.ForeignKey('VulnerabilityScans.ID', ondelete='CASCADE'))
        SourceType = db.Column(db.String(20))

    Vulnerabilities()

    class VulnerabilityRemediation(db.Model):
        __tablename__ = 'VulnerabilityRemediation'
        ID = db.Column(db.Integer, primary_key=True)
        VulnerabilityID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        TechnologyID = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))
        OpenDate = db.Column(db.DateTime, index=True)
        Status = db.Column(db.String(20))
        Priority = db.Column(db.String(20))
        CloseDate = db.Column(db.DateTime, index=True)
        ClosedBy = db.Column(db.String(20))

    VulnerabilityRemediation()

    class VulnerabilityScans(db.Model):
        __tablename__ = 'VulnerabilityScans'
        ID = db.Column(db.Integer, primary_key=True)
        ScanName = db.Column(db.String(200))
        ScanType = db.Column(db.String(30))
        ScanTargets = db.Column(LONGTEXT)
        ScanStartDate = db.Column(db.DateTime, index=True)
        ScanEndDate = db.Column(db.DateTime, index=True)
        IntegrationID = db.Column(db.Integer)
        ApplicationId = db.Column(db.Integer)
        Branch = db.Column(db.String(200))

    VulnerabilityScans()

    class VulnerabilityUpdates(db.Model):
        __tablename__ = 'VulnerabilityUpdates'
        ID = db.Column(db.Integer, primary_key=True)
        UpdateStartDate = db.Column(db.DateTime, index=True)
        UpdateEndDate = db.Column(db.DateTime, index=True)
        NewCveCnt = db.Column(db.Integer)
        UpdatedCveCnt = db.Column(db.DateTime, index=True)
        ScanEndDate = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))

    VulnerabilityUpdates()

    class PipelineJobs(db.Model):
        __tablename__ = 'PipelineJobs'
        ID = db.Column(db.Integer, primary_key=True)
        StartDate = db.Column(db.DateTime, index=True)
        Status = db.Column(db.String(30))
        Source = db.Column(db.String(30))
        SourceJobId = db.Column(db.Integer)
        ApplicationId = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        BranchName = db.Column(db.String(300))
        BuildNum = db.Column(db.String(300))
        JobName = db.Column(db.String(300))
        Project = db.Column(db.String(300))
        Node = db.Column(db.String(300))
        NodeAssetId = db.Column(db.Integer)
        GitCommit = db.Column(db.String(300))
        GitBranch = db.Column(db.String(300))
        GitUrl = db.Column(db.String(300))
        NodeIp = db.Column(db.String(30))

    PipelineJobs()

    class GitRepo(db.Model):
        __tablename__ = 'GitRepo'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime)
        Source = db.Column(db.String(30))
        RepoName = db.Column(db.String(100))
        RepoUrl = db.Column(db.String(100))
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))

    GitRepo()

    class SourceCodeFile(db.Model):
        __tablename__ = 'SourceCodeFile'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime)
        GitRepoId = db.Column(db.Integer, db.ForeignKey('GitRepo.ID', ondelete='CASCADE'))
        FileName = db.Column(db.String(300))
        FileLocation = db.Column(db.String(300))
        FileType = db.Column(db.String(300))

    SourceCodeFile()

    class DockerImages(db.Model):
        __tablename__ = 'DockerImages'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ImageName = db.Column(db.String(300))
        ImageTag = db.Column(db.String(300))
        ImageId = db.Column(db.String(300))
        AppIdList = db.Column(db.String(3000))

    DockerImages()

    class ReleaseVersions(db.Model):
        __tablename__ = 'ReleaseVersions'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        ReleaseName = db.Column(db.String(300))
        ReleaseDate = db.Column(db.DateTime, nullable=True)
        Description = db.Column(LONGTEXT)
        Source = db.Column(db.String(300))
        SourceID = db.Column(db.Integer)
        Released = db.Column(db.String(1))
        Status = db.Column(db.String(30))
        RetireDate = db.Column(db.DateTime, nullable=True)

    ReleaseVersions()

    class ServiceTickets(db.Model):
        __tablename__ = 'ServiceTickets'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ReleaseID = db.Column(db.Integer)
        TicketName = db.Column(db.String(300))
        Description = db.Column(LONGTEXT)
        Source = db.Column(db.String(300))
        SourceID = db.Column(db.Integer)
        Reporter = db.Column(db.String(300))
        Assignee = db.Column(db.String(300))
        Status = db.Column(db.String(30))
        IssueKey = db.Column(db.String(30))
        AppID = db.Column(db.Integer)

    ServiceTickets()

    class PullRequests(db.Model):
        __tablename__ = 'PullRequests'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ReleaseID = db.Column(db.Integer, db.ForeignKey('ReleaseVersions.ID', ondelete='CASCADE'))
        Name = db.Column(db.String(300))
        Description = db.Column(LONGTEXT)
        Source = db.Column(db.String(300))
        SourceID = db.Column(db.Integer)
        Reporter = db.Column(db.String(300))
        Approvers = db.Column(db.String(300))
        Status = db.Column(db.String(30))

    PullRequests()

    class ImportedCode(db.Model):
        __tablename__ = 'ImportedCode'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        PackageName = db.Column(db.String(300))
        PackageVersion = db.Column(db.String(300))
        ImportMethod = db.Column(db.String(300))
        ImportFile = db.Column(db.String(300))
        Status = db.Column(db.String(30))

    ImportedCode()

    class BuildArtifacts(db.Model):
        __tablename__ = 'BuildArtifacts'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        PipelineJobID = db.Column(db.Integer, db.ForeignKey('PipelineJobs.ID', ondelete='CASCADE'))
        ArtifactName = db.Column(db.String(300))
        Url = db.Column(db.String(300))

    BuildArtifacts()

    class Regulations(db.Model):
        __tablename__ = 'Regulations'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        Regulation = db.Column(db.String(300))
        Acronym = db.Column(db.String(300))
        Jurisdiction = db.Column(db.String(300))
        Category = db.Column(db.String(300))
        Reference = db.Column(db.String(300))
        Description = db.Column(LONGTEXT)

    Regulations()

    class ApplicationRegulations(db.Model):
        __tablename__ = 'ApplicationRegulations'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        RegulationID = db.Column(db.Integer, db.ForeignKey('Regulations.ID', ondelete='CASCADE'))

    ApplicationRegulations()

    class ApplicationEndpoints(db.Model):
        __tablename__ = 'ApplicationEndpoints'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        AssetID = db.Column(db.Integer, db.ForeignKey(IP_ASSETS_ID, ondelete='CASCADE'))
        Endpoint = db.Column(db.String(5000))
        Type = db.Column(db.String(30))

    ApplicationEndpoints()

    class Integrations(db.Model):
        __tablename__ = 'Integrations'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        Name = db.Column(db.String(500))
        Description = db.Column(LONGTEXT)
        Url = db.Column(db.String(500))
        ToolType = db.Column(db.String(100))
        AuthenticationType = db.Column(db.String(100))
        Extras = db.Column(db.String(5000))
        Username = db.Column(db.String(2000))
        Password = db.Column(db.String(1000))
        KeyName = db.Column(db.String(100))
        SSHKey = db.Column(LONGTEXT)
        APIKey = db.Column(LONGTEXT)

    Integrations()

    class CICDPipelines(db.Model):
        __tablename__ = 'CICDPipelines'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        IntegrationID = db.Column(db.Integer, db.ForeignKey('Integrations.ID', ondelete='CASCADE'))
        Name = db.Column(db.String(500))
        Description = db.Column(LONGTEXT)
        Url = db.Column(db.String(500))
        Source = db.Column(db.String(100))

    CICDPipelines()

    class Credentials(db.Model):
        __tablename__ = 'Credentials'
        ID = db.Column(db.Integer, primary_key=True)
        Title = db.Column(db.String(100))
        UserName = db.Column(db.String(100))
        Password = db.Column(LONGTEXT)
        Url = db.Column(db.String(100))
        Notes = db.Column(db.String(200))
        Category = db.Column(db.String(100))
        registration_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)
        PlatformAccountID = db.Column(db.String(100))
        MgmtPolicy = db.Column(db.String(40))
        Password2 = db.Column(LONGTEXT)

    Credentials()

    class ComponentConfigs(db.Model):
        __tablename__ = 'ComponentConfigs'
        id = db.Column(db.Integer, primary_key=True)
        component_name = db.Column(db.String(100))
        config_key = db.Column(db.String(100))
        config_value = db.Column(db.String(100))

    ComponentConfigs()

    class JobList(db.Model):
        __tablename__ = 'JobList'
        ID = db.Column(db.Integer, primary_key=True)
        Name = db.Column(db.String(100))
        StartDate = db.Column(db.DateTime)
        StatusDate = db.Column(db.DateTime)
        StatusPercent = db.Column(Integer(3))
        Status = db.Column(db.String(16))
        FinishDate = db.Column(db.DateTime)
        Category = db.Column(db.String(40))
        Type = db.Column(db.String(60))
        Owner = db.Column(db.String(40))
        TargetType = db.Column(db.String(100))
        TargetList = db.Column(LONGTEXT)

    JobList()

    class JobListPermissions(db.Model):
        __tablename__ = 'JobListPermissions'
        ID = db.Column(db.Integer, primary_key=True)
        JobID = db.Column(db.Integer(), db.ForeignKey('JobList.ID', ondelete='CASCADE'))
        EntityID = db.Column(db.Integer())

    JobListPermissions()

    class JobListReportData(db.Model):
        __tablename__ = 'JobListReportData'
        ID = db.Column(db.Integer, primary_key=True)
        JobID = db.Column(db.Integer(), db.ForeignKey('JobList.ID', ondelete='CASCADE'))
        DataName = db.Column(db.Text)
        DataValue = db.Column(LONGTEXT)

    JobListReportData()

    class CalendarScheduledJobs(db.Model):
        __tablename__ = 'CalendarScheduledJobs'
        id = db.Column(db.Integer, primary_key=True)
        component_name = db.Column(db.String(100))
        job_name = db.Column(db.String(100))
        scheduled_utc_date = db.Column(db.DateTime, index=True)
        status = db.Column(db.String(100))
        status_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)
        evt_id = db.Column(db.Integer)
        target_list = db.Column(LONGTEXT)
        recur_id = db.Column(db.Integer())

    CalendarScheduledJobs()

    class ComponentGrades(db.Model):
        __tablename__ = 'ComponentGrades'
        ID = db.Column(db.Integer, primary_key=True)
        component_name = db.Column(db.String(100))
        grade = db.Column(db.String(3))
        grade_date = db.Column(db.DateTime, index=True)
        key_factors = db.Column(db.String(2000))

    ComponentGrades()

    class ServiceTicketProjects(db.Model):
        __tablename__ = 'ServiceTicketProjects'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer)
        ProjectName = db.Column(db.String(300))
        Source = db.Column(db.String(300))
        SourceID = db.Column(db.Integer)
        ProjectKey = db.Column(db.String(300))
        ProjectType = db.Column(db.String(300))

    ServiceTicketProjects()

    class AssessmentBenchmarks(db.Model):
        __tablename__ = 'AssessmentBenchmarks'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        Name = db.Column(db.String(500))
        Description = db.Column(LONGTEXT)
        Version = db.Column(db.String(50))

    AssessmentBenchmarks()

    class AppAssessmentBenchmarkAssignments(db.Model):
        __tablename__ = 'AppAssessmentBenchmarkAssignments'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        BenchmarkID = db.Column(db.Integer, db.ForeignKey(BENCHMARKS_ID, ondelete='CASCADE'))
        UserID = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        Notes = db.Column(LONGTEXT)
        Type = db.Column(db.String(100))

    AppAssessmentBenchmarkAssignments()

    class AssessmentBenchmarkRules(db.Model):
        __tablename__ = 'AssessmentBenchmarkRules'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        BenchmarkID = db.Column(db.Integer, db.ForeignKey(BENCHMARKS_ID, ondelete='CASCADE'))
        Number = db.Column(db.String(50))
        Description = db.Column(LONGTEXT)
        ImplementationLevels = db.Column(db.String(500))

    AssessmentBenchmarkRules()

    class AssessmentBenchmarkAssessments(db.Model):
        __tablename__ = 'AssessmentBenchmarkAssessments'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        BenchmarkID = db.Column(db.Integer, db.ForeignKey(BENCHMARKS_ID, ondelete='CASCADE'))
        UserID = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        Notes = db.Column(LONGTEXT)
        Type = db.Column(db.String(100))
        TargetLevel = db.Column(db.String(100))
        Status = db.Column(db.String(100))

    AssessmentBenchmarkAssessments()

    class AssessmentBenchmarkRuleAudits(db.Model):
        __tablename__ = 'AssessmentBenchmarkRuleAudits'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        RuleID = db.Column(db.Integer, db.ForeignKey('AssessmentBenchmarkRules.ID', ondelete='CASCADE'))
        AssessmentID = db.Column(db.Integer, db.ForeignKey('AssessmentBenchmarkAssessments.ID', ondelete='CASCADE'))
        PassingLevels = db.Column(db.String(500))

    AssessmentBenchmarkRuleAudits()

    class AssessmentBenchmarkRuleAuditNotes(db.Model):
        __tablename__ = 'AssessmentBenchmarkRuleAuditNotes'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        RuleID = db.Column(db.Integer, db.ForeignKey('AssessmentBenchmarkRules.ID', ondelete='CASCADE'))
        UserID = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        Note = db.Column(LONGTEXT)
        Type = db.Column(db.String(100))

    AssessmentBenchmarkRuleAuditNotes()

    class VulnToolAppPairs(db.Model):
        __tablename__ = 'VulnToolAppPairs'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        ToolID = db.Column(db.Integer, db.ForeignKey('Integrations.ID', ondelete='CASCADE'))
        ToolProjectID = db.Column(db.String(500))
        KeyValuePairs = db.Column(LONGTEXT)

    VulnToolAppPairs()

    class VulnerabilitySLAs(db.Model):
        __tablename__ = 'VulnerabilitySLAs'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        Name = db.Column(db.String(500))
        Description = db.Column(LONGTEXT)
        CriticalSetting = db.Column(db.String(500))
        HighSetting = db.Column(db.String(500))
        MediumSetting = db.Column(db.String(500))
        LowSetting = db.Column(db.String(500))

    VulnerabilitySLAs()

    class VulnerabilitySLAAppPair(db.Model):
        __tablename__ = 'VulnerabilitySLAAppPair'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        SlaID = db.Column(db.Integer, db.ForeignKey('VulnerabilitySLAs.ID', ondelete='CASCADE'))

    VulnerabilitySLAAppPair()

    class AppCodeComposition(db.Model):
        __tablename__ = 'AppCodeComposition'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        JavaFiles = db.Column(db.Integer)
        JavaLoc = db.Column(db.Integer)
        XmlFiles = db.Column(db.Integer)
        XmlLoc = db.Column(db.Integer)
        JsonFiles = db.Column(db.Integer)
        JsonLoc = db.Column(db.Integer)
        YamlFiles = db.Column(db.Integer)
        YamlLoc = db.Column(db.Integer)
        ConfFiles = db.Column(db.Integer)
        ConfLoc = db.Column(db.Integer)
        PythonFiles = db.Column(db.Integer)
        PythonLoc = db.Column(db.Integer)
        PerlFiles = db.Column(db.Integer)
        PerlLoc = db.Column(db.Integer)
        CFiles = db.Column(db.Integer)
        CLoc = db.Column(db.Integer)
        GoFiles = db.Column(db.Integer)
        GoLoc = db.Column(db.Integer)
        JavascriptFiles = db.Column(db.Integer)
        JavascriptLoc = db.Column(db.Integer)
        CSharpFiles = db.Column(db.Integer)
        CSharpLoc = db.Column(db.Integer)
        CppFiles = db.Column(db.Integer)
        CppLoc = db.Column(db.Integer)
        PhpFiles = db.Column(db.Integer)
        PhpLoc = db.Column(db.Integer)
        TypescriptFiles = db.Column(db.Integer)
        TypescriptLoc = db.Column(db.Integer)
        SwiftFiles = db.Column(db.Integer)
        SwiftLoc = db.Column(db.Integer)
        RubyFiles = db.Column(db.Integer)
        RubyLoc = db.Column(db.Integer)
        KotlinFiles = db.Column(db.Integer)
        KotlinLoc = db.Column(db.Integer)
        DartFiles = db.Column(db.Integer)
        DartLoc = db.Column(db.Integer)
        ScalaFiles = db.Column(db.Integer)
        ScalaLoc = db.Column(db.Integer)
        ShellFiles = db.Column(db.Integer)
        ShellLoc = db.Column(db.Integer)
        RFiles = db.Column(db.Integer)
        RLoc = db.Column(db.Integer)
        LuaFiles = db.Column(db.Integer)
        LuaLoc = db.Column(db.Integer)
        GroovyFiles = db.Column(db.Integer)
        GroovyLoc = db.Column(db.Integer)
        RustFiles = db.Column(db.Integer)
        RustLoc = db.Column(db.Integer)
        MatlabFiles = db.Column(db.Integer)
        MatlabLoc = db.Column(db.Integer)
        JuliaFiles = db.Column(db.Integer)
        JuliaLoc = db.Column(db.Integer)
        FortranFiles = db.Column(db.Integer)
        FortranLoc = db.Column(db.Integer)
        ObjCFiles = db.Column(db.Integer)
        ObjCLoc = db.Column(db.Integer)
        ElixirFiles = db.Column(db.Integer)
        ElixirLoc = db.Column(db.Integer)
        HaskellFiles = db.Column(db.Integer)
        HaskellLoc = db.Column(db.Integer)
        ElmFiles = db.Column(db.Integer)
        ElmLoc = db.Column(db.Integer)
        FSharpFiles = db.Column(db.Integer)
        FSharpLoc = db.Column(db.Integer)
        ClojureFiles = db.Column(db.Integer)
        ClojureLoc = db.Column(db.Integer)
        CobolFiles = db.Column(db.Integer)
        CobolLoc = db.Column(db.Integer)

    AppCodeComposition()

    class AppToAppAssociations(db.Model):
        __tablename__ = 'AppToAppAssociations'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        AppIDA = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        DependencyDirection = db.Column(db.String(100))
        DrCriticalDependency = db.Column(db.Integer)
        AppIDB = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))

    AppToAppAssociations()

    class AppToServersAndClusters(db.Model):
        __tablename__ = 'AppToServersAndClusters'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        SoxCriticalDependency = db.Column(db.Integer)
        DrCriticalDependency = db.Column(db.Integer)
        EnvAssociation = db.Column(db.String(30))
        ServerID = db.Column(db.Integer, db.ForeignKey(IP_ASSETS_ID, ondelete='CASCADE'))

    AppToServersAndClusters()

    class SupportContacts(db.Model):
        __tablename__ = 'SupportContacts'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        Assignment = db.Column(db.String(30))
        CUID = db.Column(db.String(12))
        Name = db.Column(db.String(300))
        Email = db.Column(db.String(300))
        Role = db.Column(db.String(100))

    SupportContacts()

    class AppToSupportContactAssociations(db.Model):
        __tablename__ = 'AppToSupportContactAssociations'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        SupportContactID = db.Column(db.Integer, db.ForeignKey('SupportContacts.ID', ondelete='CASCADE'))

    AppToSupportContactAssociations()

    class AppToServerAssociations(db.Model):
        __tablename__ = 'AppToServerAssociations'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        ServerID = db.Column(db.Integer, db.ForeignKey(IP_ASSETS_ID, ondelete='CASCADE'))

    AppToServerAssociations()

    class DbToAppAssociations(db.Model):
        __tablename__ = 'DbToAppAssociations'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        DatabaseID = db.Column(db.Integer, db.ForeignKey('SUDatabases.ID', ondelete='CASCADE'))
        Environment = db.Column(db.String(100))

    DbToAppAssociations()

    class IssueNotes(db.Model):
        __tablename__ = 'IssueNotes'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        VulnerabilityID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        UserID = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        Private = db.Column(db.Integer)
        Note = db.Column(LONGTEXT)

    IssueNotes()

    class TmThreatAssessments(db.Model):
        __tablename__ = 'TmThreatAssessments'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        SubmitUserID = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        Status = db.Column(db.String(30))

    TmThreatAssessments()

    class TmThreats(db.Model):
        __tablename__ = 'TmThreats'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        Target = db.Column(db.String(100))
        Description = db.Column(LONGTEXT)
        Details = db.Column(LONGTEXT)
        LikelihoodOfAttack = db.Column(db.String(30))
        Severity = db.Column(db.String(30))
        cCondition = db.Column(LONGTEXT)
        Prerequisites = db.Column(LONGTEXT)
        Mitigations = db.Column(LONGTEXT)
        Example = db.Column(LONGTEXT)
        rReferences = db.Column(LONGTEXT)

    TmThreats()

    class TmIdentifiedThreats(db.Model):
        __tablename__ = 'TmIdentifiedThreats'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        ThreatAssessmentID = db.Column(db.Integer, db.ForeignKey(THREAT_ASSESSMENT_ID, ondelete='CASCADE'))
        ThreatID = db.Column(db.Integer, db.ForeignKey('TmThreats.ID', ondelete='CASCADE'))

    TmIdentifiedThreats()

    class TmControls(db.Model):
        __tablename__ = 'TmControls'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        Control = db.Column(LONGTEXT)
        Type = db.Column(db.String(8))
        Description = db.Column(LONGTEXT)
        Lambda = db.Column(db.String(1))
        Process = db.Column(db.String(1))
        Server = db.Column(db.String(1))
        Dataflow = db.Column(db.String(1))
        Datastore = db.Column(db.String(1))
        ExternalEntity = db.Column(db.String(1))

    TmControls()

    class TmIdentifiedControls(db.Model):
        __tablename__ = 'TmIdentifiedControls'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        ThreatAssessmentID = db.Column(db.Integer, db.ForeignKey(THREAT_ASSESSMENT_ID, ondelete='CASCADE'))
        ControlID = db.Column(db.Integer, db.ForeignKey('TmControls.ID', ondelete='CASCADE'))

    TmIdentifiedControls()

    class TmSolutions(db.Model):
        __tablename__ = 'TmSolutions'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        Targets = db.Column(db.String(60))
        Attributes = db.Column(LONGTEXT)
        Description = db.Column(LONGTEXT)
        FixType = db.Column(db.String(100))
        Fix = db.Column(LONGTEXT)
        Solution = db.Column(LONGTEXT)
        Validation = db.Column(db.String(100))

    TmSolutions()

    class TmIdentifiedSolutions(db.Model):
        __tablename__ = 'TmIdentifiedSolutions'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        ThreatAssessmentID = db.Column(db.Integer, db.ForeignKey(THREAT_ASSESSMENT_ID, ondelete='CASCADE'))
        SolutionID = db.Column(db.Integer, db.ForeignKey('TmSolutions.ID', ondelete='CASCADE'))

    TmIdentifiedSolutions()

    class TmQuestions(db.Model):
        __tablename__ = 'TmQuestions'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        Question = db.Column(LONGTEXT)
        Condition = db.Column(LONGTEXT)
        Options = db.Column(LONGTEXT)
        Type = db.Column(db.String(100))
        Prereqs = db.Column(LONGTEXT)
        Targets = db.Column(db.String(100))
        Produces = db.Column(db.String(100))

    TmQuestions()

    class TmAnsweredQuestions(db.Model):
        __tablename__ = 'TmAnsweredQuestions'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        ThreatAssessmentID = db.Column(db.Integer, db.ForeignKey(THREAT_ASSESSMENT_ID, ondelete='CASCADE'))
        QuestionID = db.Column(db.Integer, db.ForeignKey('TmQuestions.ID', ondelete='CASCADE'))
        Response = db.Column(LONGTEXT)

    TmAnsweredQuestions()

    class EntityPermissions(db.Model):
        __tablename__ = 'EntityPermissions'
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        UserID = db.Column(db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        EntityType = db.Column(db.String(100))
        EntityID = db.Column(db.String(100))

    EntityPermissions()

    class OAuth2Client(db.Model, OAuth2ClientMixin):
        __tablename__ = 'oauth2_client'

        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        user = db.relationship('User')

    OAuth2Client()

    class OAuth2AuthorizationCode(db.Model, OAuth2AuthorizationCodeMixin):
        __tablename__ = 'oauth2_code'

        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        user = db.relationship('User')

    OAuth2AuthorizationCode()

    class OAuth2Token(db.Model, OAuth2TokenMixin):
        __tablename__ = 'oauth2_token'

        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(
            db.Integer, db.ForeignKey(USER_ID, ondelete='CASCADE'))
        user = db.relationship('User')

        def is_refresh_token_active(self):
            if self.revoked:
                return False
            expires_at = self.issued_at + self.expires_in * 2
            return expires_at >= time.time()

    OAuth2Token()

    class AppConfig(db.Model):
        __tablename__ = 'AppConfig'
        id = db.Column(db.Integer, primary_key=True)
        first_access = db.Column(db.Boolean, nullable=False, default=True)

    AppConfig()

    class SgConfigSettingsPerJob(db.Model):
        __tablename__ = 'SgConfigSettingsPerJob'
        ID = db.Column(db.Integer, primary_key=True)
        AppID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
        PipelineJobID = db.Column(db.Integer, db.ForeignKey('PipelineJobs.ID', ondelete='CASCADE'))
        ThreshScaLow = db.Column(db.Integer)
        ThreshScaMedium = db.Column(db.Integer)
        ThreshScaHigh = db.Column(db.Integer)
        ThreshScaCritical = db.Column(db.Integer)
        ThreshContainerLow = db.Column(db.Integer)
        ThreshContainerMedium = db.Column(db.Integer)
        ThreshContainerHigh = db.Column(db.Integer)
        ThreshContainerCritical = db.Column(db.Integer)
        ThreshDastLow = db.Column(db.Integer)
        ThreshDastMedium = db.Column(db.Integer)
        ThreshDastHigh = db.Column(db.Integer)
        ThreshDastCritical = db.Column(db.Integer)
        ThreshDastApiLow = db.Column(db.Integer)
        ThreshDastApiMedium = db.Column(db.Integer)
        ThreshDastApiHigh = db.Column(db.Integer)
        ThreshDastApiCritical = db.Column(db.Integer)
        ThreshInfrastructureLow = db.Column(db.Integer)
        ThreshInfrastructureMedium = db.Column(db.Integer)
        ThreshInfrastructureHigh = db.Column(db.Integer)
        ThreshInfrastructureCritical = db.Column(db.Integer)
        ThreshSastLow = db.Column(db.Integer)
        ThreshSastMedium = db.Column(db.Integer)
        ThreshSastHigh = db.Column(db.Integer)
        ThreshSastCritical = db.Column(db.Integer)
        ThreshIacLow = db.Column(db.Integer)
        ThreshIacMedium = db.Column(db.Integer)
        ThreshIacHigh = db.Column(db.Integer)
        ThreshIacCritical = db.Column(db.Integer)
        ThreshSecretsLow = db.Column(db.Integer)
        ThreshSecretsMedium = db.Column(db.Integer)
        ThreshSecretsHigh = db.Column(db.Integer)
        ThreshSecretsCritical = db.Column(db.Integer)

    SgConfigSettingsPerJob()

    class SgResultsPerJob(db.Model):
        __tablename__ = 'SgResultsPerJob'
        ID = db.Column(db.Integer, primary_key=True)
        AppID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
        PipelineJobID = db.Column(db.Integer, db.ForeignKey('PipelineJobs.ID', ondelete='CASCADE'))
        ResultScaLow = db.Column(db.Integer)
        ResultScaMedium = db.Column(db.Integer)
        ResultScaHigh = db.Column(db.Integer)
        ResultScaCritical = db.Column(db.Integer)
        ResultContainerLow = db.Column(db.Integer)
        ResultContainerMedium = db.Column(db.Integer)
        ResultContainerHigh = db.Column(db.Integer)
        ResultContainerCritical = db.Column(db.Integer)
        ResultDastLow = db.Column(db.Integer)
        ResultDastMedium = db.Column(db.Integer)
        ResultDastHigh = db.Column(db.Integer)
        ResultDastCritical = db.Column(db.Integer)
        ResultDastApiLow = db.Column(db.Integer)
        ResultDastApiMedium = db.Column(db.Integer)
        ResultDastApiHigh = db.Column(db.Integer)
        ResultDastApiCritical = db.Column(db.Integer)
        ResultInfrastructureLow = db.Column(db.Integer)
        ResultInfrastructureMedium = db.Column(db.Integer)
        ResultInfrastructureHigh = db.Column(db.Integer)
        ResultInfrastructureCritical = db.Column(db.Integer)
        ResultSastLow = db.Column(db.Integer)
        ResultSastMedium = db.Column(db.Integer)
        ResultSastHigh = db.Column(db.Integer)
        ResultSastCritical = db.Column(db.Integer)
        ResultIacLow = db.Column(db.Integer)
        ResultIacMedium = db.Column(db.Integer)
        ResultIacHigh = db.Column(db.Integer)
        ResultIacCritical = db.Column(db.Integer)
        ResultSecretsLow = db.Column(db.Integer)
        ResultSecretsMedium = db.Column(db.Integer)
        ResultSecretsHigh = db.Column(db.Integer)
        ResultSecretsCritical = db.Column(db.Integer)

    SgResultsPerJob()

    class SuSiteConfiguration(db.Model):
        __tablename__ = 'SuSiteConfiguration'
        id = db.Column(db.Integer, primary_key=True)
        setting_name = db.Column(db.String(100))
        setting_key = db.Column(db.String(100))
        setting_value = db.Column(db.String(100))
        update_date = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    SuSiteConfiguration()

    class AppIntegrations(db.Model):
        __tablename__ = 'AppIntegrations'
        ID = db.Column(db.Integer, primary_key=True)
        AppID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
        IntegrationID = db.Column(db.Integer, db.ForeignKey('Integrations.ID', ondelete='CASCADE'))
        Type = db.Column(db.String(100))
        AppEntity = db.Column(db.String(100))

    AppIntegrations()

    class DockerImageAppPair(db.Model):
        __tablename__ = 'DockerImageAppPair'
        ID = db.Column(db.Integer, primary_key=True)
        AppID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
        DockerImageID = db.Column(db.Integer, db.ForeignKey('DockerImages.ID', ondelete='CASCADE'))

    DockerImageAppPair()

    class Messages(db.Model):
        __tablename__ = 'Messages'
        ID = db.Column(db.Integer, primary_key=True)
        SenderUserId = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'))
        ReceiverUserId = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'))
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        MessageType = db.Column(db.String(100))
        EntityType = db.Column(db.String(100))
        EntityID = db.Column(db.Integer)
        Message = db.Column(LONGTEXT)

    Messages()

    class MessagesStatus(db.Model):
        __tablename__ = 'MessagesStatus'
        ID = db.Column(db.Integer, primary_key=True)
        MessageId = db.Column(db.Integer, db.ForeignKey('Messages.ID', ondelete='CASCADE'))
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        Status = db.Column(db.String(100))
        UserId = db.Column(db.Integer, db.ForeignKey('User.id', ondelete='CASCADE'))

    MessagesStatus()

    db.create_all()
    db.session.commit()
