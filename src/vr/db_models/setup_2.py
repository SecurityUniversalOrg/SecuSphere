from datetime import datetime
from sqlalchemy.types import TEXT, DECIMAL
from sqlalchemy import MetaData
from vr.admin.functions import db_connection_handler
from config_engine import ENV
if ENV == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT
from authlib.integrations.sqla_oauth2 import (
    OAuth2ClientMixin,
    OAuth2AuthorizationCodeMixin,
    OAuth2TokenMixin,
)
from sqlalchemy.dialects import mysql
import time

Integer = mysql.INTEGER
USER_ID = "User.id"
TECH_ID = "Technologies.TechnologyID"
BUSINESS_APP_ID = "BusinessApplications.ID"
VULN_ID = "Vulnerabilities.VulnerabilityID"
IP_ASSETS_ID = "IPAssets.ID"
BENCHMARKS_ID = "AssessmentBenchmarks.ID"
THREAT_ASSESSMENT_ID = "TmThreatAssessments.ID"

def _init_db(db):

    class Technologies(db.Model):
        __tablename__ = 'Technologies'
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        TechnologyID = db.Column(db.Integer)  # Should be IPAssets.ID
        ApplicationID = db.Column(db.Integer)


    AssetApplications()


    class AssetDatabases(db.Model):
        __tablename__ = 'AssetDatabases'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        TechnologyID = db.Column(db.Integer)
        DatabaseID = db.Column(db.Integer)


    AssetDatabases()


    class AssetGroupAsset(db.Model):
        __tablename__ = 'AssetGroupAsset'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AssetGroupID = db.Column(db.Integer)
        TechnologyID = db.Column(db.Integer)


    AssetGroupAsset()


    class AssetGroups(db.Model):
        __tablename__ = 'AssetGroups'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AssetGroupName = db.Column(db.String(60))
        AssetGroupDesc = db.Column(db.String(200))
        RegDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)


    AssetGroups()


    class AssetNetworkServices(db.Model):
        __tablename__ = 'AssetNetworkServices'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AssetID = db.Column(db.Integer)
        ServiceID = db.Column(db.Integer)


    AssetNetworkServices()


    class NetworkServices(db.Model):
        __tablename__ = 'NetworkServices'
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
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


    class WebApplications(db.Model):
        __tablename__ = 'WebApplications'
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        VulnerabilityID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        GeneratedOn = db.Column(db.DateTime, index=True)
        OverallCVSSScore = db.Column(DECIMAL(13, 4))
        CVSSBaseScore = db.Column(DECIMAL(13, 4))
        CVSSTemporalScore = db.Column(DECIMAL(13, 4))
        CVSSEnvironmentalScore = db.Column(DECIMAL(13, 4))
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
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
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
        cvssV3baseScore = db.Column(DECIMAL(13, 4))
        cvssV3baseSeverity = db.Column(db.String(20))
        cvssV3exploitabilityScore = db.Column(DECIMAL(13, 4))
        cvssV3impactScore = db.Column(DECIMAL(13, 4))


    CVSSBaseScoresV3()


    class CVSSBaseScoresV3Extensions(db.Model):
        __tablename__ = 'CVSSBaseScoresV3Extensions'
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        PatchID = db.Column(db.Integer, db.ForeignKey('PatchInfo.ID', ondelete='CASCADE'))
        TechnologyID = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))
        DateOfInstall = db.Column(db.DateTime, index=True)
        PatchStatus = db.Column(db.String(60))
        Priority = db.Column(db.String(30))


    PatchActivity()


    class PatchActivityReview(db.Model):
        __tablename__ = 'PatchActivityReview'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        PatchActivityID = db.Column(db.Integer, db.ForeignKey('PatchActivity.ID', ondelete='CASCADE'))
        ReviewedBy = db.Column(db.String(50))
        Compliant = db.Column(db.String(1))
        PatchEffort = db.Column(db.Integer)


    PatchActivityReview()


    class PatchInfo(db.Model):
        __tablename__ = 'PatchInfo'
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
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


    class VulnerabilityRemediation(db.Model):
        __tablename__ = 'VulnerabilityRemediation'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        VulnerabilityID = db.Column(db.Integer, db.ForeignKey(VULN_ID, ondelete='CASCADE'))
        TechnologyID = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))
        OpenDate = db.Column(db.DateTime, index=True)
        Status = db.Column(db.String(20))
        Priority = db.Column(db.String(20))
        CloseDate = db.Column(db.DateTime, index=True)
        ClosedBy = db.Column(db.String(20))


    VulnerabilityRemediation()


    class VulnerabilityUpdates(db.Model):
        __tablename__ = 'VulnerabilityUpdates'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        UpdateStartDate = db.Column(db.DateTime, index=True)
        UpdateEndDate = db.Column(db.DateTime, index=True)
        NewCveCnt = db.Column(db.Integer)
        UpdatedCveCnt = db.Column(db.DateTime, index=True)
        ScanEndDate = db.Column(db.Integer, db.ForeignKey(TECH_ID, ondelete='CASCADE'))


    VulnerabilityUpdates()


    class GitRepo(db.Model):
        __tablename__ = 'GitRepo'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime)
        Source = db.Column(db.String(30))
        RepoName = db.Column(db.String(100))
        RepoUrl = db.Column(db.String(100))
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))


    GitRepo()


    class PullRequests(db.Model):
        __tablename__ = 'PullRequests'
        __table_args__ = {'extend_existing': True}
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


    class BuildArtifacts(db.Model):
        __tablename__ = 'BuildArtifacts'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        PipelineJobID = db.Column(db.Integer, db.ForeignKey('PipelineJobs.ID', ondelete='CASCADE'))
        ArtifactName = db.Column(db.String(300))
        Url = db.Column(db.String(300))


    BuildArtifacts()


    class ComponentConfigs(db.Model):
        __tablename__ = 'ComponentConfigs'
        __table_args__ = {'extend_existing': True}
        id = db.Column(db.Integer, primary_key=True)
        component_name = db.Column(db.String(100))
        config_key = db.Column(db.String(100))
        config_value = db.Column(db.String(100))


    ComponentConfigs()


    class JobList(db.Model):
        __tablename__ = 'JobList'
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        JobID = db.Column(db.Integer(), db.ForeignKey('JobList.ID', ondelete='CASCADE'))
        EntityID = db.Column(db.Integer())


    JobListPermissions()


    class JobListReportData(db.Model):
        __tablename__ = 'JobListReportData'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        JobID = db.Column(db.Integer(), db.ForeignKey('JobList.ID', ondelete='CASCADE'))
        DataName = db.Column(db.Text)
        DataValue = db.Column(LONGTEXT)


    JobListReportData()


    class CalendarScheduledJobs(db.Model):
        __tablename__ = 'CalendarScheduledJobs'
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        component_name = db.Column(db.String(100))
        grade = db.Column(db.String(3))
        grade_date = db.Column(db.DateTime, index=True)
        key_factors = db.Column(db.String(2000))


    ComponentGrades()


    class ServiceTicketProjects(db.Model):
        __tablename__ = 'ServiceTicketProjects'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer)
        ProjectName = db.Column(db.String(300))
        Source = db.Column(db.String(300))
        SourceID = db.Column(db.Integer)
        ProjectKey = db.Column(db.String(300))
        ProjectType = db.Column(db.String(300))


    ServiceTicketProjects()


    class AppToServerAssociations(db.Model):
        __tablename__ = 'AppToServerAssociations'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        ServerID = db.Column(db.Integer, db.ForeignKey(IP_ASSETS_ID, ondelete='CASCADE'))


    AppToServerAssociations()


    class TmSolutions(db.Model):
        __tablename__ = 'TmSolutions'
        __table_args__ = {'extend_existing': True}
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


    class TmQuestions(db.Model):
        __tablename__ = 'TmQuestions'
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
        ApplicationID = db.Column(db.Integer, db.ForeignKey(BUSINESS_APP_ID, ondelete='CASCADE'))
        ThreatAssessmentID = db.Column(db.Integer, db.ForeignKey(THREAT_ASSESSMENT_ID, ondelete='CASCADE'))
        QuestionID = db.Column(db.Integer, db.ForeignKey('TmQuestions.ID', ondelete='CASCADE'))
        Response = db.Column(LONGTEXT)


    TmAnsweredQuestions()


    class SgConfigSettingsPerJob(db.Model):
        __tablename__ = 'SgConfigSettingsPerJob'
        __table_args__ = {'extend_existing': True}
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
        __table_args__ = {'extend_existing': True}
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


    class AppIntegrations(db.Model):
        __tablename__ = 'AppIntegrations'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AppID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
        IntegrationID = db.Column(db.Integer, db.ForeignKey('Integrations.ID', ondelete='CASCADE'))
        Type = db.Column(db.String(100))
        AppEntity = db.Column(db.String(100))


    AppIntegrations()


    class DockerImageAppPair(db.Model):
        __tablename__ = 'DockerImageAppPair'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        AppID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
        DockerImageID = db.Column(db.Integer, db.ForeignKey('DockerImages.ID', ondelete='CASCADE'))


    DockerImageAppPair()


    db.create_all()
    db_connection_handler(db)