from datetime import datetime
from sqlalchemy.types import TEXT, DECIMAL
from sqlalchemy import MetaData
from vr.admin.functions import db_connection_handler
from vr import app
if app.config['ENV'] == 'test':
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
        RegDate = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


    Technologies()


    class AssetApplications(db.Model):
        __tablename__ = 'AssetApplications'
        __table_args__ = {'extend_existing': True}
        ID = db.Column(db.Integer, primary_key=True)
        TechnologyID = db.Column(db.Integer)  # Should be IPAssets.ID
        ApplicationID = db.Column(db.Integer)


    AssetApplications()


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
        __table_args__ = {'extend_existing': True}
        __tablename__ = 'VulnerabilityUpdates'
        ID = db.Column(db.Integer, primary_key=True)
        UpdateStartDate = db.Column(db.DateTime, index=True)
        UpdateEndDate = db.Column(db.DateTime, index=True)
        NewCveCnt = db.Column(db.Integer)
        UpdatedCveCnt = db.Column(db.Integer)
        ScanEndDate = db.Column(db.DateTime, index=True)


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