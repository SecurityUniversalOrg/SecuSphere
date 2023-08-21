from vr import db, app
from marshmallow import Schema, fields, ValidationError
from marshmallow import post_load
from marshmallow.validate import Range
from sqlalchemy.types import TEXT
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class Vulnerabilities(db.Model):
    __table_args__ = {'extend_existing': True}
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
    ApplicationId = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    HostId = db.Column(db.Integer)
    Uri = db.Column(TEXT)
    HtmlMethod = db.Column(db.String(20))
    Param = db.Column(TEXT)
    Attack = db.Column(TEXT)
    Evidence = db.Column(TEXT)
    Solution = db.Column(TEXT)
    VulnerablePackage = db.Column(db.String(300))
    VulnerableFileName = db.Column(TEXT)
    VulnerableFilePath = db.Column(TEXT)
    MitigationDate = db.Column(db.DateTime, index=True)
    Status = db.Column(db.String(300), default='Open-New')
    ScanId = db.Column(db.Integer, db.ForeignKey('VulnerabilityScans.ID', ondelete='CASCADE'))
    InitialScanId = db.Column(db.Integer, db.ForeignKey('VulnerabilityScans.ID', ondelete='CASCADE'))
    SourceType = db.Column(db.String(20))
    VulnerablePackageVersion = db.Column(db.String(100))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<Vulnerabilities(name={self.VulnerabilityName!r})>'.format(self=self)


def validate_integer(value):
    if not isinstance(value, int):
        raise ValidationError("Not a valid integer.")

class VulnerabilitiesSchema(Schema):
    VulnerabilityID = fields.Int()
    VulnerabilityName = fields.Str()
    CVEID = fields.Str()
    CWEID = fields.Str()
    Description = fields.Str()
    ReleaseDate = fields.DateTime()
    Severity = fields.Str()
    Classification = fields.Str()
    Source = fields.Str()
    LastModifiedDate = fields.DateTime()
    ReferenceName = fields.Str()
    ReferenceUrl = fields.Str()
    ReferenceTags = fields.Str()
    AddDate = fields.DateTime()
    SourceCodeFileId = fields.Int(validate=validate_integer)
    SourceCodeFileStartLine = fields.Int(validate=validate_integer)
    SourceCodeFileStartCol = fields.Int(validate=validate_integer)
    SourceCodeFileEndLine = fields.Int(validate=validate_integer)
    SourceCodeFileEndCol = fields.Int(validate=validate_integer)
    DockerImageId = fields.Int()
    ApplicationId = fields.Int()
    HostId = fields.Int()
    Uri = fields.Str()
    HtmlMethod = fields.Str()
    Param = fields.Str()
    Attack = fields.Str()
    Evidence = fields.Str()
    Solution = fields.Str()
    VulnerablePackage = fields.Str()
    VulnerableFileName = fields.Str()
    VulnerableFilePath = fields.Str()
    MitigationDate = fields.DateTime()
    Status = fields.Str()
    ScanId = fields.Int()
    ImageName = fields.Str()
    ImageTag = fields.Str()
    EndpointID = fields.Int()
    ImportedCodeID = fields.Int()
    InitialScanId = fields.Int()
    RepoURL = fields.Str()
    SourceType = fields.Str()
    findings_cnt = fields.Int()
    pkg_name = fields.Str()
    pkg_version = fields.Str()
    ApplicationName = fields.Str()
    ApplicationAcronym = fields.Str()
    cvssV3vectorString = fields.Str()
    cvssV3attackVector = fields.Str()
    cvssV3attackComplexity = fields.Str()
    cvssV3privilegesRequired = fields.Str()
    cvssV3userInteraction = fields.Str()
    cvssV3scope = fields.Str()
    cvssV3confidentialityImpact = fields.Str()
    cvssV3integrityImpact = fields.Str()
    cvssV3availabilityImpact = fields.Str()
    cvssV3baseScore = fields.Number()
    cvssV3baseSeverity = fields.Str()
    cvssV3exploitabilityScore = fields.Number()
    cvssV3impactScore = fields.Number()
    CWEName = fields.Str()
    CWEDescription = fields.Str()
    ModesOfIntroductionPhase = fields.Str()
    ModesOfIntroductionNote = fields.Str()
    CommonConsequencesScope = fields.Str()
    CommonConsequencesImpact = fields.Str()
    DetectionMethodsMethod = fields.Str()
    DetectionMethodsDescription = fields.Str()
    PotentialMitigationsPhase = fields.Str()
    PotentialMitigationsDescription = fields.Str()
    FunctionalAreas = fields.Str()
    AffectedResources = fields.Str()
    TaxonomyMappingsName = fields.Str()
    TaxonomyMappingsEntryName = fields.Str()
    VulnerablePackageVersion = fields.Str()
    KnownExploit = fields.Str()

class MakeVulnerabilitiesSchema(VulnerabilitiesSchema):
    @post_load
    def make_vuln(self, data, **kwargs):
        return Vulnerabilities(**data)



