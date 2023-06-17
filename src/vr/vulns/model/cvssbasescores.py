from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
from sqlalchemy.types import DECIMAL



class CVSSBaseScores(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'CVSSBaseScores'
    ID = db.Column(db.Integer, primary_key=True)
    VulnerabilityID = db.Column(db.Integer, db.ForeignKey('Vulnerabilities.VulnerabilityID', ondelete='CASCADE'))
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

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<CVSSBaseScores(name={self.VulnerabilityID!r})>'.format(self=self)


class CVSSBaseScoresSchema(Schema):
    ID = fields.Int()
    VulnerabilityID = fields.Int()
    GeneratedOn = fields.DateTime()
    OverallCVSSScore = fields.Number()
    CVSSBaseScore = fields.Number()
    CVSSTemporalScore = fields.Number()
    CVSSEnvironmentalScore = fields.Number()
    AccessVector = fields.Str()
    AccessComplexity = fields.Str()
    Authentication = fields.Str()
    ConfidentialityImpact = fields.Str()
    IntegrityImpact = fields.Str()
    AvailabilityImpact = fields.Str()
    ImpactBias = fields.Str()
    CollateralDamagePotential = fields.Str()
    TargetDistribution = fields.Str()
    Exploitability = fields.Str()
    RemediationLevel = fields.Str()
    ReportConfidence = fields.Str()


class MakeCVSSBaseScoresSchema(CVSSBaseScoresSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return CVSSBaseScores(**data)



