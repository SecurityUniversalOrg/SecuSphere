from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
from sqlalchemy.types import DECIMAL


class CVSSBaseScoresV2Extensions(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'CVSSBaseScoresV2Extensions'
    ID = db.Column(db.Integer, primary_key=True)
    VulnerabilityID = db.Column(db.Integer, db.ForeignKey('Vulnerabilities.VulnerabilityID', ondelete='CASCADE'))
    TechnologyID = db.Column(db.Integer, db.ForeignKey('Technologies.TechnologyID', ondelete='CASCADE'))
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

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<CVSSBaseScoresV2Extensions(name={self.VulnerabilityID!r})>'.format(self=self)


class CVSSBaseScoresV2ExtensionsSchema(Schema):
    ID = fields.Int()
    VulnerabilityID = fields.Int()
    TechnologyID = fields.Int()
    cvssV2remediationLevel = fields.Str()
    cvssV2reportConfidence = fields.Str()
    cvssV2temporalScore = fields.Number()
    cvssV2collateralDamagePotential = fields.Str()
    cvssV2targetDistribution = fields.Str()
    cvssV2confidentialityRequirements = fields.Str()
    cvssV2integrityRequirements = fields.Str()
    cvssV2availabilityRequirements = fields.Str()
    cvssV2environmentalScore = fields.Number()
    cvssV2adjustedTemporalScore = fields.Number()
    cvssV2adjustedImpactScore = fields.Number()


class MakeCVSSBaseScoresV2ExtensionsSchema(CVSSBaseScoresV2ExtensionsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return CVSSBaseScoresV2Extensions(**data)



