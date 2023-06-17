from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
from sqlalchemy.types import DECIMAL


class CVSSBaseScoresV3(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'CVSSBaseScoresV3'
    ID = db.Column(db.Integer, primary_key=True)
    VulnerabilityID = db.Column(db.Integer, db.ForeignKey('Vulnerabilities.VulnerabilityID', ondelete='CASCADE'))
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

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<CVSSBaseScoresV3(name={self.VulnerabilityID!r})>'.format(self=self)


class CVSSBaseScoresV3Schema(Schema):
    ID = fields.Int()
    VulnerabilityID = fields.Int()
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


class MakeCVSSBaseScoresV3Schema(CVSSBaseScoresV3Schema):
    @post_load
    def make_it(self, data, **kwargs):
        return CVSSBaseScoresV3(**data)



