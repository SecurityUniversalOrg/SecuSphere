from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
from sqlalchemy.types import DECIMAL



class CVSSBaseScoresV3Extensions(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'CVSSBaseScoresV3Extensions'
    ID = db.Column(db.Integer, primary_key=True)
    CVEID = db.Column(db.String(20))
    cvssV3exploitCodeMaturity = db.Column(db.String(30))
    cvssV3remediationLevel = db.Column(db.String(30))
    cvssV3reportConfidence = db.Column(db.String(30))
    cvssV3confidentialityRequirements = db.Column(db.String(20))
    cvssV3integrityRequirements = db.Column(db.String(20))
    cvssV3availabilityRequirements = db.Column(db.String(20))
    cvssV3temporalScore = db.Column(DECIMAL(13, 4))
    cvssV3environmentalScore = db.Column(DECIMAL(13, 4))
    cvssV3impactScore = db.Column(DECIMAL(13, 4))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<CVSSBaseScoresV3Extensions(name={self.VulnerabilityID!r})>'.format(self=self)


class CVSSBaseScoresV3ExtensionsSchema(Schema):
    ID = fields.Int()
    CVEID = fields.Str()
    cvssV3exploitCodeMaturity = fields.Str()
    cvssV3remediationLevel = fields.Str()
    cvssV3reportConfidence = fields.Str()
    cvssV3confidentialityRequirements = fields.Str()
    cvssV3integrityRequirements = fields.Str()
    cvssV3availabilityRequirements = fields.Str()
    cvssV3temporalScore = fields.Number()
    cvssV3environmentalScore = fields.Number()
    cvssV3impactScore = fields.Number()


class MakeCVSSBaseScoresV3ExtensionsSchema(CVSSBaseScoresV3ExtensionsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return CVSSBaseScoresV3Extensions(**data)


