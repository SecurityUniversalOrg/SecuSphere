from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
from sqlalchemy.types import DECIMAL


class CVSSBaseScoresV2(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'CVSSBaseScoresV2'
    ID = db.Column(db.Integer, primary_key=True)
    VulnerabilityID = db.Column(db.Integer, db.ForeignKey('Vulnerabilities.VulnerabilityID', ondelete='CASCADE'))
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

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<CVSSBaseScoresV2(name={self.VulnerabilityID!r})>'.format(self=self)


class CVSSBaseScoresV2Schema(Schema):
    ID = fields.Int()
    VulnerabilityID = fields.Int()
    cvssV2vectorString = fields.Str()
    cvssV2accessVector = fields.Str()
    cvssV2accessComplexity = fields.Str()
    cvssV2authentication = fields.Str()
    cvssV2confidentialityImpact = fields.Str()
    cvssV2integrityImpact = fields.Str()
    cvssV2availabilityImpact = fields.Number()
    cvssV2baseScore = fields.Number()
    cvssV2severity = fields.Str()
    cvssV2exploitabilityScore = fields.Number()
    cvssV2impactScore = fields.Number()
    cvssV2acInsufInfo = fields.Str()
    cvssV2obtainAllPrivilege = fields.Str()
    cvssV2obtainUserPrivilege = fields.Str()
    cvssV2obtainOtherPrivilege = fields.Str()
    cvssV2userInteractionRequired = fields.Str()


class MakeCVSSBaseScoresV2Schema(CVSSBaseScoresV2Schema):
    @post_load
    def make_it(self, data, **kwargs):
        return CVSSBaseScoresV2(**data)



