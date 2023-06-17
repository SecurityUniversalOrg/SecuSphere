from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class IdentifiedVulnerabilities(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'IdentifiedVulnerabilities'
    ID = db.Column(db.Integer, primary_key=True)
    TechnologyID = db.Column(db.Integer, db.ForeignKey('Technologies.TechnologyID', ondelete='CASCADE'))
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    VulnerabilityID = db.Column(db.Integer, db.ForeignKey('Vulnerabilities.VulnerabilityID', ondelete='CASCADE'))
    DateOfDetection = db.Column(db.DateTime, index=True)
    DetectionMethod = db.Column(db.String(10))
    ScanID = db.Column(db.Integer, db.ForeignKey('Vulnerabilities.VulnerabilityID', ondelete='CASCADE'))
    VulnerabilityStatus = db.Column(db.String(30))
    StatusDate = db.Column(db.DateTime, index=True)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<IdentifiedVulnerabilities(name={self.TechnologyID!r})>'.format(self=self)


class IdentifiedVulnerabilitiesSchema(Schema):
    ID = fields.Int()
    TechnologyID = fields.Int()
    ApplicationID = fields.Int()
    VulnerabilityID = fields.Int()
    DateOfDetection = fields.DateTime()
    DetectionMethod = fields.Str()
    ScanID = fields.Int()
    VulnerabilityStatus = fields.Str()
    StatusDate = fields.DateTime()


class MakeIdentifiedVulnerabilitiesSchema(IdentifiedVulnerabilitiesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return IdentifiedVulnerabilities(**data)



