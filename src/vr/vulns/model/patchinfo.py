from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load



class PatchInfo(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'PatchInfo'
    ID = db.Column(db.Integer, primary_key=True)
    VulnerabilityID = db.Column(db.Integer, db.ForeignKey('Vulnerabilities.VulnerabilityID', ondelete='CASCADE'))
    PatchSource = db.Column(db.String(50))
    PatchName = db.Column(db.String(60))
    CriticalityLevel = db.Column(db.String(10))
    OrgCriticalityLevel = db.Column(db.String(30))
    DateOfNotification = db.Column(db.DateTime, index=True)
    DateOfAvailability = db.Column(db.DateTime, index=True)
    DateOfPatchApproval = db.Column(db.DateTime, index=True)
    PatchType = db.Column(db.String(30))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<PatchInfo(name={self.VulnerabilityID!r})>'.format(self=self)


class PatchInfoSchema(Schema):
    ID = fields.Int()
    VulnerabilityID = fields.Int()
    PatchSource = fields.Str()
    PatchName = fields.Str()
    CriticalityLevel = fields.Str()
    OrgCriticalityLevel = fields.Str()
    DateOfNotification = fields.DateTime()
    DateOfAvailability = fields.DateTime()
    DateOfPatchApproval = fields.DateTime()
    PatchType = fields.Str()


class MakePatchInfoSchema(PatchInfoSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return PatchInfo(**data)



