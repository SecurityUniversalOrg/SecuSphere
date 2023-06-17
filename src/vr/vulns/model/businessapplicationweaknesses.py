from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class BusinessApplicationWeaknesses(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'BusinessApplicationWeaknesses'
    ID = db.Column(db.Integer, primary_key=True)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    TechnologyID = db.Column(db.Integer, db.ForeignKey('Technologies.TechnologyID', ondelete='CASCADE'))
    CWEID = db.Column(db.String(30))
    DiscoveredDate = db.Column(db.DateTime, index=True)
    DiscoveredBy = db.Column(db.String(40))
    Status = db.Column(db.String(30))
    Priority = db.Column(db.String(20))
    Type = db.Column(db.String(50))
    MitigationDate = db.Column(db.DateTime, index=True)
    MitigatedBy = db.Column(db.String(50))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<BusinessApplicationWeaknesses(name={self.ApplicationID!r})>'.format(self=self)


class BusinessApplicationWeaknessesSchema(Schema):
    ID = fields.Int()
    ApplicationID = fields.Int()
    TechnologyID = fields.Int()
    CWEID = fields.Str()
    DiscoveredDate = fields.DateTime()
    DiscoveredBy = fields.Str()
    Status = fields.Str()
    Priority = fields.Str()
    Type = fields.Str()
    MitigationDate = fields.DateTime()
    MitigatedBy = fields.Str()


class MakeBusinessApplicationWeaknessesSchema(BusinessApplicationWeaknessesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return BusinessApplicationWeaknesses(**data)



