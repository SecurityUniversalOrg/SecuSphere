from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load



class PatchActivity(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'PatchActivity'
    ID = db.Column(db.Integer, primary_key=True)
    PatchID = db.Column(db.Integer, db.ForeignKey('PatchInfo.ID', ondelete='CASCADE'))
    TechnologyID = db.Column(db.Integer, db.ForeignKey('Technologies.TechnologyID', ondelete='CASCADE'))
    DateOfInstall = db.Column(db.DateTime, index=True)
    PatchStatus = db.Column(db.String(60))
    Priority = db.Column(db.String(30))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<PatchActivity(name={self.PatchID!r})>'.format(self=self)


class PatchActivitySchema(Schema):
    ID = fields.Int()
    PatchID = fields.Int()
    TechnologyID = fields.Int()
    DateOfInstall = fields.DateTime()
    PatchStatus = fields.Str()
    Priority = fields.Str()


class MakePatchActivitySchema(PatchActivitySchema):
    @post_load
    def make_it(self, data, **kwargs):
        return PatchActivity(**data)



