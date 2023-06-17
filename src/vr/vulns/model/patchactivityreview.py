from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load



class PatchActivityReview(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'PatchActivityReview'
    ID = db.Column(db.Integer, primary_key=True)
    PatchActivityID = db.Column(db.Integer, db.ForeignKey('PatchActivity.ID', ondelete='CASCADE'))
    ReviewedBy = db.Column(db.String(50))
    Compliant = db.Column(db.String(1))
    PatchEffort = db.Column(db.Integer)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<PatchActivityReview(name={self.PatchActivityID!r})>'.format(self=self)


class PatchActivityReviewSchema(Schema):
    ID = fields.Int()
    PatchActivityID = fields.Int()
    ReviewedBy = fields.Str()
    Compliant = fields.Str()
    PatchEffort = fields.Int()


class MakePatchActivityReviewSchema(PatchActivityReviewSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return PatchActivityReview(**data)



