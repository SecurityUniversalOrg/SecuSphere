from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load



class TopProgrammingErrors(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'TopProgrammingErrors'
    ID = db.Column(db.Integer, primary_key=True)
    CWEID = db.Column(db.String(20))
    Name = db.Column(db.String(60))
    WeaknessPrevalence = db.Column(db.String(15))
    RemediationCost = db.Column(db.String(10))
    AttackFrequency = db.Column(db.String(10))
    Consequences = db.Column(db.String(25))
    EaseOfDetection = db.Column(db.String(10))
    AttackerAwareness = db.Column(db.String(10))
    Discussion = db.Column(db.String(200))
    Prevention = db.Column(db.String(200))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<TopProgrammingErrors(name={self.CWEID!r})>'.format(self=self)


class TopProgrammingErrorsSchema(Schema):
    ID = fields.Int()
    CWEID = fields.Str()
    Name = fields.Str()
    WeaknessPrevalence = fields.Str()
    RemediationCost = fields.Str()
    AttackFrequency = fields.Str()
    Consequences = fields.Str()
    EaseOfDetection = fields.Str()
    AttackerAwareness = fields.Str()
    Discussion = fields.Str()
    Prevention = fields.Str()


class MakeTopProgrammingErrorsSchema(TopProgrammingErrorsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return TopProgrammingErrors(**data)



