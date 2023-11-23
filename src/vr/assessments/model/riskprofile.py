from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class RiskProfile(db.Model):
    __tablename__ = 'RiskProfile'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime)
    CompletedByUserID = db.Column(db.Integer)
    Answers = db.Column(LONGTEXT)
    Status = db.Column(db.String(100))
    Scores = db.Column(LONGTEXT)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))

    def __init__(self, AddDate=None, CompletedByUserID=None, Answers=None, Status=None, ID=None, Scores=None, ApplicationID=None):
        if ID:
            self.ID = ID
        if AddDate:
            self.AddDate = AddDate
        if CompletedByUserID:
            self.CompletedByUserID = CompletedByUserID
        if Answers:
            self.Answers = Answers
        if Status:
            self.Status = Status
        if Scores:
            self.Scores = Scores
        if ApplicationID:
            self.ApplicationID = ApplicationID

    def __repr__(self):
        return '<RiskProfile(name={self.AddDate!r})>'.format(self=self)

class RiskProfileSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    CompletedByUserID = fields.Int()
    Answers = fields.Str()
    Status = fields.Str()
    Scores = fields.Str()
    ApplicationID = fields.Int()

class MakeRiskProfileSchema(RiskProfileSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return RiskProfile(**data)


with app.app_context():
    db.create_all()

