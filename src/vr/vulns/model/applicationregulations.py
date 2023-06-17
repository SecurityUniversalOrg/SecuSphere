import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class ApplicationRegulations(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'ApplicationRegulations'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    RegulationID = db.Column(db.Integer, db.ForeignKey('Regulations.ID', ondelete='CASCADE'))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<ApplicationRegulations(name={self.AddDate!r})>'.format(self=self)


class ApplicationRegulationsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    ApplicationID = fields.Int()
    RegulationID = fields.Int()


class MakeApplicationRegulationsSchema(ApplicationRegulationsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return ApplicationRegulations(**data)



