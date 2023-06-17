from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class AppToServerAssociations(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AppToServerAssociations'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    ServerID = db.Column(db.Integer, db.ForeignKey('IPAssets.ID', ondelete='CASCADE'))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AppToServerAssociations(name={self.AddDate!r})>'.format(self=self)


class AppToServerAssociationsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    ApplicationID = fields.Int()
    ServerID = fields.Int()


class MakeAppToServerAssociationsSchema(AppToServerAssociationsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AppToServerAssociations(**data)



