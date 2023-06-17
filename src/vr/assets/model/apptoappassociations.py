from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class AppToAppAssociations(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AppToAppAssociations'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    AppIDA = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    DependencyDirection = db.Column(db.String(100))
    DrCriticalDependency = db.Column(db.Integer)
    AppIDB = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AppToAppAssociations(name={self.AddDate!r})>'.format(self=self)

class AppToAppAssociationsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    AppIDA = fields.Int()
    DependencyDirection = fields.Str()
    DrCriticalDependency = fields.Int()
    AppIDB = fields.Int()

class MakeAppToAppAssociationsSchema(AppToAppAssociationsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AppToAppAssociations(**data)



