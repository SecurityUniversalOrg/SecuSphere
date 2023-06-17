from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class DbToAppAssociations(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'DbToAppAssociations'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    DatabaseID = db.Column(db.Integer, db.ForeignKey('SUDatabases.ID', ondelete='CASCADE'))
    Environment = db.Column(db.String(100))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<DbToAppAssociations(name={self.AddDate!r})>'.format(self=self)


class DbToAppAssociationsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    ApplicationID = fields.Int()
    DatabaseID = fields.Int()
    Environment = fields.Str()


class MakeDbToAppAssociationsSchema(DbToAppAssociationsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return DbToAppAssociations(**data)



