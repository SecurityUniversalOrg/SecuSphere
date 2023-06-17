from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class SupportContacts(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'SupportContacts'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    Assignment = db.Column(db.String(30))
    CUID = db.Column(db.String(12))
    Name = db.Column(db.String(300))
    Email = db.Column(db.String(300))
    Role = db.Column(db.String(100))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<SupportContacts(name={self.AddDate!r})>'.format(self=self)


class SupportContactsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    Assignment = fields.Str()
    CUID = fields.Str()
    Name = fields.Str()
    Email = fields.Str()
    Role = fields.Str()


class MakeSupportContactsSchema(SupportContactsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return SupportContacts(**data)



