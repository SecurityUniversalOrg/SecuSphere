import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT



class VulnToolAppPairs(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'VulnToolAppPairs'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    ToolID = db.Column(db.Integer, db.ForeignKey('Integrations.ID', ondelete='CASCADE'))
    ToolProjectID = db.Column(db.String(500))
    KeyValuePairs = db.Column(LONGTEXT)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<VulnToolAppPairs(name={self.AddDate!r})>'.format(self=self)


class VulnToolAppPairsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    ApplicationID = fields.Int()
    ToolID = fields.Int()
    ToolProjectID = fields.Str()
    KeyValuePairs = fields.Str()


class MakeVulnToolAppPairsSchema(VulnToolAppPairsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return VulnToolAppPairs(**data)



