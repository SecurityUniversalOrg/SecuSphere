import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class PullRequests(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'PullRequests'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ReleaseID = db.Column(db.Integer, db.ForeignKey('ReleaseVersions.ID', ondelete='CASCADE'))
    Name = db.Column(db.String(300))
    Description = db.Column(LONGTEXT)
    Source = db.Column(db.String(300))
    SourceID = db.Column(db.Integer)
    Reporter = db.Column(db.String(300))
    Approvers = db.Column(db.String(300))
    Status = db.Column(db.String(30))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<PullRequests(name={self.AddDate!r})>'.format(self=self)

class PullRequestsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    ReleaseID = fields.Int()
    Name = fields.Str()
    Description = fields.Str()
    Source = fields.Str()
    SourceID = fields.Int()
    Reporter = fields.Str()
    Approvers = fields.Str()
    Status = fields.Str()

class MakePullRequestsSchema(PullRequestsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return PullRequests(**data)



