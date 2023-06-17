from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class GitRepo(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'GitRepo'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime)
    Source = db.Column(db.String(30))
    RepoName = db.Column(db.String(100))
    RepoUrl = db.Column(db.String(100))
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<GitRepo(name={self.AddDate!r})>'.format(self=self)


class GitRepoSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    Source = fields.Str()
    RepoName = fields.Str()
    RepoUrl = fields.Str()
    ApplicationID = fields.Int()


class MakeGitRepoSchema(GitRepoSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return GitRepo(**data)



