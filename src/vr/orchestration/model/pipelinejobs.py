from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load



class PipelineJobs(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'PipelineJobs'
    ID = db.Column(db.Integer, primary_key=True)
    StartDate = db.Column(db.DateTime, index=True)
    Status = db.Column(db.String(30))
    Source = db.Column(db.String(30))
    SourceJobId = db.Column(db.Integer)
    ApplicationId = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    BranchName = db.Column(db.String(300))
    BuildNum = db.Column(db.String(300))
    JobName = db.Column(db.String(300))
    Project = db.Column(db.String(300))
    Node = db.Column(db.String(300))
    NodeAssetId = db.Column(db.Integer)
    GitCommit = db.Column(db.String(300))
    GitBranch = db.Column(db.String(300))
    GitUrl = db.Column(db.String(300))
    NodeIp = db.Column(db.String(300))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<PipelineJobs(name={self.StartDate!r})>'.format(self=self)


class PipelineJobsSchema(Schema):
    ID = fields.Int()
    StartDate = fields.DateTime()
    Status = fields.Str()
    Source = fields.Str()
    SourceJobId = fields.Int()
    ApplicationId = fields.Int()
    BranchName = fields.Str()
    BuildNum = fields.Str()
    JobName = fields.Str()
    Project = fields.Str()
    Node = fields.Str()
    NodeAssetId = fields.Int()
    GitCommit = fields.Str()
    GitBranch = fields.Str()
    GitUrl = fields.Str()
    NodeIp = fields.Str()
    ApplicationName = fields.Str()


class MakePipelineJobsSchema(PipelineJobsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return PipelineJobs(**data)



