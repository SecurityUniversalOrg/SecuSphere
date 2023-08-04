from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class CICDPipelineBuilds(db.Model):
    __tablename__ = 'CICDPipelineBuilds'
    ID = db.Column(db.Integer, primary_key=True)
    PipelineID = db.Column(db.Integer, db.ForeignKey('CICDPipelines.ID', ondelete='CASCADE'))
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    BuildName = db.Column(db.String(400))
    BranchName = db.Column(db.String(600))
    Status = db.Column(db.String(40))
    StartTime = db.Column(db.DateTime, index=True)
    DurationMillis = db.Column(db.Integer)

    def __init__(self, PipelineID=None, AddDate=None, BuildName=None, BranchName=None, Status=None, StartTime=None, DurationMillis=None, ID=None):
        if ID:
            self.ID = ID
        if PipelineID:
            self.PipelineID = PipelineID
        if AddDate:
            self.AddDate = AddDate
        if BuildName:
            self.BuildName = BuildName
        if BranchName:
            self.BranchName = BranchName
        if Status:
            self.Status = Status
        if StartTime:
            self.StartTime = StartTime
        if DurationMillis:
            self.DurationMillis = DurationMillis

    def __repr__(self):
        return '<CICDPipelineBuilds(name={self.PipelineID!r})>'.format(self=self)

class CICDPipelineBuildsSchema(Schema):
    ID = fields.Int()
    PipelineID = fields.Int()
    AddDate = fields.Date()
    BuildName = fields.Str()
    BranchName = fields.Str()
    Status = fields.Str()
    StartTime = fields.Date()
    DurationMillis = fields.Int()

class MakeCICDPipelineBuildsSchema(CICDPipelineBuildsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return CICDPipelineBuilds(**data)

