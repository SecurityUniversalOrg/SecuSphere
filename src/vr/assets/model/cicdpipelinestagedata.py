from datetime import datetime
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class CICDPipelineStageData(db.Model):
    __tablename__ = 'CICDPipelineStageData'
    ID = db.Column(db.Integer, primary_key=True)
    BuildID = db.Column(db.Integer, db.ForeignKey('CICDPipelineBuilds.ID', ondelete='CASCADE'))
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    StageName = db.Column(db.String(400))
    BuildNode = db.Column(db.String(400))
    Status = db.Column(db.String(40))
    StartTime = db.Column(db.DateTime, index=True)
    DurationMillis = db.Column(db.Integer)

    def __init__(self, BuildID=None, AddDate=None, StageName=None, BuildNode=None, Status=None, StartTime=None, DurationMillis=None, ID=None):
        if ID:
            self.ID = ID
        if BuildID:
            self.BuildID = BuildID
        if AddDate:
            self.AddDate = AddDate
        if StageName:
            self.StageName = StageName
        if BuildNode:
            self.BuildNode = BuildNode
        if Status:
            self.Status = Status
        if StartTime:
            self.StartTime = StartTime
        if DurationMillis:
            self.DurationMillis = DurationMillis

    def __repr__(self):
        return '<CICDPipelineStageData(name={self.BuildID!r})>'.format(self=self)

class CICDPipelineStageDataSchema(Schema):
    ID = fields.Int()
    BuildID = fields.Int()
    AddDate = fields.Date()
    StageName = fields.Str()
    BuildNode = fields.Str()
    Status = fields.Str()
    StartTime = fields.Date()
    DurationMillis = fields.Int()

class MakeCICDPipelineStageDataSchema(CICDPipelineStageDataSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return CICDPipelineStageData(**data)

