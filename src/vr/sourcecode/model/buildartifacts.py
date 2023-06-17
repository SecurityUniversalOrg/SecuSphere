import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class BuildArtifacts(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'BuildArtifacts'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    PipelineJobID = db.Column(db.Integer, db.ForeignKey('PipelineJobs.ID', ondelete='CASCADE'))
    ArtifactName = db.Column(db.String(300))
    Url = db.Column(db.String(300))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<BuildArtifacts(name={self.AddDate!r})>'.format(self=self)


class BuildArtifactsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    PipelineJobID = fields.Int()
    ArtifactName = fields.Str()
    Url = fields.Str()


class MakeBuildArtifactsSchema(BuildArtifactsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return BuildArtifacts(**data)



