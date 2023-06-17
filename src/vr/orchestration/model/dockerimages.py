from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
from datetime import datetime


class DockerImages(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'DockerImages'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=datetime.utcnow, nullable=False)
    ImageName = db.Column(db.String(300))
    ImageTag = db.Column(db.String(300))
    ImageId = db.Column(db.String(300))
    AppIdList = db.Column(db.String(3000))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<DockerImages(name={self.ID!r})>'.format(self=self)

class DockerImagesSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    ImageName = fields.Str()
    ImageTag = fields.Str()
    ImageId = fields.Str()
    AppIdList = fields.Str()
    total_vulnerabilities = fields.Int()

class MakeDockerImagesSchema(DockerImagesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return DockerImages(**data)



