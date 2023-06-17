from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class DockerImageAppPair(db.Model):
    __tablename__ = 'DockerImageAppPair'
    __table_args__ = {'extend_existing': True}
    ID = db.Column(db.Integer, primary_key=True)
    AppID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    DockerImageID = db.Column(db.Integer, db.ForeignKey('DockerImages.ID', ondelete='CASCADE'))

    def __init__(self, AppID=None, DockerImageID=None, ID=None):
        if ID:
            self.ID = ID
        if AppID:
            self.AppID = AppID
        if DockerImageID:
            self.DockerImageID = DockerImageID

    def __repr__(self):
        return '<DockerImageAppPair(name={self.AppID!r})>'.format(self=self)

class DockerImageAppPairSchema(Schema):
    ID = fields.Int()
    AppID = fields.Int()
    DockerImageID = fields.Int()

class MakeDockerImageAppPairSchema(DockerImageAppPairSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return DockerImageAppPair(**data)



