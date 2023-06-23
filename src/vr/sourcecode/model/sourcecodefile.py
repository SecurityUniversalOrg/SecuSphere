from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class SourceCodeFile(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'SourceCodeFile'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime)
    GitRepoId = db.Column(db.Integer)
    FileName = db.Column(db.String(300))
    FileLocation = db.Column(db.String(300))
    FileType = db.Column(db.String(300))

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<SourceCodeFile(name={self.AddDate!r})>'.format(self=self)


class SourceCodeFileSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    GitRepoId = fields.Int()
    FileName = fields.Str()
    FileLocation = fields.Str()
    FileType = fields.Str()


class MakeSourceCodeFileSchema(SourceCodeFileSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return SourceCodeFile(**data)



