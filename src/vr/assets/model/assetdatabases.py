from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class AssetDatabases(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AssetDatabases'
    ID = db.Column(db.Integer, primary_key=True)
    TechnologyID = db.Column(db.Integer)
    DatabaseID = db.Column(db.Integer)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AssetDatabases(name={self.TechnologyID!r})>'.format(self=self)

class AssetDatabasesSchema(Schema):
    ID = fields.Int()
    TechnologyID = fields.Int()
    DatabaseID = fields.Int()

class MakeAssetDatabasesSchema(AssetDatabasesSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AssetDatabases(**data)



