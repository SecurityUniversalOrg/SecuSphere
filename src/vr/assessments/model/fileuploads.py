from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class FileUploads(db.Model):
    __tablename__ = 'FileUploads'
    ID = db.Column(db.Integer, primary_key=True)
    FileName  = db.Column(db.String(255))
    FileSize = db.Column(db.Integer)
    FileType = db.Column(db.String(100))
    UploadDate = db.Column(db.DateTime)
    UploadedByUserID = db.Column(db.Integer)
    AuditID = db.Column(db.Integer)
    BenchmarkingID = db.Column(db.Integer)
    FilePath = db.Column(LONGTEXT)
    Status = db.Column(db.String(100))
    FileDescription = db.Column(LONGTEXT)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))

    def __init__(self, FileName =None, FileSize=None, FileType=None, UploadDate=None, UploadedByUserID=None, AuditID=None, BenchmarkingID=None, FilePath=None, Status=None, ID=None, FileDescription=None, ApplicationID=None):
        if ID:
            self.ID = ID
        if FileName :
            self.FileName  = FileName
        if FileSize:
            self.FileSize = FileSize
        if FileType:
            self.FileType = FileType
        if UploadDate:
            self.UploadDate = UploadDate
        if UploadedByUserID:
            self.UploadedByUserID = UploadedByUserID
        if AuditID:
            self.AuditID = AuditID
        if BenchmarkingID:
            self.BenchmarkingID = BenchmarkingID
        if FilePath:
            self.FilePath = FilePath
        if Status:
            self.Status = Status
        if FileDescription:
            self.FileDescription = FileDescription
        if ApplicationID:
            self.ApplicationID = ApplicationID

    def __repr__(self):
        return '<FileUploads(name={self.FileName !r})>'.format(self=self)


class FileUploadsSchema(Schema):
    ID = fields.Int()
    FileName  = fields.Str()
    FileSize = fields.Int()
    FileType = fields.Str()
    UploadDate = fields.Date()
    UploadedByUserID = fields.Int()
    AuditID = fields.Int()
    BenchmarkingID = fields.Int()
    FilePath = fields.Str()
    Status = fields.Str()
    FileDescription = fields.Str()
    ApplicationID = fields.Str()


class MakeFileUploadsSchema(FileUploadsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return FileUploads(**data)
