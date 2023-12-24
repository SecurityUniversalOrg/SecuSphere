from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load



class ParallelSecurityPipelineRuns(db.Model):
    __tablename__ = 'ParallelSecurityPipelineRuns'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    Status = db.Column(db.String(40))
    ScanEndDate = db.Column(db.DateTime)
    SecretFindings = db.Column(db.String(100))
    ScaFindings = db.Column(db.String(100))
    SastFindings = db.Column(db.String(100))
    IacFindings = db.Column(db.String(100))
    ContainerFindings = db.Column(db.String(100))
    DastFindings = db.Column(db.String(100))
    DastApiFindings = db.Column(db.String(100))
    Branch = db.Column(db.String(1000))

    def __init__(self, AddDate=None, ApplicationID=None, Status=None, ScanEndDate=None, SecretFindings=None, ScaFindings=None, SastFindings=None, IacFindings=None, ContainerFindings=None, DastFindings=None, DastApiFindings=None, ID=None, Branch=None):
        if ID:
            self.ID = ID
        if AddDate:
            self.AddDate = AddDate
        if ApplicationID:
            self.ApplicationID = ApplicationID
        if Status:
            self.Status = Status
        if ScanEndDate:
            self.ScanEndDate = ScanEndDate
        if SecretFindings:
            self.SecretFindings = SecretFindings
        if ScaFindings:
            self.ScaFindings = ScaFindings
        if SastFindings:
            self.SastFindings = SastFindings
        if IacFindings:
            self.IacFindings = IacFindings
        if ContainerFindings:
            self.ContainerFindings = ContainerFindings
        if DastFindings:
            self.DastFindings = DastFindings
        if DastApiFindings:
            self.DastApiFindings = DastApiFindings
        if Branch:
            self.Branch = Branch

    def __repr__(self):
        return '<ParallelSecurityPipelineRuns(name={self.AddDate!r})>'.format(self=self)

class ParallelSecurityPipelineRunsSchema(Schema):
    ID = fields.Int()
    AddDate = fields.Date()
    ApplicationID = fields.Int()
    Status = fields.Str()
    ScanEndDate = fields.Date()
    SecretFindings = fields.Str()
    ScaFindings = fields.Str()
    SastFindings = fields.Str()
    IacFindings = fields.Str()
    ContainerFindings = fields.Str()
    DastFindings = fields.Str()
    DastApiFindings = fields.Str()
    Branch = fields.Str()

class MakeParallelSecurityPipelineRunsSchema(ParallelSecurityPipelineRunsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return ParallelSecurityPipelineRuns(**data)
