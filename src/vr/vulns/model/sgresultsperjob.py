from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load



class SgResultsPerJob(db.Model):
    __tablename__ = 'SgResultsPerJob'
    __table_args__ = {'extend_existing': True}
    ID = db.Column(db.Integer, primary_key=True)
    AppID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    PipelineJobID = db.Column(db.Integer, db.ForeignKey('PipelineJobs.ID', ondelete='CASCADE'))
    ResultScaLow = db.Column(db.Integer)
    ResultScaMedium = db.Column(db.Integer)
    ResultScaHigh = db.Column(db.Integer)
    ResultScaCritical = db.Column(db.Integer)
    ResultContainerLow = db.Column(db.Integer)
    ResultContainerMedium = db.Column(db.Integer)
    ResultContainerHigh = db.Column(db.Integer)
    ResultContainerCritical = db.Column(db.Integer)
    ResultDastLow = db.Column(db.Integer)
    ResultDastMedium = db.Column(db.Integer)
    ResultDastHigh = db.Column(db.Integer)
    ResultDastCritical = db.Column(db.Integer)
    ResultDastApiLow = db.Column(db.Integer)
    ResultDastApiMedium = db.Column(db.Integer)
    ResultDastApiHigh = db.Column(db.Integer)
    ResultDastApiCritical = db.Column(db.Integer)
    ResultInfrastructureLow = db.Column(db.Integer)
    ResultInfrastructureMedium = db.Column(db.Integer)
    ResultInfrastructureHigh = db.Column(db.Integer)
    ResultInfrastructureCritical = db.Column(db.Integer)
    ResultSastLow = db.Column(db.Integer)
    ResultSastMedium = db.Column(db.Integer)
    ResultSastHigh = db.Column(db.Integer)
    ResultSastCritical = db.Column(db.Integer)
    ResultIacLow = db.Column(db.Integer)
    ResultIacMedium = db.Column(db.Integer)
    ResultIacHigh = db.Column(db.Integer)
    ResultIacCritical = db.Column(db.Integer)
    ResultSecretsLow = db.Column(db.Integer)
    ResultSecretsMedium = db.Column(db.Integer)
    ResultSecretsHigh = db.Column(db.Integer)
    ResultSecretsCritical = db.Column(db.Integer)

    def __init__(self, AppID=None, PipelineJobID=None, ResultScaLow=None, ResultScaMedium=None, ResultScaHigh=None, ResultScaCritical=None, ResultContainerLow=None, ResultContainerMedium=None, ResultContainerHigh=None, ResultContainerCritical=None, ResultDastLow=None, ResultDastMedium=None, ResultDastHigh=None, ResultDastCritical=None, ResultDastApiLow=None, ResultDastApiMedium=None, ResultDastApiHigh=None, ResultDastApiCritical=None, ResultInfrastructureLow=None, ResultInfrastructureMedium=None, ResultInfrastructureHigh=None, ResultInfrastructureCritical=None, ResultSastLow=None, ResultSastMedium=None, ResultSastHigh=None, ResultSastCritical=None, ResultIacLow=None, ResultIacMedium=None, ResultIacHigh=None, ResultIacCritical=None, ResultSecretsLow=None, ResultSecretsMedium=None, ResultSecretsHigh=None, ResultSecretsCritical=None, ID=None):
        if ID:
            self.ID = ID
        if AppID:
            self.AppID = AppID
        if PipelineJobID:
            self.PipelineJobID = PipelineJobID
        if ResultScaLow:
            self.ResultScaLow = ResultScaLow
        if ResultScaMedium:
            self.ResultScaMedium = ResultScaMedium
        if ResultScaHigh:
            self.ResultScaHigh = ResultScaHigh
        if ResultScaCritical:
            self.ResultScaCritical = ResultScaCritical
        if ResultContainerLow:
            self.ResultContainerLow = ResultContainerLow
        if ResultContainerMedium:
            self.ResultContainerMedium = ResultContainerMedium
        if ResultContainerHigh:
            self.ResultContainerHigh = ResultContainerHigh
        if ResultContainerCritical:
            self.ResultContainerCritical = ResultContainerCritical
        if ResultDastLow:
            self.ResultDastLow = ResultDastLow
        if ResultDastMedium:
            self.ResultDastMedium = ResultDastMedium
        if ResultDastHigh:
            self.ResultDastHigh = ResultDastHigh
        if ResultDastCritical:
            self.ResultDastCritical = ResultDastCritical
        if ResultDastApiLow:
            self.ResultDastApiLow = ResultDastApiLow
        if ResultDastApiMedium:
            self.ResultDastApiMedium = ResultDastApiMedium
        if ResultDastApiHigh:
            self.ResultDastApiHigh = ResultDastApiHigh
        if ResultDastApiCritical:
            self.ResultDastApiCritical = ResultDastApiCritical
        if ResultInfrastructureLow:
            self.ResultInfrastructureLow = ResultInfrastructureLow
        if ResultInfrastructureMedium:
            self.ResultInfrastructureMedium = ResultInfrastructureMedium
        if ResultInfrastructureHigh:
            self.ResultInfrastructureHigh = ResultInfrastructureHigh
        if ResultInfrastructureCritical:
            self.ResultInfrastructureCritical = ResultInfrastructureCritical
        if ResultSastLow:
            self.ResultSastLow = ResultSastLow
        if ResultSastMedium:
            self.ResultSastMedium = ResultSastMedium
        if ResultSastHigh:
            self.ResultSastHigh = ResultSastHigh
        if ResultSastCritical:
            self.ResultSastCritical = ResultSastCritical
        if ResultIacLow:
            self.ResultIacLow = ResultIacLow
        if ResultIacMedium:
            self.ResultIacMedium = ResultIacMedium
        if ResultIacHigh:
            self.ResultIacHigh = ResultIacHigh
        if ResultIacCritical:
            self.ResultIacCritical = ResultIacCritical
        if ResultSecretsLow:
            self.ResultSecretsLow = ResultSecretsLow
        if ResultSecretsMedium:
            self.ResultSecretsMedium = ResultSecretsMedium
        if ResultSecretsHigh:
            self.ResultSecretsHigh = ResultSecretsHigh
        if ResultSecretsCritical:
            self.ResultSecretsCritical = ResultSecretsCritical

    def __repr__(self):
        return '<SgResultsPerJob(name={self.AppID!r})>'.format(self=self)

class SgResultsPerJobSchema(Schema):
    ID = fields.Int()
    AppID = fields.Int()
    PipelineJobID = fields.Int()
    ResultScaLow = fields.Int()
    ResultScaMedium = fields.Int()
    ResultScaHigh = fields.Int()
    ResultScaCritical = fields.Int()
    ResultContainerLow = fields.Int()
    ResultContainerMedium = fields.Int()
    ResultContainerHigh = fields.Int()
    ResultContainerCritical = fields.Int()
    ResultDastLow = fields.Int()
    ResultDastMedium = fields.Int()
    ResultDastHigh = fields.Int()
    ResultDastCritical = fields.Int()
    ResultDastApiLow = fields.Int()
    ResultDastApiMedium = fields.Int()
    ResultDastApiHigh = fields.Int()
    ResultDastApiCritical = fields.Int()
    ResultInfrastructureLow = fields.Int()
    ResultInfrastructureMedium = fields.Int()
    ResultInfrastructureHigh = fields.Int()
    ResultInfrastructureCritical = fields.Int()
    ResultSastLow = fields.Int()
    ResultSastMedium = fields.Int()
    ResultSastHigh = fields.Int()
    ResultSastCritical = fields.Int()
    ResultIacLow = fields.Int()
    ResultIacMedium = fields.Int()
    ResultIacHigh = fields.Int()
    ResultIacCritical = fields.Int()
    ResultSecretsLow = fields.Int()
    ResultSecretsMedium = fields.Int()
    ResultSecretsHigh = fields.Int()
    ResultSecretsCritical = fields.Int()

class MakeSgResultsPerJobSchema(SgResultsPerJobSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return SgResultsPerJob(**data)