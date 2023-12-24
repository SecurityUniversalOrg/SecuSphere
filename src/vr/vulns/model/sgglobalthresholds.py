from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load



class SgGlobalThresholds(db.Model):
    __tablename__ = 'SgGlobalThresholds'
    __table_args__ = {'extend_existing': True}
    ID = db.Column(db.Integer, primary_key=True)
    Name = db.Column(db.String)
    AddDate = db.Column(db.DateTime)
    ThreshScaLow = db.Column(db.Integer)
    ThreshScaMedium = db.Column(db.Integer)
    ThreshScaHigh = db.Column(db.Integer)
    ThreshScaCritical = db.Column(db.Integer)
    ThreshContainerLow = db.Column(db.Integer)
    ThreshContainerMedium = db.Column(db.Integer)
    ThreshContainerHigh = db.Column(db.Integer)
    ThreshContainerCritical = db.Column(db.Integer)
    ThreshDastLow = db.Column(db.Integer)
    ThreshDastMedium = db.Column(db.Integer)
    ThreshDastHigh = db.Column(db.Integer)
    ThreshDastCritical = db.Column(db.Integer)
    ThreshDastApiLow = db.Column(db.Integer)
    ThreshDastApiMedium = db.Column(db.Integer)
    ThreshDastApiHigh = db.Column(db.Integer)
    ThreshDastApiCritical = db.Column(db.Integer)
    ThreshInfrastructureLow = db.Column(db.Integer)
    ThreshInfrastructureMedium = db.Column(db.Integer)
    ThreshInfrastructureHigh = db.Column(db.Integer)
    ThreshInfrastructureCritical = db.Column(db.Integer)
    ThreshSastLow = db.Column(db.Integer)
    ThreshSastMedium = db.Column(db.Integer)
    ThreshSastHigh = db.Column(db.Integer)
    ThreshSastCritical = db.Column(db.Integer)
    ThreshIacLow = db.Column(db.Integer)
    ThreshIacMedium = db.Column(db.Integer)
    ThreshIacHigh = db.Column(db.Integer)
    ThreshIacCritical = db.Column(db.Integer)
    ThreshSecretsLow = db.Column(db.Integer)
    ThreshSecretsMedium = db.Column(db.Integer)
    ThreshSecretsHigh = db.Column(db.Integer)
    ThreshSecretsCritical = db.Column(db.Integer)

    def __init__(self, Name=None, AddDate=None, ThreshScaLow=None, ThreshScaMedium=None, ThreshScaHigh=None, ThreshScaCritical=None, ThreshContainerLow=None, ThreshContainerMedium=None, ThreshContainerHigh=None, ThreshContainerCritical=None, ThreshDastLow=None, ThreshDastMedium=None, ThreshDastHigh=None, ThreshDastCritical=None, ThreshDastApiLow=None, ThreshDastApiMedium=None, ThreshDastApiHigh=None, ThreshDastApiCritical=None, ThreshInfrastructureLow=None, ThreshInfrastructureMedium=None, ThreshInfrastructureHigh=None, ThreshInfrastructureCritical=None, ThreshSastLow=None, ThreshSastMedium=None, ThreshSastHigh=None, ThreshSastCritical=None, ThreshIacLow=None, ThreshIacMedium=None, ThreshIacHigh=None, ThreshIacCritical=None, ThreshSecretsLow=None, ThreshSecretsMedium=None, ThreshSecretsHigh=None, ThreshSecretsCritical=None, ID=None):
        if ID:
            self.ID = ID
        if Name:
            self.Name = Name
        if AddDate:
            self.AddDate = AddDate
        if ThreshScaLow:
            self.ThreshScaLow = ThreshScaLow
        if ThreshScaMedium:
            self.ThreshScaMedium = ThreshScaMedium
        if ThreshScaHigh:
            self.ThreshScaHigh = ThreshScaHigh
        if ThreshScaCritical:
            self.ThreshScaCritical = ThreshScaCritical
        if ThreshContainerLow:
            self.ThreshContainerLow = ThreshContainerLow
        if ThreshContainerMedium:
            self.ThreshContainerMedium = ThreshContainerMedium
        if ThreshContainerHigh:
            self.ThreshContainerHigh = ThreshContainerHigh
        if ThreshContainerCritical:
            self.ThreshContainerCritical = ThreshContainerCritical
        if ThreshDastLow:
            self.ThreshDastLow = ThreshDastLow
        if ThreshDastMedium:
            self.ThreshDastMedium = ThreshDastMedium
        if ThreshDastHigh:
            self.ThreshDastHigh = ThreshDastHigh
        if ThreshDastCritical:
            self.ThreshDastCritical = ThreshDastCritical
        if ThreshDastApiLow:
            self.ThreshDastApiLow = ThreshDastApiLow
        if ThreshDastApiMedium:
            self.ThreshDastApiMedium = ThreshDastApiMedium
        if ThreshDastApiHigh:
            self.ThreshDastApiHigh = ThreshDastApiHigh
        if ThreshDastApiCritical:
            self.ThreshDastApiCritical = ThreshDastApiCritical
        if ThreshInfrastructureLow:
            self.ThreshInfrastructureLow = ThreshInfrastructureLow
        if ThreshInfrastructureMedium:
            self.ThreshInfrastructureMedium = ThreshInfrastructureMedium
        if ThreshInfrastructureHigh:
            self.ThreshInfrastructureHigh = ThreshInfrastructureHigh
        if ThreshInfrastructureCritical:
            self.ThreshInfrastructureCritical = ThreshInfrastructureCritical
        if ThreshSastLow:
            self.ThreshSastLow = ThreshSastLow
        if ThreshSastMedium:
            self.ThreshSastMedium = ThreshSastMedium
        if ThreshSastHigh:
            self.ThreshSastHigh = ThreshSastHigh
        if ThreshSastCritical:
            self.ThreshSastCritical = ThreshSastCritical
        if ThreshIacLow:
            self.ThreshIacLow = ThreshIacLow
        if ThreshIacMedium:
            self.ThreshIacMedium = ThreshIacMedium
        if ThreshIacHigh:
            self.ThreshIacHigh = ThreshIacHigh
        if ThreshIacCritical:
            self.ThreshIacCritical = ThreshIacCritical
        if ThreshSecretsLow:
            self.ThreshSecretsLow = ThreshSecretsLow
        if ThreshSecretsMedium:
            self.ThreshSecretsMedium = ThreshSecretsMedium
        if ThreshSecretsHigh:
            self.ThreshSecretsHigh = ThreshSecretsHigh
        if ThreshSecretsCritical:
            self.ThreshSecretsCritical = ThreshSecretsCritical

    def __repr__(self):
        return '<SgGlobalThresholds(name={self.ID!r})>'.format(self=self)

class SgGlobalThresholdsSchema(Schema):
    ID = fields.Int()
    Name = fields.Str()
    AddDate = fields.Date()
    ThreshScaLow = fields.Int()
    ThreshScaMedium = fields.Int()
    ThreshScaHigh = fields.Int()
    ThreshScaCritical = fields.Int()
    ThreshContainerLow = fields.Int()
    ThreshContainerMedium = fields.Int()
    ThreshContainerHigh = fields.Int()
    ThreshContainerCritical = fields.Int()
    ThreshDastLow = fields.Int()
    ThreshDastMedium = fields.Int()
    ThreshDastHigh = fields.Int()
    ThreshDastCritical = fields.Int()
    ThreshDastApiLow = fields.Int()
    ThreshDastApiMedium = fields.Int()
    ThreshDastApiHigh = fields.Int()
    ThreshDastApiCritical = fields.Int()
    ThreshInfrastructureLow = fields.Int()
    ThreshInfrastructureMedium = fields.Int()
    ThreshInfrastructureHigh = fields.Int()
    ThreshInfrastructureCritical = fields.Int()
    ThreshSastLow = fields.Int()
    ThreshSastMedium = fields.Int()
    ThreshSastHigh = fields.Int()
    ThreshSastCritical = fields.Int()
    ThreshIacLow = fields.Int()
    ThreshIacMedium = fields.Int()
    ThreshIacHigh = fields.Int()
    ThreshIacCritical = fields.Int()
    ThreshSecretsLow = fields.Int()
    ThreshSecretsMedium = fields.Int()
    ThreshSecretsHigh = fields.Int()
    ThreshSecretsCritical = fields.Int()

class MakeSgGlobalThresholdsSchema(SgGlobalThresholdsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return SgGlobalThresholds(**data)


