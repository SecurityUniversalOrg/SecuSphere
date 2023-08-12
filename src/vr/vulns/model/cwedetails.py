from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load
if app.config['RUNTIME_ENV'] == 'test':
    from sqlalchemy.dialects.sqlite import TEXT as LONGTEXT
else:
    from sqlalchemy.dialects.mysql import LONGTEXT


class CWEDetails(db.Model):
    __tablename__ = 'CWEDetails'
    ID = db.Column(db.Integer, primary_key=True)
    CWEID = db.Column(db.String(20))
    Name = db.Column(db.String(400))
    Description = db.Column(LONGTEXT)
    ModesOfIntroductionPhase = db.Column(db.String(400))
    ModesOfIntroductionNote = db.Column(LONGTEXT)
    CommonConsequencesScope = db.Column(LONGTEXT)
    CommonConsequencesImpact = db.Column(LONGTEXT)
    DetectionMethodsMethod = db.Column(db.String(400))
    DetectionMethodsDescription = db.Column(LONGTEXT)
    PotentialMitigationsPhase = db.Column(db.String(400))
    PotentialMitigationsDescription = db.Column(LONGTEXT)
    FunctionalAreas = db.Column(LONGTEXT)
    AffectedResources = db.Column(LONGTEXT)
    TaxonomyMappingsName = db.Column(LONGTEXT)
    TaxonomyMappingsEntryName = db.Column(LONGTEXT)

    def __init__(self, CWEID=None, Name=None, Description=None, ModesOfIntroductionPhase=None, ModesOfIntroductionNote=None, CommonConsequencesScope=None, CommonConsequencesImpact=None, DetectionMethodsMethod=None, DetectionMethodsDescription=None, PotentialMitigationsPhase=None, PotentialMitigationsDescription=None, FunctionalAreas=None, AffectedResources=None, TaxonomyMappingsName=None, TaxonomyMappingsEntryName=None, ID=None):
        if ID:
            self.ID = ID
        if CWEID:
            self.CWEID = CWEID
        if Name:
            self.Name = Name
        if Description:
            self.Description = Description
        if ModesOfIntroductionPhase:
            self.ModesOfIntroductionPhase = ModesOfIntroductionPhase
        if ModesOfIntroductionNote:
            self.ModesOfIntroductionNote = ModesOfIntroductionNote
        if CommonConsequencesScope:
            self.CommonConsequencesScope = CommonConsequencesScope
        if CommonConsequencesImpact:
            self.CommonConsequencesImpact = CommonConsequencesImpact
        if DetectionMethodsMethod:
            self.DetectionMethodsMethod = DetectionMethodsMethod
        if DetectionMethodsDescription:
            self.DetectionMethodsDescription = DetectionMethodsDescription
        if PotentialMitigationsPhase:
            self.PotentialMitigationsPhase = PotentialMitigationsPhase
        if PotentialMitigationsDescription:
            self.PotentialMitigationsDescription = PotentialMitigationsDescription
        if FunctionalAreas:
            self.FunctionalAreas = FunctionalAreas
        if AffectedResources:
            self.AffectedResources = AffectedResources
        if TaxonomyMappingsName:
            self.TaxonomyMappingsName = TaxonomyMappingsName
        if TaxonomyMappingsEntryName:
            self.TaxonomyMappingsEntryName = TaxonomyMappingsEntryName

    def __repr__(self):
        return '<CWEDetails(name={self.CWEID!r})>'.format(self=self)

class CWEDetailsSchema(Schema):
    ID = fields.Int()
    CWEID = fields.Str()
    Name = fields.Str()
    Description = fields.Str()
    ModesOfIntroductionPhase = fields.Str()
    ModesOfIntroductionNote = fields.Str()
    CommonConsequencesScope = fields.Str()
    CommonConsequencesImpact = fields.Str()
    DetectionMethodsMethod = fields.Str()
    DetectionMethodsDescription = fields.Str()
    PotentialMitigationsPhase = fields.Str()
    PotentialMitigationsDescription = fields.Str()
    FunctionalAreas = fields.Str()
    AffectedResources = fields.Str()
    TaxonomyMappingsName = fields.Str()
    TaxonomyMappingsEntryName = fields.Str()

class MakeCWEDetailsSchema(CWEDetailsSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return CWEDetails(**data)


