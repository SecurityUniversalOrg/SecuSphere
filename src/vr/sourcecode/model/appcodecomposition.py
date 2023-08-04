import datetime as dt
from vr import db, app
from marshmallow import Schema, fields
from marshmallow import post_load


class AppCodeComposition(db.Model):
    __table_args__ = {'extend_existing': True}
    __tablename__ = 'AppCodeComposition'
    ID = db.Column(db.Integer, primary_key=True)
    AddDate = db.Column(db.DateTime, index=True, default=dt.datetime.utcnow, nullable=False)
    ApplicationID = db.Column(db.Integer, db.ForeignKey('BusinessApplications.ID', ondelete='CASCADE'))
    BranchName = db.Column(db.String(600))
    JavaFiles = db.Column(db.Integer)
    JavaLoc = db.Column(db.Integer)
    XmlFiles = db.Column(db.Integer)
    XmlLoc = db.Column(db.Integer)
    JsonFiles = db.Column(db.Integer)
    JsonLoc = db.Column(db.Integer)
    YamlFiles = db.Column(db.Integer)
    YamlLoc = db.Column(db.Integer)
    ConfFiles = db.Column(db.Integer)
    ConfLoc = db.Column(db.Integer)
    PythonFiles = db.Column(db.Integer)
    PythonLoc = db.Column(db.Integer)
    PerlFiles = db.Column(db.Integer)
    PerlLoc = db.Column(db.Integer)
    CFiles = db.Column(db.Integer)
    CLoc = db.Column(db.Integer)
    GoFiles = db.Column(db.Integer)
    GoLoc = db.Column(db.Integer)
    JavascriptFiles = db.Column(db.Integer)
    JavascriptLoc = db.Column(db.Integer)
    CSharpFiles = db.Column(db.Integer)
    CSharpLoc = db.Column(db.Integer)
    CppFiles = db.Column(db.Integer)
    CppLoc = db.Column(db.Integer)
    PhpFiles = db.Column(db.Integer)
    PhpLoc = db.Column(db.Integer)
    TypescriptFiles = db.Column(db.Integer)
    TypescriptLoc = db.Column(db.Integer)
    SwiftFiles = db.Column(db.Integer)
    SwiftLoc = db.Column(db.Integer)
    RubyFiles = db.Column(db.Integer)
    RubyLoc = db.Column(db.Integer)
    KotlinFiles = db.Column(db.Integer)
    KotlinLoc = db.Column(db.Integer)
    DartFiles = db.Column(db.Integer)
    DartLoc = db.Column(db.Integer)
    ScalaFiles = db.Column(db.Integer)
    ScalaLoc = db.Column(db.Integer)
    ShellFiles = db.Column(db.Integer)
    ShellLoc = db.Column(db.Integer)
    RFiles = db.Column(db.Integer)
    RLoc = db.Column(db.Integer)
    LuaFiles = db.Column(db.Integer)
    LuaLoc = db.Column(db.Integer)
    GroovyFiles = db.Column(db.Integer)
    GroovyLoc = db.Column(db.Integer)
    RustFiles = db.Column(db.Integer)
    RustLoc = db.Column(db.Integer)
    MatlabFiles = db.Column(db.Integer)
    MatlabLoc = db.Column(db.Integer)
    JuliaFiles = db.Column(db.Integer)
    JuliaLoc = db.Column(db.Integer)
    FortranFiles = db.Column(db.Integer)
    FortranLoc = db.Column(db.Integer)
    ObjCFiles = db.Column(db.Integer)
    ObjCLoc = db.Column(db.Integer)
    ElixirFiles = db.Column(db.Integer)
    ElixirLoc = db.Column(db.Integer)
    HaskellFiles = db.Column(db.Integer)
    HaskellLoc = db.Column(db.Integer)
    ElmFiles = db.Column(db.Integer)
    ElmLoc = db.Column(db.Integer)
    FSharpFiles = db.Column(db.Integer)
    FSharpLoc = db.Column(db.Integer)
    ClojureFiles = db.Column(db.Integer)
    ClojureLoc = db.Column(db.Integer)
    CobolFiles = db.Column(db.Integer)
    CobolLoc = db.Column(db.Integer)

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def __repr__(self):
        return '<AppCodeComposition(name={self.AddDate!r})>'.format(self=self)


class AppCodeCompositionSchema(Schema):
    ID = fields.Int()
    AddDate = fields.DateTime()
    ApplicationID = fields.Int()
    BranchName = fields.Str()
    JavaFiles = fields.Int()
    JavaLoc = fields.Int()
    XmlFiles = fields.Int()
    XmlLoc = fields.Int()
    JsonFiles = fields.Int()
    JsonLoc = fields.Int()
    YamlFiles = fields.Int()
    YamlLoc = fields.Int()
    ConfFiles = fields.Int()
    ConfLoc = fields.Int()
    PythonFiles = fields.Int()
    PythonLoc = fields.Int()
    PerlFiles = fields.Int()
    PerlLoc = fields.Int()
    CFiles = fields.Int()
    CLoc = fields.Int()
    GoFiles = fields.Int()
    GoLoc = fields.Int()
    JavascriptFiles = fields.Int()
    JavascriptLoc = fields.Int()
    CSharpFiles = fields.Int()
    CSharpLoc = fields.Int()
    CppFiles = fields.Int()
    CppLoc = fields.Int()
    PhpFiles = fields.Int()
    PhpLoc = fields.Int()
    TypescriptFiles = fields.Int()
    TypescriptLoc = fields.Int()
    SwiftFiles = fields.Int()
    SwiftLoc = fields.Int()
    RubyFiles = fields.Int()
    RubyLoc = fields.Int()
    KotlinFiles = fields.Int()
    KotlinLoc = fields.Int()
    DartFiles = fields.Int()
    DartLoc = fields.Int()
    ScalaFiles = fields.Int()
    ScalaLoc = fields.Int()
    ShellFiles = fields.Int()
    ShellLoc = fields.Int()
    RFiles = fields.Int()
    RLoc = fields.Int()
    LuaFiles = fields.Int()
    LuaLoc = fields.Int()
    GroovyFiles = fields.Int()
    GroovyLoc = fields.Int()
    RustFiles = fields.Int()
    RustLoc = fields.Int()
    MatlabFiles = fields.Int()
    MatlabLoc = fields.Int()
    JuliaFiles = fields.Int()
    JuliaLoc = fields.Int()
    FortranFiles = fields.Int()
    FortranLoc = fields.Int()
    ObjCFiles = fields.Int()
    ObjCLoc = fields.Int()
    ElixirFiles = fields.Int()
    ElixirLoc = fields.Int()
    HaskellFiles = fields.Int()
    HaskellLoc = fields.Int()
    ElmFiles = fields.Int()
    ElmLoc = fields.Int()
    FSharpFiles = fields.Int()
    FSharpLoc = fields.Int()
    ClojureFiles = fields.Int()
    ClojureLoc = fields.Int()
    CobolFiles = fields.Int()
    CobolLoc = fields.Int()


class MakeAppCodeCompositionSchema(AppCodeCompositionSchema):
    @post_load
    def make_it(self, data, **kwargs):
        return AppCodeComposition(**data)



