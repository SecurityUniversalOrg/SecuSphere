import datetime
import os

from Crypto.PublicKey import RSA
from vr.functions.mysql_db import connect_to_db
from vr.functions.threat_modeling_data import TM_CONTROLS, TM_QUESTIONS, TM_SOLUTIONS, TM_THREATS
from vr.functions.assessment_benchmarks_data import ASSESSMENT_BENCHMARKS, ASSESSMENT_RULES


user_roles = ['Admin', 'Developer', 'DevOps', 'QA', 'Security', 'Application Admin', 'Application Viewer']

sla_policy_dict = [
    {
        "Name": "Default",
        "Description": "The Default SLA Configuration. Products not using an explicit SLA Configuration will use this one.",
        "CriticalSetting": 7,
        "HighSetting": 30,
        "MediumSetting": 90,
        "LowSetting": 120
    },
    {
        "Name": "Expedited",
        "Description": "This policy is applied to mission critical infrastructure.",
        "CriticalSetting": 3,
        "HighSetting": 14,
        "MediumSetting": 30,
        "LowSetting": 60
    }
]

regulations = [
    {
        "Regulation": "California Security Breach Information Act",
        "Acronym": "CA SB-1386",
        "Jurisdiction": "United States, California",
        "Category": "privacy",
        "Reference": "http://en.wikipedia.org/wiki/California_S.B._1386",
        "Description": "In the United States, the California Security Breach Information Act (SB-1386) is a California state law requiring organizations that maintain personal information about individuals to inform those individuals if the security of their information is compromised. The Act stipulates that if there's a security breach of a database containing personal data, the responsible organization must notify each individual for whom it maintained information. The Act, which went into effect July 1, 2003, was created to help stem the increasing incidence of identity theft."
    },
    {
        "Regulation": "Children's Online Privacy Protection Act",
        "Acronym": "COPPA",
        "Jurisdiction": "United States",
        "Category": "privacy",
        "Reference": "http://en.wikipedia.org/wiki/Children%27s_Online_Privacy_Protection_Act",
        "Description": "The Children's Online Privacy Protection Act of 1998 (COPPA) is a United States federal law that applies to the online collection of personal information by persons or entities under U.S. jurisdiction from children under 13 years of age. It details what a website operator must include in a privacy policy, when and how to seek verifiable consent from a parent or guardian, and what responsibilities an operator has to protect children's privacy and safety online including restrictions on the marketing to those under 13. While children under 13 can legally give out personal information with their parents' permission, many websites disallow underage children from using their services altogether due to the amount of cash and work involved in the law compliance."
    },
    {
        "Regulation": "Data Protection Act 1998",
        "Acronym": "DPA",
        "Jurisdiction": "United Kingdom",
        "Category": "privacy",
        "Reference": "http://en.wikipedia.org/wiki/Data_Protection_Act_1998 ",
        "Description": "The Data Protection Act 1998 (DPA) is an Act of Parliament of the United Kingdom of Great Britain and Northern Ireland which defines UK law on the processing of data on identifiable living people. It is the main piece of legislation that governs the protection of personal data in the UK. Although the Act itself does not mention privacy, it was enacted to bring British law into line with the EU data protection directive of 1995 which required Member States to protect people's fundamental rights and freedoms and in particular their right to privacy with respect to the processing of personal data. In practice it provides a way for individuals to control information about themselves. Most of the Act does not apply to domestic use, for example keeping a personal address book. Anyone holding personal data for other purposes is legally obliged to comply with this Act, subject to some exemptions. The Act defines eight data protection principles. It also requires companies and individuals to keep personal information to themselves."
    },
    {
        "Regulation": "Data Protection Directive",
        "Acronym": "Directive 95/46/EC",
        "Jurisdiction": "European Union",
        "Category": "privacy",
        "Reference": "http://en.wikipedia.org/wiki/Data_Protection_Directive",
        "Description": "The Data Protection Directive (officially Directive 95/46/EC on the protection of individuals with regard to the processing of personal data and on the free movement of such data) is a European Union directive adopted in 1995 which regulates the processing of personal data within the European Union. It is an important component of EU privacy and human rights law."
    },
    {
        "Regulation": "Directive on Privacy and Electronic Communications",
        "Acronym": "Directive 2002/58/EC",
        "Jurisdiction": "European Union",
        "Category": "privacy",
        "Reference": "http://en.wikipedia.org/wiki/Directive_on_Privacy_and_Electronic_Communications",
        "Description": "Directive 2002/58 on Privacy and Electronic Communications, otherwise known as E-Privacy Directive, is an EU directive on data protection and privacy in the digital age. It presents a continuation of earlier efforts, most directly the Data Protection Directive. It deals with the regulation of a number of important issues such as confidentiality of information, treatment of traffic data, spam and cookies. This Directive has been amended by Directive 2009/136, which introduces several changes, especially in what concerns cookies, that are now subject to prior consent."
    },
    {
        "Regulation": "Family Educational Rights and Privacy Act",
        "Acronym": "FERPA",
        "Jurisdiction": "United States",
        "Category": "education",
        "Reference": "http://en.wikipedia.org/wiki/Family_Educational_Rights_and_Privacy_Act",
        "Description": "The Family Educational Rights and Privacy Act of 1974 (FERPA) is a United States federal law that gives parents access to their child's education records, an opportunity to seek to have the records amended, and some control over the disclosure of information from the records. With several exceptions, schools must have a student's consent prior to the disclosure of education records after that student is 18 years old. The law applies only to educational agencies and institutions that receive funding under a program administered by the U.S. Department of Education. Other regulations under this act, effective starting January 3, 2012, allow for greater disclosures of personal and directory student identifying information and regulate student IDs and e-mail addresses."
    },
    {
        "Regulation": "General Data Protection Regulation",
        "Acronym": "GDPR",
        "Jurisdiction": "EU & EU Data Extra-Territorial Applicability",
        "Category": "privacy",
        "Reference": "https://www.eugdpr.org/",
        "Description": "The General Data Protection Regulation (GDPR) (EU) 2016/679 is a regulation in EU law on data protection and privacy for all individuals within the European Union (EU) and the European Economic Area (EEA). It also addresses the export of personal data outside the EU and EEA. The GDPR aims primarily to give control to citizens and residents over their personal data and to simplify the regulatory environment for international business by unifying the regulation within the EU. Superseding the Data Protection Directive 95/46/EC, the regulation contains provisions and requirements pertaining to the processing of personally identifiable information of data subjects inside the European Union, and applies to all enterprises, regardless of location, that are doing business with the European Economic Area. Business processes that handle personal data must be built with data protection by design and by default, meaning that personal data must be stored using pseudonymisation or full anonymisation, and use the highest-possible privacy settings by default, so that the data is not available publicly without explicit consent, and cannot be used to identify a subject without additional information stored separately. No personal data may be processed unless it is done under a lawful basis specified by the regulation, or if the data controller or processor has received explicit, opt-in consent from the data's owner. The data owner has the right to revoke this permission at any time."
    },
    {
        "Regulation": "Gramm–Leach–Bliley Act",
        "Acronym": "GLBA",
        "Jurisdiction": "United States",
        "Category": "finance",
        "Reference": "http://en.wikipedia.org/wiki/Gramm%E2%80%93Leach%E2%80%93Bliley_Act",
        "Description": "The Gramm–Leach–Bliley Act (GLBA) is an act of the 106th United States Congress. It repealed part of the Glass–Steagall Act of 1933, removing barriers in the market among banking companies, securities companies and insurance companies that prohibited any one institution from acting as any combination of an investment bank, a commercial bank, and an insurance company. With the bipartisan passage of the Gramm–Leach–Bliley Act, commercial banks, investment banks, securities firms, and insurance companies were allowed to consolidate. Furthermore, it failed to give to the SEC or any other financial regulatory agency the authority to regulate large investment bank holding companies."
    },
    {
        "Regulation": "Health Insurance Portability and Accountability Act",
        "Acronym": "HIPAA",
        "Jurisdiction": "United States",
        "Category": "medical",
        "Reference": "http://en.wikipedia.org/wiki/Health_Insurance_Portability_and_Accountability_Act",
        "Description": "The Health Insurance Portability and Accountability Act of 1996 (HIPAA) was enacted by the United States Congress and signed by President Bill Clinton in 1996. It has been known as the Kennedy–Kassebaum Act or Kassebaum-Kennedy Act after two of its leading sponsors. Title I of HIPAA protects health insurance coverage for workers and their families when they change or lose their jobs. Title II of HIPAA, known as the Administrative Simplification (AS) provisions, requires the establishment of national standards for electronic health care transactions and national identifiers for providers, health insurance plans, and employers."
    },
    {
        "Regulation": "Payment Card Industry Data Security Standard",
        "Acronym": "PCI DSS",
        "Jurisdiction": "United States",
        "Category": "finance",
        "Reference": "http://en.wikipedia.org/wiki/Payment_Card_Industry_Data_Security_Standard",
        "Description": "The Payment Card Industry Data Security Standard (PCI DSS) is a proprietary information security standard for organizations that handle branded credit cards from the major card schemes including Visa, MasterCard, American Express, Discover, and JCB."
    },
    {
        "Regulation": "Personal Information Protection and Electronic Documents Act",
        "Acronym": "PIPEDA",
        "Jurisdiction": "Canada",
        "Category": "privacy",
        "Reference": "http://en.wikipedia.org/wiki/Personal_Information_Protection_and_Electronic_Documents_Act",
        "Description": "The Personal Information Protection and Electronic Documents Act (PIPEDA) is a Canadian law relating to data privacy. It governs how private sector organizations collect, use and disclose personal information in the course of commercial business. In addition, the Act contains various provisions to facilitate the use of electronic documents. PIPEDA became law on 13 April 2000 to promote consumer trust in electronic commerce. The act was also intended to reassure the European Union that the Canadian privacy law was adequate to protect the personal information of European citizens."
    },
    {
        "Regulation": "Sarbanes–Oxley Act",
        "Acronym": "SOX",
        "Jurisdiction": "United States",
        "Category": "finance",
        "Reference": "http://en.wikipedia.org/wiki/Sarbanes%E2%80%93Oxley_Act",
        "Description": "The Sarbanes–Oxley Act of 2002 (SOX) is a United States federal law that set new or enhanced standards for all U.S. public company boards, management and public accounting firms. There are also a number of provisions of the Act that also apply to privately held companies, for example the willful destruction of evidence to impede a Federal investigation."
    }
]

def setup_core_db_tables(ENV):
    cur, db = connect_to_db()
    for role in user_roles:
        if ENV == 'test':
            sql = 'INSERT INTO UserRoles (name) VALUES (?)'
        else:
            sql = 'INSERT INTO UserRoles (name) VALUES (%s)'
        args = (role,)
        cur.execute(sql, args)
        db.commit()
    for p in sla_policy_dict:
        now = datetime.datetime.utcnow()
        if ENV == 'test':
            sql = 'INSERT INTO VulnerabilitySLAs (AddDate, Name, Description, CriticalSetting, HighSetting, MediumSetting, LowSetting) VALUES (?, ?, ?, ?, ?, ?, ?)'
        else:
            sql = 'INSERT INTO VulnerabilitySLAs (AddDate, Name, Description, CriticalSetting, HighSetting, MediumSetting, LowSetting) VALUES (%s, %s, %s, %s, %s, %s, %s)'
        args = (now, p['Name'], p['Description'], p['CriticalSetting'], p['HighSetting'], p['MediumSetting'], p['LowSetting'])
        cur.execute(sql, args)
        db.commit()
    for r in regulations:
        now = datetime.datetime.utcnow()
        if ENV == 'test':
            sql = 'INSERT INTO Regulations (AddDate, Regulation, Acronym, Jurisdiction, Category, Reference, Description) VALUES (?, ?, ?, ?, ?, ?, ?)'
        else:
            sql = 'INSERT INTO Regulations (AddDate, Regulation, Acronym, Jurisdiction, Category, Reference, Description) VALUES (%s, %s, %s, %s, %s, %s, %s)'
        args = (now, r['Regulation'], r['Acronym'], r['Jurisdiction'], r['Category'], r['Reference'], r['Description'])
        cur.execute(sql, args)
        db.commit()
    for i in TM_CONTROLS:
        now = datetime.datetime.utcnow()
        if ENV == 'test':
            sql = 'INSERT INTO TmControls (AddDate, Control, Type, Description, Lambda, Process, Server, Dataflow, Datastore, ExternalEntity) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        else:
            sql = 'INSERT INTO TmControls (AddDate, Control, Type, Description, Lambda, Process, Server, Dataflow, Datastore, ExternalEntity) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
        args = (
        now, i['Control'], i['Type'], i['Description'], i['Lambda'], i['Process'], i['Server'], i['Dataflow'], i['Datastore'], i['ExternalEntity'])
        cur.execute(sql, args)
        db.commit()
    for i in TM_QUESTIONS:
        now = datetime.datetime.utcnow()
        if ENV == 'test':
            sql = 'INSERT INTO TmQuestions (AddDate, Question, Condition, Options, Type, Prereqs, Targets, Produces) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        else:
            sql = 'INSERT INTO TmQuestions (AddDate, Question, `Condition`, `Options`, `Type`, Prereqs, Targets, Produces) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)'
        args = (
        now, i['Question'], i['Condition'], i['Options'], i['Type'], i['Prereqs'], i['Targets'], i['Produces'])
        cur.execute(sql, args)
        db.commit()
    for i in TM_SOLUTIONS:
        now = datetime.datetime.utcnow()
        if ENV == 'test':
            sql = 'INSERT INTO TmSolutions (AddDate, Targets, Attributes, Description, FixType, Fix, Solution, Validation) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        else:
            sql = 'INSERT INTO TmSolutions (AddDate, Targets, Attributes, Description, FixType, Fix, Solution, Validation) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)'
        args = (
        now, i['Targets'], i['Attributes'], i['Description'], i['FixType'], i['Fix'], i['Solution'], i['Validation'])
        cur.execute(sql, args)
        db.commit()
    for i in TM_THREATS:
        now = datetime.datetime.utcnow()
        if ENV == 'test':
            sql = 'INSERT INTO TmThreats (AddDate, Target, Description, Details, LikelihoodOfAttack, Severity, cCondition, Prerequisites, Mitigations, Example, rReferences) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        else:
            sql = 'INSERT INTO TmThreats (AddDate, Target, Description, Details, LikelihoodOfAttack, Severity, cCondition, Prerequisites, Mitigations, Example, rReferences) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
        args = (
        now, i['Target'], i['Description'], i['Details'], i['LikelihoodOfAttack'], i['Severity'], i['cCondition'], i['Prerequisites'], i['Mitigations'], i['Example'], i['rReferences'])
        cur.execute(sql, args)
        db.commit()
    for i in ASSESSMENT_BENCHMARKS:
        now = datetime.datetime.utcnow()
        if ENV == 'test':
            sql = 'INSERT INTO AssessmentBenchmarks (AddDate, Name, Description, Version) VALUES (?, ?, ?, ?)'
        else:
            sql = 'INSERT INTO AssessmentBenchmarks (AddDate, Name, Description, Version) VALUES (%s, %s, %s, %s)'
        args = (
        now, i['Name'], i['Description'], i['Version'])
        cur.execute(sql, args)
        db.commit()
    for i in ASSESSMENT_RULES:
        now = datetime.datetime.utcnow()
        if ENV == 'test':
            sql = 'INSERT INTO AssessmentBenchmarkRules (AddDate, BenchmarkID, Number, Description, ImplementationLevels) SELECT ?, ID, ?, ?, ? FROM AssessmentBenchmarks WHERE Name=?'
        else:
            sql = 'INSERT INTO AssessmentBenchmarkRules (AddDate, BenchmarkID, Number, Description, ImplementationLevels) SELECT %s, ID, %s, %s, %s FROM AssessmentBenchmarks WHERE Name=%s'
        args = (now, i['Number'], i['Description'], i['ImplementationLevels'], i['BanchmarkName'])
        cur.execute(sql, args)
        db.commit()
    db.close()


def generate_key_pair():
    directory = os.path.join(os.getcwd(), "runtime/certs")

    # Create the directory if it doesn't exist
    if not os.path.exists(directory):
        os.makedirs(directory)

    # Generate a RSA key
    key = RSA.generate(2048)

    # Write the private key to a .pem file
    with open(os.path.join(directory, 'cred_store_pri.pem'), 'wb') as f:
        f.write(key.exportKey('PEM'))

    # Write the public key to a .pem file
    public_key = key.publickey()
    with open(os.path.join(directory, 'cred_store_pub.pem'), 'wb') as f:
        f.write(public_key.exportKey('PEM'))

