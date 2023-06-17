import csv
import json
from vr.functions.mysql_db import connect_to_db


PARENTHESIS_AND = ") and "
AND = " and "


class ThreatModeler(object):
    def __init__(self):
        self.elements = {}
        self.cur, self.db = connect_to_db()

    def run(self, form):
        self.get_input(form)
        self.process_input()
        threats, controls, applied_solutions, threats_mitigated = self.find_threats()
        return threats, controls, applied_solutions, threats_mitigated

    def get_input(self, form):
        self.read_in_responses(form)

    def process_input(self):
        for e in self.elements:
            self.map_dfd_type()
            self.elements[e] = self.apply_default_controls(self.elements[e])
            self.elements[e] = self.apply_data(self.elements[e])

    def apply_data(self, element):
        if 'Processed Data Formats' in element:
            for format in element['Processed Data Formats']:
                element['data']['formats'].append(format)
        return element

    def apply_default_controls(self, element):
        lambda_controls, process_controls, server_controls, dataflow_controls, datastore_controls = self.read_controls_csv()
        if element['DFDType'] == 'Lambda':
            element = self.apply_control_handler(element, lambda_controls)
        elif element['DFDType'] == 'Process':
            element = self.apply_control_handler(element, process_controls)
        elif element['DFDType'] == 'Server':
            element = self.apply_control_handler(element, server_controls)
        elif element['DFDType'] == 'Dataflow':
            element = self.apply_control_handler(element, dataflow_controls)
        elif element['DFDType'] == 'Datastore':
            element = self.apply_control_handler(element, datastore_controls)
        return element

    def apply_control_handler(self, element, controlset):
        for control in controlset:
            control_dict = controlset[control]
            if control_dict['type'] == 'bool':
                element['conditions'].append(
                    f'target.controls.{control} is False'
                )
            elif control_dict['type'] == 'text':
                element['conditions'].append(
                    f'target.controls.{control} == ""'
                )
        return element

    def map_dfd_type(self):
        for e in self.elements:
            elem_type = self.elements[e]['Type']
            if elem_type == 'Application':
                self.elements[e]['DFDType'] = 'Process'
            elif elem_type == 'Database':
                self.elements[e]['DFDType'] = 'Datastore'
            else:
                print('placeholder for more element types')

    def find_threats(self):

        threats = self.read_threats_csv()
        for e in self.elements:
            elem_type = self.elements[e]['DFDType']
            for threat in threats:
                if elem_type in threat['target']:
                    match = self.condition_check(self.elements[e], self.elements[e]['conditions'], threat['condition'])
                    if match:
                        self.elements[e]['threats'].append(threat)
            threats, controls, applied_solutions, threats_mitigated = self.generate_threat_control_options(self.elements[e]['threats'], self.elements[e])
        return threats, controls, applied_solutions, threats_mitigated

    def condition_check(self, element, elem_conditions, threat_conditions):
        match = True
        all_must_match, any_can_match, all_must_not_match, any_can_not_match = self.parse_json_conditions(threat_conditions)

        if all_must_match:
            match = self._parse_all_must_match(match, any_can_match, all_must_match, elem_conditions, element)
        elif any_can_match:
            any_matches = False
            for req in any_can_match:
                if req in elem_conditions:
                    any_matches = True
            if not any_matches:
                match = False
        return match

    def _parse_all_must_match(self, match, any_can_match, all_must_match, elem_conditions, element):
        if any_can_match:
            match = self._parse_any_must_match(match, all_must_match, elem_conditions, any_can_match)
        else:
            for req in all_must_match:
                if '=' in req:
                    match = self._parse_equal_match(match, req, element)
                else:
                    if req not in elem_conditions:
                        match = False
        return match

    def _parse_any_must_match(self, match, all_must_match, elem_conditions, any_can_match):
        for req in all_must_match:
            if req not in elem_conditions:
                match = False
        if match:
            any_matches = False
            for req in any_can_match:
                if req in elem_conditions:
                    any_matches = True
            if not any_matches:
                match = False
        return match

    def _parse_equal_match(self, match, req, element):
        if ' for d in target.data)' in req:  # means it is a data requirement
            if 'd.format ==' in req:
                elem = req.split("d.format == '")[1].split("'")[0]
                if elem not in element['data']['formats']:
                    match = False
        else:
            if req.endswith("'"):  # Example: target.environment == "Production"
                match = self._parse_equal_match_handler(req, element)
        return match

    def _parse_equal_match_handler(self, req, element):
        if ' == ' in req:
            if req not in element['conditions']:
                match = False
        else:
            if req.replace('!=', '==') in element['conditions']:
                match = False
        return match

    def parse_json_conditions(self, raw_conditions):
        all_must_match = []
        any_can_match = []
        all_must_not_match = []
        any_can_not_match = []
        if raw_conditions.startswith('(') and PARENTHESIS_AND in raw_conditions:
            placeholder = raw_conditions.split(PARENTHESIS_AND)[1]
            parenth = raw_conditions.split(PARENTHESIS_AND)[0]
            raw_conditions = placeholder + AND + parenth + ')'
        if ' (' in raw_conditions:
            all_must_match, any_can_match, all_must_not_match, any_can_not_match = \
                self._parse_parenthesis(raw_conditions, all_must_match, any_can_match, all_must_not_match, any_can_not_match)
        else:
            if AND in raw_conditions:
                all_matches = raw_conditions.split(AND)
                for i in all_matches:
                    all_must_match.append(i)
            elif ' or ' in raw_conditions:
                parts = raw_conditions.split(' or ')
                for i in parts:
                    any_can_match.append(i)
            else:
                all_must_match.append(raw_conditions)
        return all_must_match, any_can_match, all_must_not_match, any_can_not_match

    def _parse_parenthesis(self, raw_conditions, all_must_match, any_can_match, all_must_not_match, any_can_not_match):
        parenthesis_cnt = raw_conditions.count('(')
        if parenthesis_cnt == 1:
            parenthesis_modifier = raw_conditions.split(' (')[0]
            all_words = parenthesis_modifier.split()
            parenthesis_modifier = all_words[len(all_words) - 1]
            parenthesis_portion = raw_conditions.split(' (')[1].replace('(', '').replace(')', '')
            if parenthesis_modifier == 'and':
                prefix = raw_conditions.split(' and (')[0]
                all_must_match.append(prefix)
                if ' or ' in parenthesis_portion:
                    parts = parenthesis_portion.split(' or ')
                    for i in parts:
                        any_can_match.append(i)
        return all_must_match, any_can_match, all_must_not_match, any_can_not_match

    def generate_threat_control_options(self, threats, element):
        controls = []
        applied_solutions = []
        threats_mitigated = []
        solutions = self.read_solutions_csv(element)
        modified_threats = []
        for threat in threats:

            threat['status'] = 'review' ## review, suggested_control, planned_control, implemented_control, mitigated, transfered, avoided, accepted
            threat['control_option'] = ''
            threat['validation_method'] = ''
            threat_id = threat['SID']
            for solution in solutions:
                solution_id = list(solution.keys())[0]
                if (solution_id == threat_id):
                    threat_target_str = ','.join(threat['target'])
                    if (solution[solution_id]['solution_target'] in threat_target_str):
                        applied_solutions.append(solution)
                        threats_mitigated.append(threat_id)
                        threat['control_option'] = solution[list(solution.keys())[0]]['solution']
                        threat['validation_method'] = solution[list(solution.keys())[0]]['validation']
                        threat['status'] = 'suggested_control'
            modified_threats.append(threat)
        for solution in applied_solutions:
            control = solution[list(solution.keys())[0]]['solution']
            if control not in controls:
                controls.append(control)
        return modified_threats, controls, applied_solutions, threats_mitigated

    def generate_threats_csv(self):
        with open('threats.json', errors='ignore') as f_in:
            threats = json.load(f_in)
        with open('threat_report.csv', 'w', newline='') as f_out:
            csv_writer = csv.writer(f_out)
            for t in threats:
                row = [
                    t['SID'], ", ".join(t['target']), t['description'], t['details'],
                    t['Likelihood of Attack'] if 'Likelihood of Attack' in t else '',
                    t['severity'], t['condition'], t['prerequisites'], t['mitigations'], t['example'], t['references']
                ]
                csv_writer.writerow(row)

    def read_threats_csv(self):
        json_threats = []
        sql = 'SELECT * FROM TmThreats'
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        for l in rows:
            targets = l[2].split(', ')
            new = {
                "SID": l[0],
                "target": targets,
                "description": l[3],
                "details": l[4],
                "Likelihood Of Attack": l[5],
                "severity": l[6],
                "condition": l[7],
                "prerequisites": l[8],
                "mitigations": l[9],
                "example": l[10],
                "references": l[11]
            }
            json_threats.append(new)

        return json_threats

    def read_controls_csv(self):
        lambda_controls = {}
        process_controls = {}
        server_controls = {}
        dataflow_controls = {}
        datastore_controls = {}
        sql = 'SELECT * FROM TmControls'
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        for l in rows:
            if l[5]:
                lambda_controls[l[2]] = {
                    'type': l[3],
                    'description': l[4]
                }
            if l[6]:
                process_controls[l[2]] = {
                    'type': l[3],
                    'description': l[4]
                }
            if l[7]:
                server_controls[l[2]] = {
                    'type': l[3],
                    'description': l[4]
                }
            if l[8]:
                dataflow_controls[l[2]] = {
                    'type': l[3],
                    'description': l[4]
                }
            if l[9]:
                datastore_controls[l[2]] = {
                    'type': l[3],
                    'description': l[4]
                }

        return lambda_controls, process_controls, server_controls, dataflow_controls, datastore_controls

    def read_solutions_csv(self, element):
        solutions = []
        sql = 'SELECT * FROM TmSolutions'
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        for l in rows:
            if l[7] and l[2] == element['DFDType']:
                new = {
                    l[0]: {
                        'solution_target': l[2],
                        'attribute': ", ".join(l[3]) if ',' in l[3] else l[3],
                        'threat_description': l[4],
                        'solution_type': l[5],
                        'fix': l[6],
                        'solution': l[7],
                        'validation': l[8]
                    }
                }
                solutions.append(new)

        return solutions
    
    def read_questions_csv(self):
        questions = {}
        sql = 'SELECT * FROM TmQuestions'
        self.cur.execute(sql)
        rows = self.cur.fetchall()
        for l in rows:
            questions[l[0]] = {
                'question': l[2],
                'condition_applied': l[3] if l[3] else "",
                'options': l[4] if l[4] else "",
                'type': l[5] if l[5] else "",
                'prerequisites': l[6] if l[6] else "",
                'targets': l[7].split(', ') if l[7] and ',' in l[7] else "",
                'produces': l[8] if l[8] else ""
            }
        return questions

    def read_in_responses(self, form):
        entities = []
        questions = self.read_questions_csv()
        for q in questions:
            name = questions[q]['question']
            if name in form:
                val = form[name]
                produces = questions[q]['produces']
                if produces and produces == 'Elements':
                    entities.append(val)
                    self.elements[val] = {'conditions': [], 'threats': [],
                                                   'data': {'formats': [], 'categories': [], 'classification': ''}}
                    # The type of review: Application, System, Network, Other
                    self.elements[val]['Type'] = 'Application'
        for e in self.elements:
            self._parse_elements(e, questions, form)

    def _parse_elements(self, e, questions, form):
        elem_type = self.elements[e]['Type']
        for q in questions:
            name = questions[q]['question']
            if name in form:
                val = form[name]
                targets = questions[q]['targets']
                if elem_type in targets:
                    opts = questions[q]['options']
                    if opts == 'bool' and val == 'Yes':
                        self.elements[e]['conditions'].append(questions[q]['condition_applied'])
