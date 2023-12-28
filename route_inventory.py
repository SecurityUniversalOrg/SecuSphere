import ast
import csv
import os

class FlaskRouteVisitor(ast.NodeVisitor):
    def __init__(self):
        self.routes = []

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and hasattr(decorator.func, 'attr') and decorator.func.attr == 'route':
                path = self.extract_value(decorator.args[0]) if decorator.args else None
                methods = None
                for kw in decorator.keywords:
                    if kw.arg == 'methods':
                        methods = self.extract_value(kw.value)
                        break
                methods = methods or ['GET']
                self.routes.append((path, methods))
        self.generic_visit(node)

    def extract_value(self, node):
        if isinstance(node, ast.Str):
            return node.s
        elif isinstance(node, ast.List):
            return [self.extract_value(elem) for elem in node.elts]
        elif isinstance(node, ast.Name):
            return node.id  # or handle variable reference differently
        # Add more cases here if needed
        return None
def find_flask_routes(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        node = ast.parse(file.read())
        visitor = FlaskRouteVisitor()
        visitor.visit(node)
        return visitor.routes

def write_routes_to_csv(routes, csv_file_path):
    with open(csv_file_path, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(['Endpoint', 'Methods'])
        for path, methods in routes:
            writer.writerow([path, ', '.join(methods)])

def process_directory(directory):
    routes = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.py'):
                file_path = os.path.join(root, file)
                routes.extend(find_flask_routes(file_path))
    return routes

# Example usage
root_dir = 'src'  # Replace with actual path
csv_file_path = 'flask_endpoints.csv'
routes = process_directory(root_dir)
write_routes_to_csv(routes, csv_file_path)
