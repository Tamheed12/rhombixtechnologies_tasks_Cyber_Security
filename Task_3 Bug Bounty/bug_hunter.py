import ast
import os
from rich.console import Console
from rich.table import Table

console = Console()

class FlawDetector(ast.NodeVisitor):
    def __init__(self):
        self.findings = []
        # Define "Dangerous" functions that often lead to bugs
        self.danger_zone = ['eval', 'exec', 'input', 'os.system']

    def visit_Call(self, node):
        # Check if a function call is in our danger list
        if isinstance(node.func, ast.Name):
            if node.func.id in self.danger_zone:
                self.findings.append({
                    "type": "Insecure Function",
                    "detail": f"Use of {node.func.id}() detected (Potential Code Injection)",
                    "line": node.lineno
                })
        self.generic_visit(node)

    def visit_Assign(self, node):
        # Detect potential hardcoded secrets/passwords
        for target in node.targets:
            if isinstance(target, ast.Name) and "password" in target.id.lower():
                self.findings.append({
                    "type": "Hardcoded Secret",
                    "detail": f"Variable '{target.id}' might contain sensitive data",
                    "line": node.lineno
                })
        self.generic_visit(node)

def analyze_file(filename):
    with open(filename, "r") as f:
        tree = ast.parse(f.read())
    
    detector = FlawDetector()
    detector.visit(tree)
    return detector.findings

# --- UI Logic ---
table = Table(title="Bug Bounty Scan Results")
table.add_column("Line", style="cyan")
table.add_column("Issue Type", style="magenta")
table.add_column("Details", style="green")

# Test it on itself or another file
results = analyze_file('target_code.py') 
for bug in results:
    table.add_row(str(bug['line']), bug['type'], bug['detail'])

console.print(table)