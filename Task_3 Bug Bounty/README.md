# 🛡️ Simple Python Flaw Detector

A lightweight static analysis tool that scans Python source code for common security risks and bad practices using Python's built-in `ast` module. Results are displayed in a clean terminal UI powered by **Rich**.

---

## 📌 Overview

This tool parses Python code into an Abstract Syntax Tree (AST) and inspects it for patterns that frequently introduce bugs or security vulnerabilities.

It currently detects:

✔ Use of potentially dangerous functions  
✔ Possible hardcoded secrets (like passwords)

---

## 🚨 Detection Rules

### 1. Insecure Function Usage

Flags calls to functions often associated with security risks:

- `eval()`
- `exec()`
- `input()`
- `os.system()`

These functions may lead to:

- Code injection
- Command execution vulnerabilities
- Unsafe user input handling

---

### 2. Hardcoded Secrets

Detects assignments to variables containing the word:

- `password`

Example:

```python
password = "123456"
```
While not always a vulnerability, hardcoded credentials are a common security mistake.

⚙️ How It Works

The scanner:

Reads a Python file

Parses it into an AST

Visits nodes using ast.NodeVisitor

Records suspicious patterns

Displays findings using a Rich table

📦 Requirements

Install dependencies:

```
pip install rich
```
Python version:

Python 3.8+
▶️ Usage

Modify the target file name inside the script:
```
results = analyze_file('target_code.py')
```
Then run:

python flaw_detector.py
✅ Example Output
┏━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Line ┃ Issue Type           ┃ Details                              ┃
┡━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
┃ 12   ┃ Insecure Function    ┃ Use of eval() detected               ┃
┃ 25   ┃ Hardcoded Secret     ┃ Variable 'password' might contain... ┃
└──────┴──────────────────────┴──────────────────────────────────────┘
⚠️ Limitations

This is a basic heuristic scanner, not a full security analyzer.

It does not:

❌ Understand context or intent
❌ Detect complex vulnerabilities
❌ Replace professional tools

False positives are expected.

🚀 Possible Improvements

Future enhancements could include:

Detecting API keys / tokens

Checking unsafe file operations

Identifying SQL injection patterns

Severity scoring

CLI arguments for file selection

Directory scanning

🧠 Educational Purpose

This project is ideal for:

✔ Learning AST analysis
✔ Understanding static code scanning
✔ Experimenting with Python tooling
✔ Security education

📜 Disclaimer

This tool is for educational use only.

It should not be relied upon for real security auditing.

Always use professional security scanners and manual reviews for production systems.

👨‍💻 Author
## Tamheed 
### Cyber Security Student
#### Intership Project
