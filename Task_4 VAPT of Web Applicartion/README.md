# Web Application Vulnerability Assessment & Penetration Testing (VAPT)

## Overview
This project demonstrates a basic Vulnerability Assessment and Penetration Testing (VAPT) process on a deliberately vulnerable web application (DVWA).  
The goal is to identify, exploit, and document common web application vulnerabilities in a safe lab environment.

## Target Application
- **DVWA (Damn Vulnerable Web Application)**  
  DVWA is a PHP/MySQL web application designed for students and security professionals to practice penetration testing safely.

## Tools Used
- Ubuntu Linux
- Docker (for DVWA setup)
- Nmap (network scanning)
- OWASP ZAP (spidering & vulnerability scanning)
- DVWA (target web app)

## Lab Setup
- Host OS: Ubuntu
- DVWA running in Docker container
- Local testing environment (localhost)
- Browser configured for OWASP ZAP proxy

## Methodology

### 1. Information Gathering
- Used **Nmap** to identify open ports and services on localhost.
- Observed DVWA running on Docker.

### 2. Vulnerability Scanning
- Used **OWASP ZAP** to spider the web application and detect potential vulnerabilities.
- Alerts were recorded in ZAP.

### 3. Exploitation
Successfully exploited the following vulnerabilities:
- SQL Injection
- Cross Site Scripting (XSS)
- Command Injection

### 4. Documentation
All findings were recorded with screenshots and recommended fixes.

## Vulnerabilities Identified

### SQL Injection
- **Severity:** High  
- **Description:** Allows manipulation of database queries.  
- **Payload Used:** `1' OR '1'='1`  
- **Impact:** Database information disclosure, authentication bypass  
- **Mitigation:** Use prepared statements, parameterized queries, input validation  
- **Screenshot:** `screenshots/sql_injection.png`

### Cross Site Scripting (XSS)
- **Severity:** Medium  
- **Description:** Allows attackers to inject scripts into web pages viewed by other users.  
- **Payload Used:** `<script>alert('XSS')</script>`  
- **Impact:** Session hijacking, credential theft, script execution  
- **Mitigation:** Input validation, output encoding, use Content Security Policy (CSP)  
- **Screenshot:** `screenshots/xss.png`

### Command Injection
- **Severity:** High  
- **Description:** Executes system commands via user input.  
- **Payload Used:** `127.0.0.1; ls`  
- **Impact:** Remote command execution, data exposure  
- **Mitigation:** Sanitize inputs, avoid executing system commands  
- **Screenshot:** `screenshots/command_injection.png`

### OWASP ZAP Findings
- **Spider Scan Screenshot:** `screenshots/zap_spider.png`  
- **Alerts Screenshot:** `screenshots/zap_alerts.png`  
- **Description:** ZAP spidered the site to identify reachable URLs and possible vulnerabilities. Alerts showed risk points detected automatically.

### Nmap Scan
- **Description:** Checked open ports and services of the host environment.  
- **Screenshot:** `screenshots/nmap_scan.png`

## Conclusion
This project demonstrates how common web application vulnerabilities can be discovered and exploited in a safe lab environment. Proper input validation, secure coding practices, and periodic security testing can reduce these risks significantly.

## Disclaimer
This project was conducted in a controlled lab environment for educational purposes only. Do not use these techniques on any live or unauthorized systems.

---

**Tamheed – Intern – Cyber Security**
