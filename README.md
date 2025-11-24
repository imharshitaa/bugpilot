# BugPilot

**Pentesting Automation Framework Pilot**

- Recon & discovery  
- Automated vulnerability checks  
- Payload-based testing  
- Result validation  
- Severity classification  
- Report generation

----------------------------------

Features:
1. Recon automation
2. Vulnerability scanning
3. payloads based testing
4. AI assist
5. automated reporting

Installation and setup steps:
-

1. Install:
```
git clone

```

2. Running bugpilot:
```
python3 main.py --target 
```

3. For custom scope file

```
python3 main.py --scope config/scope.txt
```

4. Specify modules
```
python3 main.py --modules xss,sqli,ssrf
```

---------------

MODULES TRACK:
-

| Module Name  | File                      | Status     | Description                    |
| ------------ | ------------------------- | ---------- | ------------------------------ |
| XSS          | `modules/xss.py`          | WIP  | Reflected & DOM XSS checks     |
| SQLi         | `modules/sqli.py`         | WIP   | Union-based & error-based SQLi |
| SSRF         | `modules/ssrf.py`         | WIP     | Basic SSRF detection           |
| RCE          | `modules/rce.py`          | WIP     | Command execution tests        |
| IDOR         | `modules/idor.py`         | WIP | Authorization bypass           |
| API Security | `modules/api_security.py` | WIP     | OWASP API Top 10  of API repo             |



(Use cases: appsec audits, security reviews, pentesting)






















