MITRE_TECHNIQUES = {
    "T1046": {
        "name": "Network Service Scanning",
        "tactic": "Discovery",
        "description": (
            "Adversaries may scan systems for "
            "services and open ports."
        ),
    },
    "T1018": {
        "name": "Remote System Discovery",
        "tactic": "Discovery",
        "description": (
            "Adversaries may attempt to identify "
            "other systems on a network."
        ),
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "tactic": "Command and Control",
        "description": (
            "Adversaries may communicate using "
            "application layer protocols."
        ),
    },
    "T1071.001": {
        "name": "Web Protocols",
        "tactic": "Command and Control",
        "description": (
            "HTTP and HTTPS may be used for "
            "command and control."
        ),
    },
    "T1071.004": {
        "name": "DNS",
        "tactic": "Command and Control",
        "description": (
            "DNS may be abused for command and "
            "control communication."
        ),
    },
    "T1041": {
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": (
            "Adversaries may steal data over an "
            "existing command and control channel."
        ),
    },
    "T1021": {
        "name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": (
            "Adversaries may use remote services "
            "to move between systems."
        ),
    },
}