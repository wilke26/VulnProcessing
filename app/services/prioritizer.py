import yaml


class Prioritizer:
    def __init__(self, rules_path):
        with open(rules_path) as f:
            self.rules = yaml.safe_load(f)

    def prioritize(self, finding):
        score = 0
        cvss = finding.get("cvss", 0)
        criticality = finding.get("criticality", "").lower()
        if cvss >= self.rules["cvss"]["critical"]:
            score += 5
        elif cvss >= self.rules["cvss"]["high"]:
            score += 3
        # weitere Kriterien gemäß rules.yaml
        if criticality == "hoch":
            score += 2
        return score
