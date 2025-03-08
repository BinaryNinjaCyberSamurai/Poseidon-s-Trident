class Firewall:
    def __init__(self):
        self.rules = []

    def add_rule(self, rule):
        self.rules.append(rule)
        self.apply_rules()

    def get_rules(self):
        return self.rules

    def apply_rules(self):
        # Placeholder for applying rules to the actual firewall system
        # This could involve system calls or interfacing with firewall software
        for rule in self.rules:
            print(f"Applying rule: {rule}")

    def remove_rule(self, rule):
        if rule in self.rules:
            self.rules.remove(rule)
            self.apply_rules()
