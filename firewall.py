# firewall.py

class Firewall:
    def __init__(self):
        # Initialize any necessary data structures or configurations
        self.rules = []  # List of firewall rules (e.g., tuples of (source, destination, action))

    def add_rule(self, source, destination, action):
        """
        Add a new rule to the firewall.

        Args:
            source (str): Source IP address or range.
            destination (str): Destination IP address or range.
            action (str): Action to take (e.g., "ALLOW" or "DENY").
        """
        self.rules.append((source, destination, action))

    def filter(self, traffic):
        """
        Filter incoming traffic based on firewall rules.

        Args:
            traffic (dict): Dictionary containing traffic details (e.g., {'source': '192.168.1.2', 'destination': '10.0.0.1'}).

        Returns:
            str: Action to take for the given traffic ('ALLOW' or 'DENY').
        """
        source_ip = traffic.get('source')
        destination_ip = traffic.get('destination')

        for rule in self.rules:
            rule_source, rule_destination, rule_action = rule
            if self._matches(rule_source, source_ip) and self._matches(rule_destination, destination_ip):
                return rule_action

        # Default action (if no matching rule found)
        return 'DENY'

    def _matches(self, rule_value, traffic_value):
        """
        Check if a traffic value matches a rule value (supports IP ranges).

        Args:
            rule_value (str): Rule value (e.g., IP address or CIDR range).
            traffic_value (str): Traffic value to compare.

        Returns:
            bool: True if the values match, False otherwise.
        """
        # Implement logic to handle IP ranges (e.g., using ipaddress module)
        # Example: Check if traffic_value falls within the rule_value range
        # You can also handle other conditions (e.g., exact match, wildcard, etc.)

        # Placeholder implementation (replace with actual logic)
        return rule_value == traffic_value

# Example usage:
if __name__ == '__main__':
    firewall = Firewall()
    firewall.add_rule(source='192.168.1.0/24', destination='10.0.0.0/24', action='ALLOW')

    # Simulate incoming traffic
    incoming_traffic = {'source': '192.168.1.2', 'destination': '10.0.0.1'}
    result = firewall.filter(incoming_traffic)
    print(f"Action for traffic: {result}")
