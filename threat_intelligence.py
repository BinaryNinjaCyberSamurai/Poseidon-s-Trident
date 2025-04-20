class ThreatIntelligence:
    def __init__(self):
        # Initialize an empty set to store threat indicators
        self.threat_indicators = set()

    def update(self, feed):
        """
        Update threat intelligence with new indicators from the specified feed.

        Args:
            feed (list): A list of threat indicators (e.g., IP addresses, domains).
        """
        # Add new indicators to the set
        self.threat_indicators.update(feed)

    def get_threat_indicators(self):
        """
        Get all stored threat indicators.

        Returns:
            set: A set of threat indicators.
        """
        return self.threat_indicators

# Example usage
if __name__ == "__main__":
    threat_intel = ThreatIntelligence()
    threat_feed = ["192.168.1.1", "example.com", "malicious-domain.org"]

    # Update threat intelligence with the feed
    threat_intel.update(threat_feed)

    # Get all threat indicators
    all_indicators = threat_intel.get_threat_indicators()
    print("Stored threat indicators:")
    for indicator in all_indicators:
        print(indicator)
