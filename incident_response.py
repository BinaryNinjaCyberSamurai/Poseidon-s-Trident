import logging
from abc import ABC, abstractmethod

class Incident(ABC):
    @abstractmethod
    def get_severity(self):
        pass

    @abstractmethod
    def get_details(self):
        pass

    @abstractmethod
    def get_location(self):
        pass

class ServerIncident(Incident):
    def __init__(self, severity, details, location):
        self.severity = severity
        self.details = details
        self.location = location

    def get_severity(self):
        return self.severity

    def get_details(self):
        return self.details

    def get_location(self):
        return self.location

class IncidentResponse:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.handlers = {
            'low': {
                'location1': self._handle_low_severity_location1,
                'location2': self._handle_low_severity_location2,
                'location3': self._handle_low_severity_location3,  # New handler for low severity at location3
            },
            'medium': {
                'location1': self._handle_medium_severity_location1,
                'location2': self._handle_medium_severity_location2,
                'location3': self._handle_medium_severity_location3,  # New handler for medium severity at location3
            },
            'high': {
                'location1': self._new_handle_high_severity_location1,  # Changed handler for high severity at location1
                'location2': self._handle_high_severity_location2,
                'location3': self._handle_high_severity_location3,  # New handler for high severity at location3
            },
            'critical': {  # New severity level 'critical'
                'location1': self._handle_critical_severity_location1,
                'location2': self._handle_critical_severity_location2,
                'location3': self._handle_critical_severity_location3,
            },
        }

    def respond(self, incident):
        severity = incident.get_severity()
        location = incident.get_location()
        handler = self.handlers.get(severity, {}).get(location)
        if not handler:
            self.logger.error(f'No handler for severity {severity} at location {location}')
            return

        handler(incident)

    def _handle_low_severity_location1(self, incident):
        # Implement your low severity response logic for location1 here
        pass

    def _handle_low_severity_location2(self, incident):
        # Implement your low severity response logic for location2 here
        pass

    def _handle_low_severity_location3(self, incident):  # New method for low severity at location3
        # Implement your low severity response logic for location3 here
        pass

    def _handle_medium_severity_location1(self, incident):
        # Implement your medium severity response logic for location1 here
        pass

    def _handle_medium_severity_location2(self, incident):
        # Implement your medium severity response logic for location2 here
        pass

    def _handle_medium_severity_location3(self, incident):  # New method for medium severity at location3
        # Implement your medium severity response logic for location3 here
        pass

    def _new_handle_high_severity_location1(self, incident):  # New method for high severity at location1
        # Implement your new high severity response logic for location1 here
        pass

    def _handle_high_severity_location2(self, incident):
        # Implement your high severity response logic for location2 here
        pass

    def _handle_high_severity_location3(self, incident):  # New method for high severity at location3
        # Implement your high severity response logic for location3 here
        pass

    def _handle_critical_severity_location1(self, incident):  # New method for critical severity at location1
        # Implement your critical severity response logic for location1 here
        pass

    def _handle_critical_severity_location2(self, incident):  # New method for critical severity at location2
        # Implement your critical severity response logic for location2 here
        pass

    def _handle_critical_severity_location3(self, incident):  # New method for critical severity at location3
        # Implement your critical severity response logic for location3 here
        pass
