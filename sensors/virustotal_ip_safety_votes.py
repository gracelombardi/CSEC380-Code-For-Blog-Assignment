import requests
from st2reactor.sensor.base import PollingSensor


class VirusTotalPollingSensor(PollingSensor):
    """This sensor polls VirusTotal for IP Safety Votes."""

    # pylint: disable=too-many-instance-attributes
    def __init__(self, sensor_service, config=None, poll_interval=None):
        """This function initializes the sensor.

            Args:
                sensor_service (str): The sensor service.
                config (None): The config for the sensor.
                poll_interval (None): The polling interval for the sensor.

            Returns:
                This returns an instance of the sensor.
        """
        super(VirusTotalPollingSensor, self).__init__(sensor_service=sensor_service,
                                                      config=config,
                                                      poll_interval=poll_interval)

        self._logger = self.sensor_service.get_logger(name=self.__class__.__name__)
        self.api_key = self.sensor_service.get_value(self.virus_total_api_key, local=False)
        self.test_ip = self.sensor_service.get_value(self.test_ip, local=False)

    def setup(self):
        """This function sets the global variables for the sensor."""

    def poll(self):
        """This function starts the polling of the sensor."""
        headers = {'x-apikey': self.api_key}

        response = requests.get('https://www.virustotal.com/api/v3/ip_addresses/' + self.test_ip +
                                '/votes',
                                headers=headers)
        self.trigger_payload(response.json())

    def trigger_payload(self, results):
        """This function triggers the result payload to the UI

            Args:
                results (dict): The ip safety votes results
        """
        trigger = 'virustotal.ip_safety_votes'

        payload = {
            'results': results
        }
        self._sensor_service.dispatch(trigger=trigger, payload=payload)

    def cleanup(self):
        """This is called when the st2 system goes down. You can perform cleanup operations
         like closing the connections to external system here."""

        # Close the Kafka Connection
        pass

    def add_trigger(self, trigger):
        """This method is called when trigger is created

            Args:
                trigger (str): The trigger for the sensor
        """
        pass

    def update_trigger(self, trigger):
        """This method is called when trigger is updated

            Args:
                trigger (str): The trigger for the sensor
        """
        pass

    def remove_trigger(self, trigger):
        """This method is called when trigger is deleted

            Args:
                trigger (str): The trigger for the sensor
        """
        pass
