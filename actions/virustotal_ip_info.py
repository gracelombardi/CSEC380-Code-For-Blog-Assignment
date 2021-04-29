import requests
from st2common.runners.base_action import Action


class VirusTotalIPInfo(Action):

    def run(self, api_key, test_ip):
        """This action returns information about an IP

            Args:
                api_key (str): The VirusTotal API Key
                test_ip (str): The IP address to analyze

            Returns:
                The JSON result of the IP analysis
        """
        headers = {'x-apikey': api_key}

        response = requests.get('https://www.virustotal.com/api/v3/ip_addresses/' + test_ip,
                                headers=headers)

        return "IP Analysis Result: " + response.json()
