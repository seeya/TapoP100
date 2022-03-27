from PyP100 import PyP100

import json
import logging
import time

_LOGGER = logging.getLogger(__name__)

class P110(PyP100.P100):

    def getEnergyUsage(self):
        URL = f"http://{self.ipAddress}/app?token={self.token}"
        Payload = {
            "method": "get_energy_usage",
            "requestTimeMils": int(round(time.time() * 1000)),
        }

        headers = {
            "Cookie": self.cookie
        }

        EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

        SecurePassthroughPayload = {
            "method":"securePassthrough",
            "params":{
                "request": EncryptedPayload
            }
        }
        _LOGGER.debug("getEnergyUsage %s", self.ipAddress)
        r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

        decryptedResponse = self.tpLinkCipher.decrypt(r.json()["result"]["response"])

        return json.loads(decryptedResponse)
    
    def turnOn(self):
        URL = f"http://{self.ipAddress}/app?token={self.token}"
        Payload = {
            "method": "set_device_info",
            "params":{
                "device_on": True 
            },
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": "0A950402-7224-46EB-A450-7362CDB902A2" 
        }

        headers = {
            "Cookie": self.cookie
        }

        EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

        SecurePassthroughPayload = {
            "method": "securePassthrough",
            "params":{
                "request": EncryptedPayload
            }
        }

        r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

        decryptedResponse = self.tpLinkCipher.decrypt(r.json()["result"]["response"])

        return json.loads(decryptedResponse) 

    def turnOff(self):
        URL = f"http://{self.ipAddress}/app?token={self.token}"
        Payload = {
            "method": "set_device_info",
            "params":{
                "device_on": False
            },
            "requestTimeMils": int(round(time.time() * 1000)),
            "terminalUUID": "0A950402-7224-46EB-A450-7362CDB902A2" 
        }

        headers = {
            "Cookie": self.cookie
        }

        EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

        SecurePassthroughPayload = {
            "method": "securePassthrough",
            "params":{
                "request": EncryptedPayload
            }
        }

        r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers, timeout=2)

        decryptedResponse = self.tpLinkCipher.decrypt(r.json()["result"]["response"])

        return json.loads(decryptedResponse) 

    def turnOnWithDelay(self, delay):
        URL = f"http://{self.ipAddress}/app?token={self.token}"
        Payload = {
            "method": "add_countdown_rule",
            "params": {
                "delay": int(delay),
                "desired_states": {
                    "on": True
                },
                "enable": True,
                "remain": int(delay)
            },
            "terminalUUID": "0A950402-7224-46EB-A450-7362CDB902A2" 
        }

        headers = {
            "Cookie": self.cookie
        }

        EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

        SecurePassthroughPayload = {
            "method": "securePassthrough",
            "params": {
                "request": EncryptedPayload
            }
        }

        r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers)

        decryptedResponse = self.tpLinkCipher.decrypt(r.json()["result"]["response"])

        return decryptedResponse

    def turnOffWithDelay(self, delay):
        URL = f"http://{self.ipAddress}/app?token={self.token}"
        Payload = {
            "method": "add_countdown_rule",
            "params": {
                "delay": int(delay),
                "desired_states": {
                    "on": False
                },
                "enable": True,
                "remain": int(delay)
            },
            "terminalUUID": "0A950402-7224-46EB-A450-7362CDB902A2" 
        }

        headers = {
            "Cookie": self.cookie
        }

        EncryptedPayload = self.tpLinkCipher.encrypt(json.dumps(Payload))

        SecurePassthroughPayload = {
            "method": "securePassthrough",
            "params": {
                "request": EncryptedPayload
            }
        }

        r = self.session.post(URL, json=SecurePassthroughPayload, headers=headers)

        decryptedResponse = self.tpLinkCipher.decrypt(r.json()["result"]["response"])

        return decryptedResponse
