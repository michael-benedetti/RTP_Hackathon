import logging
import requests

from apps import App, action

logger = logging.getLogger("apps")

def vt_api_post(file_hash, api_key):
    params = {'apikey': api_key}
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params['resource'] = file_hash
    return requests.post(url, params)

@action
def is_file_hash_malicious(file_hash, api_key):
    result = vt_api_post(file_hash, api_key)
    logger.debug("result: {}".format(result.json()))
    resultObject = result.json()
    maliciousConfidence = resultObject["positives"]/resultObject["total"]
    return maliciousConfidence, "MaliciousConfidence"
