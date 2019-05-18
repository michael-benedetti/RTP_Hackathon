import logging

from apps import App, action

logger = logging.getLogger("apps")

# def vt_api_post(file_hash, api_key):
#     params = {'apikey': api_key}
#     url = 'https://www.virustotal.com/vtapi/v2/file/report'
#     params['resource'] = file_hash
#     requests.post(url, params)
#     if api_key == "":
#         return True
#     else:
#         return False

@action
def is_file_malicious(file_hash, api_key):
    logger.debug("file_hash: {}".format(file_hash))
    logger.debug("file_hash: {}".format(api_key))
    return True, "Malicious"
