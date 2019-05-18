import requests

from apps import App, action

def vt_api_post(file_hash, api_key):
    params = {'apikey': api_key}
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params['resource'] = file_hash
    return requests.post(url, params)

def vt_api_url_post(urlToGetReport, api_key):
    params = {'apikey': api_key}
    url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params['resource'] = urlToGetReport
    params['scan'] = 1
    return requests.post(url, params)


def vt_api_post_ip_report(ip_address, api_key):
    params = {'apikey': api_key}
    params['ip'] = ip_address
    url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
    return requests.get(url, params)


@action
def hash_report(file_hash, api_key):
    result = vt_api_post(file_hash, api_key)
    resultObject = result.json()
    maliciousConfidence = resultObject["positives"]/resultObject["total"]
    return {"MaliciousConfidence": maliciousConfidence, "Report": resultObject}, "Report"


@action
def ip_report(ip_address, api_key):
    # TODO: Add IP address validation
    result = vt_api_post_ip_report(ip_address, api_key)
    resultObject = result.json()
    ip_report_result = resultObject
    return ip_report_result, "IPAddressReport"


@action
def url_report(url, api_key):
    result = vt_api_url_post(url, api_key)
    return result.json(), "Report"
