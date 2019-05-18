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


def vt_api_helper(endpoint, method, **kwargs):
    base_url = 'https://www.virustotal.com/vtapi/'
    full_url = f'{base_url}{endpoint}'
    return requests.request(method, full_url, params=kwargs)


def vt_api_post_domain(domain, api_key):
    params = {'apikey': api_key}
    params['domain'] = domain
    url = 'https://www.virustotal.com/vtapi/v2/domain/report'
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
    helper_kwargs = {"ip": ip_address,
                     "apikey": api_key,
                     }
    api_endpoint = "v2/ip-address/report"
    result = vt_api_helper(api_endpoint, "GET", **helper_kwargs)
    resultObject = result.json()
    ip_report_result = resultObject
    return ip_report_result, "IPAddressReport"


@action
def url_report(url, api_key):
    result = vt_api_url_post(url, api_key)
    return result.json(), "Report"


@action
def domain_report(domain, api_key):
    result = vt_api_post_domain(domain, api_key)
    resultObject = result.json()
    domain_report_result = resultObject
    return domain_report_result, "DomainReport"