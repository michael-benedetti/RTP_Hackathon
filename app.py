import requests

from apps import App, action

def vt_api_post(file_hash, api_key):
    params = {'apikey': api_key}
    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    params['resource'] = file_hash
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
    helper_kwargs = {"resource": file_hash,
                     "apikey": api_key}
    api_endpoint = "v2/file/report"
    result = vt_api_helper(api_endpoint, "POST", **helper_kwargs)
    resultObject = result.json()
    maliciousConfidence = resultObject["positives"]/resultObject["total"]
    return {"MaliciousConfidence": maliciousConfidence, "Report": resultObject, "FileHash": file_hash}, "Report"


@action
def ip_report(ip_address, api_key):
    # TODO: Add IP address validation
    helper_kwargs = {"ip": ip_address,"apikey": api_key}
    api_endpoint = "v2/ip-address/report"
    result = vt_api_helper(api_endpoint, "GET", **helper_kwargs)
    resultObject = result.json()
    ip_report_result = resultObject
    return ip_report_result, "IPAddressReport"


@action
def url_report(url, api_key):
    endpoint = "v2/url/report"
    kwargs = {'resource': url, 'apikey': api_key}
    result = vt_api_helper(endpoint, "POST", **kwargs)
    return result.json(), "Report"


@action
def domain_report(domain, api_key):
    helper_kwargs = {"domain": domain,
                     "apikey": api_key,
                     }
    api_endpoint = "v2/domain/report"
    result = vt_api_helper(api_endpoint, "GET", **helper_kwargs)
    resultObject = result.json()
    domain_report_result = resultObject
    return domain_report_result, "DomainReport"

@action
def comment_on_file(comments, fileHash, api_key):
    endpoint = "v2/comments/put"
    kwargs = {'apikey': api_key, 'resource': fileHash, 'comment': comments}
    result = vt_api_helper(endpoint, "POST", **kwargs)
    resultJson = result.json()

    return resultJson['verbose_msg'], "Comment"
