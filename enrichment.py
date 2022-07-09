from email import header
import requests
import urllib3
from time import sleep
from datetime import datetime, timedelta

from logger import logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VT_KEY = ['f36c750df7101682625fdfd1d0f790d7e81e44c58a388ce88431f51903b48f0f', 'f0b5f86f3a269f8bb14757441b3b4f45eddb28d8e8c2f0112c2476c6934a3c62', '190bef9cb97b1c5a12e4e23a59bf4696554fbe7115f378b001fdeaabb1ea0e20',
          '83f0dfc08ec8d1888786a09b568ee608b07cd7fbf8e033c8f02e3ba55152a1a1', '99851cf3439eb34ad96efc6c94a94c2d0db05411973bb922c33e257f68423246']


def check_vt_quota(key):
    url = f'https://www.virustotal.com/api/v3/users/{key}/api_usage'
    headers = {'x-apikey': key}
    response = requests.get(url, headers=headers).json()
    today = (datetime.now() - timedelta(hours=3)).strftime("%Y-%m-%d")
    print(response['data'].keys())
    quotas = sum(response['data']['daily'][today].values())
    logger.info(
        f"ENRICHMENT {response.status_code} - Today {quotas} requests {key}")


def virustotal_request_hash(hash: str):
    url = f'https://www.virustotal.com/api/v3/files/{hash}'
    for key in VT_KEY:
        headers = {'x-apikey': key, "Accept": "application/json"}
        response = requests.get(url, verify=False, headers=headers)
        logger.info(
            f"[ENRICHMENT] {response.status_code} request hash {hash}")
        if response.status_code == 404:
            logger.info(
            f"[ENRICHMENT] hash {hash} not found")
            return response, response.status_code
        elif response.status_code == 200:
            break
        else:
            check_vt_quota(key)
    return response, response.status_code


def vt_response(data: dict):
    values = data['data']['attributes']
    md5 = sha1 = sha256 = None
    try:
        md5 = values['md5']
        sha1 = values['sha1']
        sha256 = values['sha256']
        logger.info(
            f"[ENRICHMENT] hash enrichment success {values['md5']}")
    except:
        logger.warning(
            f"[ENRICHMENT] hash not found {values['md5']}")
    sleep(15)  # VirusTotal Public API allows only 4 requests per minute
    return {
        'md5': md5,
        'sha1': sha1,
        'sha256': sha256,
    }


def enrichment_hash(hash: str):
    enrichment = {}
    data, status = virustotal_request_hash(hash)
    if status == 200:
        enrichment.update(vt_response(data.json()))
    else:
        logger.warning(
            f"[ENRICHMENT] not enriched {hash}")
    return enrichment
