from email import message
from urllib.parse import non_hierarchical
import requests
from logger import logger
from enrichment import enrichment_hash


def request_url(url):
    parser_url = "https://api.iocparser.com/url"
    payload = {"url": url}
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request(
        "POST", parser_url, headers=headers, json=payload)
    logger.info(
        f"{response.request.method} {response.request.url} {response.status_code} {payload}")
    return response


def request_raw(raw):
    parser_url = "https://api.iocparser.com/raw"
    headers = {
        'Content-Type': 'text/plain'
    }
    response = requests.request(
        "POST", parser_url, headers=headers, data=raw)
    logger.info(
        f"{response.request.method} {response.request.url} {response.status_code} {raw}")
    return response


def parse_response(response):
    data = response.json()['data']
    iocs = {
        'md5': data['FILE_HASH_MD5'],
        'sha256': data['FILE_HASH_SHA256'],
        'sha1': data['FILE_HASH_SHA1'],
        'domain': data['DOMAIN'],
        'ip': data['IPv4'],
        'email': data['EMAIL'],
        'url': data['URL'],
        'ttp': data['MITRE_ATT&CK']
    }
    logger.info(f"Parse data {iocs}")
    return iocs


def parse_meta(response):
    try:
        meta = response.json()['meta']
        logger.info(f"Parse meta {meta}")
        return {
            'description': meta['description'],
            'title': meta['title']
        }
    except KeyError as err:
        logger.error(f"Error parse meta {err}")
        return {}


def parse_mitre_ttp(response):
    try:
        data = response.json()['data']
        ttp = data['MITRE_ATT&CK']
        logger.info(f"Parse ttps {ttp}")
        return ttp
    except KeyError as err:
        logger.error(f"Error parse ttp {err}")
        return []


def parse_yara(response):
    data = response.json()['data']
    return data['YARA_RULE']


def enrich_hash_from_vt(hashes):
    enr = {'md5': set(), 'sha1': set(), 'sha256': set()}
    for type, hash_list in hashes.items():
        for hash in hash_list:
            enrichment = enrichment_hash(hash)
            if enrichment == {}:
                continue
            enr['md5'].add(enrichment['md5'])
            enr['sha256'].add(enrichment['sha256'])
            enr['sha1'].add(enrichment['sha1'])
            logger.info(f"Hash enriched {enrichment}")
    for key, value in enr.items():
        value.update(set(hashes[key]))
    return enr

def update_iocs(iocs):
    hashes = {'md5': iocs['md5'],
              'sha1': iocs['sha1'], 'sha256': iocs['sha256']}
    updated_hashes = enrich_hash_from_vt(hashes)
    iocs.update(updated_hashes)
    return iocs

def save_yara(yara):
    with open(f'{file}.yar', 'w') as file:
        for rule in yara:
            file.write(rule)
    logger.info(f"Yara saved to file {file}")
    return file