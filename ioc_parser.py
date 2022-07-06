from email import message
import requests


def request_url(url):
    parser_url = "https://api.iocparser.com/url"
    payload = {"url": url}
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request(
        "POST", parser_url, headers=headers, json=payload).json()
    print(response)
    return response


def request_raw(raw):
    parser_url = "https://api.iocparser.com/raw"
    headers = {
        'Content-Type': 'text/plain'
    }
    response = requests.request(
        "POST", parser_url, headers=headers, data=raw).json()
    return response


def parse_response(response):
    status = response["status"]
    if status == "error":
        return response, status

    data = response['data']
    iocs = {
        'md5': data['FILE_HASH_MD5'],
        'sha256': data['FILE_HASH_SHA256'],
        'domain': data['DOMAIN'],
        'ip': data['IPv4'],
        'email': data['EMAIL']
    }
    return {k: v for k, v in iocs.items() if v}, status


def parse_meta(response):
    meta = response['meta']
    return {
        'description': meta['description'],
        'title': meta['title']
    }


def parse_mitre_ttp(response):
    data = response['data']
    ttp = data['MITRE_ATT&CK']
    return ttp


def parse_yara(response):
    data = response['data']
    return data['YARA_RULE']


def save_yara(yara):
    with open('yara.yar', 'w') as file:
        for rule in yara:
            file.write(rule)


def ioc_to_message(iocs):
    message = ''
    for type, values in iocs.items():
        message += f"*{type}*\r\n"
        for val in values:
            message += f"{val}\r\n"
        message += f"\r\n"
    return message


def meta_to_message(meta):
    title = meta['title']
    description = meta['description']
    message = f"*{title}*\r\n"
    message += f"{description}\r\n"
 

def process_ioc(url):
    response = request_url(url)
    iocs, status = parse_response(response)
    if status == "error":
        return iocs["error"], None

    yara = parse_yara(response)
    if yara:
        save_yara(yara)

    ttps = parse_mitre_ttp(response)
    meta = parse_meta(response)
    message_iocs = ioc_to_message(iocs)
    message_ttps = f"TTPs: {len(ttps)}"
    message_description = meta_to_message(meta)
    message = message_description
    message += message_ttps
    message += message_iocs
    return message, yara
