import telebot
import requests
import urllib.parse
import os
import logging

TOKEN = os.getenv('BOT_TOKEN')

# Создаем экземпляр бота
bot = telebot.TeleBot(TOKEN)
# Функция, обрабатывающая команду /start


def request_url(url):
    parser_url = "https://api.iocparser.com/url"
    payload = {"url": url}
    headers = {
        'Content-Type': 'application/json'
    }
    response = requests.request(
        "POST", parser_url, headers=headers, json=payload).json()
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
    print(response)
    status = response["status"]
    print(status)
    if status == "error":
        print(response)
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


def ioc_to_message(iocs):
    answer = ''
    for type, values in iocs.items():
        answer += f"*{type}*\r\n"
        for val in values:
            answer += f"{val}\r\n"
        answer += f"\r\n"
    return answer


def get_yara(response):
    data = response['data']
    return data['YARA_RULE']


def save_yara(yara):
    with open('yara.yar', 'w') as file:
        for rule in yara:
            file.write(rule)


def process_ioc(url):
    response = request_url(url)
    iocs, status = parse_response(response)
    if status == "error":
        return iocs["error"], None
    message = ioc_to_message(iocs)
    yara = get_yara(response)
    if yara:
        save_yara(yara)
    return message, yara


@bot.message_handler(commands=["start"])
def start(m, res=False):
    logging.info('Start')
    bot.send_message(m.chat.id, 'Send url')
# Получение сообщений от юзера


@bot.message_handler(content_types=["text"])
def handle_text(message):
    text, yara = process_ioc(message.text)
    logging.info('ioc processing..............')
    bot.send_message(message.chat.id, text, parse_mode='Markdown')
    logging.info('send message')
    if yara:
        bot.send_document(message.chat.id, document=open(
            'yara.yar', 'rb'), visible_file_name="yara.yar")


# Запускаем бота
bot.polling(none_stop=True, interval=0)
