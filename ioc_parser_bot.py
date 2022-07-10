from tokenize import Token
import telebot
import urllib.parse
import os
from logger import logger
from ioc_parser import *

TOKEN = os.getenv('BOT_TOKEN')


bot = telebot.TeleBot(TOKEN)


@bot.message_handler(commands=["start"])
def start(m, res=False):
    logger.info('Start')
    bot.send_message(m.chat.id, 'Send url')


@bot.message_handler(content_types=["text"])
def handle_text(message):
    process_user_message(message)


def process_user_message(message):
    logger.info(
        f'Get message {message.chat.id} {message.chat.username} - "{message.text}"')
    source_type = None
    response = None
    enrichment = True
    hashtags = []
    text = message.text

    if message.entities:
        for entitie in message.entities:
            if entitie.type == "hashtag":
                hashtag = message.text[
                    entitie.offset:entitie.offset+entitie.length]
                hashtags.append(hashtag)
                text = text.replace(hashtag, '')

    if "#no_enr" in hashtags:
        enrichment = False
    if "#report" in hashtags:
        response = request_url(text)
    elif "#twitter" in hashtags:
        response = request_twitter(text)
    else:
        response = request_raw(text)

    send_formated_iocs(message, response, enrichment)


def send_formated_iocs(message, response, enrichment=True):
    if response.status_code == 204:
        bot.send_message(message.chat.id, "No IOC", parse_mode="HTML")
        return
    if response.status_code != 200:
        bot.send_message(
            message.chat.id, response['error'], parse_mode="HTML")
        return

    if enrichment:
        bot.send_message(message.chat.id, "Searching IOCs", parse_mode="HTML")
        bot.send_video(message.chat.id,
                       'https://i.imgur.com/hDOfuOx.mp4', None, 'Searching IOCs')

    iocs = parse_response(response)
    if enrichment:
        iocs = update_iocs(iocs)

    ttps = parse_mitre_ttp(response)
    meta = parse_meta(response)
    yara = parse_yara(response)
    try:
        yara_file = meta['title'].replace(" ", "_")
    except KeyError as err:
        yara_file = "yara"

    text = format_message(iocs, meta, ttps)
    msgs = [text[i:i + 4096] for i in range(0, len(text), 4096)]
    for msg in msgs:
        bot.send_message(message.chat.id, msg, parse_mode="HTML")

    logger.info(f'message send - {message.chat.id} {message.chat.username}')

    send_yara(yara, yara_file)


def format_message(iocs, meta, ttps):
    iocs = {k: v for k, v in iocs.items() if v}
    message = ''
    try:
        message += f"<strong>{meta['title']}</strong>\r\n"
        message += f"<i>{meta['description']}</i>\r\n\n"
        message += f"<b>TTPs</b>: {len(ttps)}\r\n\n"
    except KeyError as err:
        logger.error(f"Error format message{err}")

    for type, values in iocs.items():
        message += f"<b>{type}</b>\r\n"
        for val in values:
            message += f"<code>{val}</code>\r\n"
        message += f"\r\n"
    return message


def send_yara(yara, filename='yara'):
    if yara:
        file = filename.replace(" ", "_")
        save_yara(yara, file)
        bot.send_document(message.chat.id, document=open(
            f'{file}.yar', 'rb'), visible_file_name=f'{file}.yar')
        logger.info(f'yara file send - {message.chat.id}')


bot.polling(none_stop=True, interval=0)
