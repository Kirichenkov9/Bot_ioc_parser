import telebot
import urllib.parse
import os
import logging
from ioc_parser import *

TOKEN = os.getenv('BOT_TOKEN')


bot = telebot.TeleBot(TOKEN)


@bot.message_handler(commands=["start"])
def start(m, res=False):
    logging.info('Start')
    bot.send_message(m.chat.id, 'Send url')


@bot.message_handler(content_types=["text"])
def handle_text(message):
    text, yara = process_ioc(message.text)

    if text == '':
        text = "Report doesn't contains IOCs"

    logging.info('ioc processing..............')
    msgs = [text[i:i + 4096] for i in range(0, len(text), 4096)]
    for msg in msgs:
        bot.send_message(message.chat.id, msg)
    logging.info('send message')
    if yara:
        bot.send_document(message.chat.id, document=open(
            'yara.yar', 'rb'), visible_file_name="yara.yar")


bot.polling(none_stop=True, interval=0)
