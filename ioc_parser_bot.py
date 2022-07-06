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
    logging.info('ioc processing..............')
    if len(text) > 4095:
        for x in range(0, len(text), 4095):
            bot.send_message(message.chat.id, text=text[x:x+4095], parse_mode='Markdown')
    else:
        bot.send_message(message.chat.id, text, parse_mode='Markdown')
    logging.info('send message')
    if yara:
        bot.send_document(message.chat.id, document=open(
            'yara.yar', 'rb'), visible_file_name="yara.yar")


bot.polling(none_stop=True, interval=0)
