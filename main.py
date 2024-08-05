import sys;
from includes.settings import *;
import telebot;
from includes.single_ip import ip_info
import vt;


# Ensure the output directories exist
def ensure_directories():
    os.makedirs('output/single-ip', exist_ok=True)
    os.makedirs('output/single-domain', exist_ok=True)
    os.makedirs('output/domain-ip-lists', exist_ok=True)

#print(API_URL_IP_VT)
#print(VT_KEY)


test = ip_info('193.124.92.156')
print(test)
'''
bot = telebot.TeleBot(TG_KEY);

@bot.message_handler(content_types=['text'])
def get_text_messages(message):
    if message.text == "Привет":
        bot.send_message(message.from_user.id, "Привет чем могу помочь?")
    elif message.text == "/help":
        bot.send_message(message.from_user.id, "Напиши привет")
    else:
        bot.send_message(message.from_user.id, "Я тебя не понимаю. Напиши /help")

bot.polling(none_stop=True, interval=0)
'''
