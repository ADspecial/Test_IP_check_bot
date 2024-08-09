#from includes.single_ip import ip_info
#from includes.ip_file import process_ip_list

import sys

sys.path.append('C:\\Users\\d.lekontsev\\Documents\\Development\\Test_IP_check_bot')


from includes.ip_list import extract_and_validate, check_ip_list
from time import sleep

# Пример использования
host = ""
username = ""
password = ""
command = "inet show interface eth0"


import wexpect
import time

def execute_commands_with_pause(host, username, password, commands, pause_duration):
    # Подключение к удаленному серверу по SSH
    ssh_command = f'ssh {username}@{host}'
    child = wexpect.spawn(ssh_command)

    # Ожидание запроса пароля
    child.expect('password:')
    child.sendline(password)
    print(f"Выполнение команды: {command}")
    child.expect('>')  # Ожидание приглашения командной строки
    child.sendline(command)

    # Ожидание завершения команды
    child.expect('>')
    output = child.before.decode().strip()  # Получение вывода
    print(f"Вывод: {output}")


    # Завершение SSH сессии
    child.sendline('exit')
    child.close()

pause_duration = 5  # Пауза в 5 секунд между командами

execute_commands_with_pause(host, username, password, command, pause_duration)

'''
test = ip_info('193.124.92.111')
print(test)

file_path = input("Type the input file (Example: input.txt): ")
process_ip_list(file_path)
'''
