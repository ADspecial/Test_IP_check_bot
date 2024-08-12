#from includes.single_ip import ip_info
#from includes.ip_file import process_ip_list

import sys

sys.path.append('C:\\Users\\d.lekontsev\\Documents\\Development\\Test_IP_check_bot')


from includes.ip_list import extract_and_validate, check_ip_list
import time
import paramiko

# Пример использования
host = "11.0.0.134"
username = "user"
password = "njhyflrjy"
command = "inet show interface eth0"


# Создаем объект SSH клиента
client = paramiko.SSHClient()

# Автоматически добавляем неизвестные ключи хостов
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

# Подключаемся к серверу
client.connect(hostname=host, username=username, password=password)
cli = client.invoke_shell()
cli.send('ip sh config\n')
time.sleep(3)
cli.send("\x1b[6~")
# Читаем вывод
while True:
    if cli.recv_ready():
        output = cli.recv(1024).decode('koi8-r')
        print(output)
    if cli.exit_status_ready():
        break
client.close()

'''
test = ip_info('193.124.92.111')
print(test)

file_path = input("Type the input file (Example: input.txt): ")
process_ip_list(file_path)
'''
