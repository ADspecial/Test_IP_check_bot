#from includes.single_ip import ip_info
#from includes.ip_file import process_ip_list

import sys

sys.path.append('C:\\Users\\d.lekontsev\\Documents\\Development\\Test_IP_check_bot')


from includes.ip_list import extract_and_validate, check_ip_list
import time
import paramiko
import threading

# Пример использования
host = "11.0.0.134"
username = "user"
password = "njhyflrjy"
command = "inet show interface eth0"

def read_output(chan):
    while True:
        time.sleep(1)  # Задержка для избежания излишней загрузки процессора
        if chan.recv_ready():
            output = chan.recv(1024).decode()
            print(output, end='')


def main():

    # Создаем объект SSH клиента
    client = paramiko.SSHClient()
    # Автоматически добавляем неизвестные ключи хостов
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    # Подключаемся к серверу
    client.connect(hostname=host, username=username, password=password)
    cli = client.invoke_shell()
    output_thread = threading.Thread(target=read_output, args=(cli,))

    output_thread.start()

    cli.send('en\n')
    time.sleep(3)
    cli.send("vjlcfkbphgjg\n")
    time.sleep(3)
    cli.send('admin show check integrity status\n')
    time.sleep(3)

    cli.close()
    client.close()

if __name__ == '__main__':
    main()

'''
test = ip_info('193.124.92.111')
print(test)

file_path = input("Type the input file (Example: input.txt): ")
process_ip_list(file_path)
'''
