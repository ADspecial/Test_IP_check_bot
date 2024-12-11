import paramiko
import time

class ViPNetHW:
    def __init__(self, host, username, password, enable_password):
        """
        Инициализация объекта для подключения к ViPNet HW.
        :param host: IP-адрес устройства ViPNet HW.
        :param username: Логин для SSH.
        :param password: Пароль для SSH.
        :param enable_password: Пароль для команды enable.
        """
        self.host = host
        self.username = username
        self.password = password
        self.enable_password = enable_password
        self.client = None
        self.ssh = None

    def connect(self):
        """Устанавливает соединение с устройством ViPNet HW."""
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(hostname=self.host, username=self.username, password=self.password)
            self.ssh = self.client.invoke_shell()
            print("Успешное подключение к ViPNet HW.")
        except Exception as e:
            print(f"Ошибка подключения: {e}")
            raise

    def enable(self):
        """Переходит в режим администратора."""
        try:
            self.ssh.send("enable\n")
            time.sleep(1)
            output = self.ssh.recv(1024).decode("utf-8")
            if "Type the administrator password:" in output:
                self.ssh.send(f"{self.enable_password}\n")
                time.sleep(1)
                output = self.ssh.recv(1024).decode("utf-8")
                if "Admin login failed" in output:
                    raise ValueError("Неверный пароль администратора.")
                elif "#" in output:
                    print("Переход в режим администратора выполнен успешно.")
                else:
                    raise ValueError("Не удалось перейти в режим администратора.")
            else:
                raise ValueError("Устройство не запросило пароль администратора.")
        except Exception as e:
            print(f"Ошибка при выполнении команды enable: {e}")
            raise

    def add_ip_object(self, name, ip_list):
        """
        Создает объект IP-адресов.
        :param name: Имя объекта.
        :param ip_list: Список IP-адресов (строка с адресами, разделенными запятой).
        """
        try:
            command = f"firewall ip-object add name @{name} {','.join(ip_list)}"
            self.ssh.send(command + "\n")
            time.sleep(1)
            output = self.ssh.recv(1024).decode("utf-8")
            if "Error" in output or "Ошибка" in output:
                raise ValueError(f"Ошибка создания объекта: {output}")
            print(f"Объект {name} успешно создан с адресами: {ip_list}")
        except Exception as e:
            print(f"Ошибка добавления объекта: {e}")
            raise

    def add_blocking_rule(self, name):
        """
        Создает блокирующее правило на основе объекта IP-адресов.
        :param name: Имя объекта.
        """
        try:
            command1 = f"firewall forward add src @any dst @{name} drop"
            command2 = f"firewall forward add src @{name} dst @any drop"

            # Добавляем правило для блокировки трафика к объекту
            self.ssh.send(command1 + "\n")
            time.sleep(1)
            output1 = self.ssh.recv(1024).decode("utf-8")
            if "Error" in output1 or "Ошибка" in output1:
                raise ValueError(f"Ошибка создания правила (src -> dst): {output1}")

            # Добавляем правило для блокировки трафика от объекта
            self.ssh.send(command2 + "\n")
            time.sleep(1)
            output2 = self.ssh.recv(1024).decode("utf-8")
            if "Error" in output2 or "Ошибка" in output2:
                raise ValueError(f"Ошибка создания правила (dst -> src): {output2}")

            print(f"Блокирующее правило на основе объекта {name} успешно создано.")
        except Exception as e:
            print(f"Ошибка создания блокирующего правила: {e}")
            raise

    def exit(self):
        """Выполняет команду выхода из текущего режима командного интерпретатора."""
        try:
            self.ssh.send("exit\n")
            time.sleep(1)
            output = self.ssh.recv(1024).decode("utf-8")
            if ">" in output:
                print("Переход в режим пользователя выполнен.")
            elif "login:" in output or "password:" in output:
                print("Сессия завершена. Требуется повторный вход.")
            else:
                print("Команда exit выполнена успешно.")
        except Exception as e:
            print(f"Ошибка выполнения команды exit: {e}")
            raise

    def disconnect(self):
        """Закрывает SSH-соединение."""
        if self.client:
            self.client.close()
            print("Соединение закрыто.")
