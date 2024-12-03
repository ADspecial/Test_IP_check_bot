import xmlrpc.client as rpc
import sys
import os
import json


class UtmXmlRpc:
    def __init__(self, server_ip, login, password):
        """
        Инициализация класса для взаимодействия с UserGate через XML-RPC.
        :param server_ip: IP-адрес сервера UserGate.
        :param login: Логин пользователя.
        :param password: Пароль пользователя.
        """
        self._login = login
        self._password = password
        self._url = f"http://{server_ip}:4040/rpc"
        self._auth_token = None
        self._server = None
        self.server_ip = server_ip

    def _connect(self):
        """Установка соединения с сервером UserGate и получение токена аутентификации."""
        try:
            self._server = rpc.ServerProxy(self._url, verbose=False)
            result = self._server.v2.core.login(self._login, self._password, {'origin': 'dev-script'})
            self._auth_token = result.get('auth_token')
            print("Успешное подключение к серверу UserGate.")
        except rpc.ProtocolError as err:
            print(f"Ошибка протокола: [{err.errcode}] {err.errmsg}")
            sys.exit(1)
        except rpc.Fault as err:
            print(f"Ошибка аутентификации: [{err.faultCode}] {err.faultString}")
            sys.exit(1)
        except Exception as e:
            print(f"Ошибка подключения: {e}")
            sys.exit(1)

    def logout(self):
        """Завершение сессии на сервере UserGate."""
        try:
            if self._server and self._auth_token:
                self._server.v2.core.logout(self._auth_token)
                print("Сессия завершена.")
        except rpc.Fault as err:
            if err.faultCode == 104:
                print("Сессия уже завершена по таймауту.")

    def add_firewall_rule(self, rule_name, source_ip, action="deny", description=""):
        """
        Добавить блокирующее правило в межсетевой экран.
        :param rule_name: Название правила.
        :param source_ip: Источник (IP-адрес).
        :param action: Действие ("allow" или "deny").
        :param description: Описание правила.
        :return: Статус операции.
        """
        rule = {
            "name": rule_name,
            "enabled": True,
            "action": action,
            "src_ips": [{"type": "ip", "value": source_ip}],
            "description": description,
            "position": 1  # Добавляем правило в начало списка
        }
        try:
            # Проверяем, существует ли правило с таким именем
            existing_rules = self._server.v1.firewall.rules.list(self._auth_token, 0, 1000, {"name": rule_name})['items']
            if existing_rules:
                rule_id = existing_rules[0]['id']
                # Обновляем существующее правило
                self._server.v1.firewall.rule.update(self._auth_token, rule_id, rule)
                print(f"Правило '{rule_name}' обновлено.")
            else:
                # Создаем новое правило
                result = self._server.v1.firewall.rule.add(self._auth_token, rule)
                print(f"Новое правило добавлено: {result}")
            return True
        except rpc.Fault as err:
            print(f"Ошибка добавления/обновления правила: [{err.faultCode}] — {err.faultString}")
            return False
        except Exception as e:
            print(f"Ошибка: {e}")
            return False
