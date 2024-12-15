import sys
sys.path.append('/app')

import pytest
from unittest.mock import MagicMock, patch
from integrations.utm_xmlrpc import UtmXmlRpc
import xmlrpc.client as rpc

@pytest.fixture
def utm():
    return UtmXmlRpc(server_ip="192.168.0.1", login="admin", password="secret")

@patch("integrations.utm_xmlrpc.rpc.ServerProxy")
def test_connect_success(mock_server, utm):
    mock_proxy = MagicMock()
    mock_server.return_value = mock_proxy
    mock_proxy.v2.core.login.return_value = {"auth_token": "test_token"}

    # Проверяем что при вызове _connect не возникает исключений и auth_token устанавливается
    utm._connect()
    assert utm._auth_token == "test_token"
    mock_proxy.v2.core.login.assert_called_once_with("admin", "secret", {"origin": "dev-script"})
    print("Успешное подключение протестировано.")

@patch("integrations.utm_xmlrpc.rpc.ServerProxy")
def test_connect_protocol_error(mock_server, utm):
    mock_proxy = MagicMock()
    mock_server.return_value = mock_proxy
    mock_proxy.v2.core.login.side_effect = rpc.ProtocolError("url", 404, "Not Found", {})
    with pytest.raises(SystemExit) as exc:
        utm._connect()
    assert exc.type == SystemExit
    print("Проверен ProtocolError при подключении.")

@patch("integrations.utm_xmlrpc.rpc.ServerProxy")
def test_connect_fault_error(mock_server, utm):
    mock_proxy = MagicMock()
    mock_server.return_value = mock_proxy
    mock_proxy.v2.core.login.side_effect = rpc.Fault(100, "Authentication failed")
    with pytest.raises(SystemExit) as exc:
        utm._connect()
    assert exc.type == SystemExit
    print("Проверен Fault при подключении.")

@patch("integrations.utm_xmlrpc.rpc.ServerProxy")
def test_connect_generic_exception(mock_server, utm):
    mock_proxy = MagicMock()
    mock_server.return_value = mock_proxy
    mock_proxy.v2.core.login.side_effect = Exception("Some error")
    with pytest.raises(SystemExit) as exc:
        utm._connect()
    assert exc.type == SystemExit
    print("Проверено общее исключение при подключении.")

@patch("integrations.utm_xmlrpc.rpc.ServerProxy")
def test_logout_success(mock_server, utm):
    mock_proxy = MagicMock()
    mock_server.return_value = mock_proxy

    # Установим auth_token
    utm._auth_token = "test_token"
    utm._server = mock_proxy

    utm.logout()
    mock_proxy.v2.core.logout.assert_called_once_with("test_token")
    print("Проверен logout при наличии токена.")

@patch("integrations.utm_xmlrpc.rpc.ServerProxy")
def test_logout_no_auth_token(mock_server, utm):
    mock_proxy = MagicMock()
    mock_server.return_value = mock_proxy

    # auth_token не установлен
    utm._auth_token = None
    utm._server = mock_proxy

    utm.logout()
    mock_proxy.v2.core.logout.assert_not_called()
    print("Проверен logout при отсутствии токена.")

@patch("integrations.utm_xmlrpc.rpc.ServerProxy")
def test_logout_fault_error(mock_server, utm):
    mock_proxy = MagicMock()
    mock_server.return_value = mock_proxy

    utm._auth_token = "test_token"
    utm._server = mock_proxy
    mock_proxy.v2.core.logout.side_effect = rpc.Fault(104, "Session timed out")

    # Не падаем с исключением, просто печатаем сообщение
    utm.logout()
    mock_proxy.v2.core.logout.assert_called_once_with("test_token")
    print("Проверен logout при Fault(104).")

@patch("integrations.utm_xmlrpc.rpc.ServerProxy")
def test_add_firewall_rule_new(mock_server, utm):
    mock_proxy = MagicMock()
    mock_server.return_value = mock_proxy
    # Настраиваем успешное подключение
    utm._server = mock_proxy
    utm._auth_token = "test_token"

    # Нет существующих правил
    mock_proxy.v1.firewall.rules.list.return_value = {"items": []}
    mock_proxy.v1.firewall.rule.add.return_value = {"id": 123}

    result = utm.add_firewall_rule("block_rule", "10.0.0.1", "deny", "test desc")
    assert result is True
    mock_proxy.v1.firewall.rules.list.assert_called_once()
    mock_proxy.v1.firewall.rule.add.assert_called_once()
    print("Проверено добавление нового правила.")

@patch("integrations.utm_xmlrpc.rpc.ServerProxy")
def test_add_firewall_rule_update(mock_server, utm):
    mock_proxy = MagicMock()
    mock_server.return_value = mock_proxy
    utm._server = mock_proxy
    utm._auth_token = "test_token"

    # Существующее правило найдено
    mock_proxy.v1.firewall.rules.list.return_value = {"items": [{"id": 999}]}

    result = utm.add_firewall_rule("block_rule", "10.0.0.1", "deny", "test desc")
    assert result is True
    mock_proxy.v1.firewall.rule.update.assert_called_once_with("test_token", 999, {
        "name": "block_rule",
        "enabled": True,
        "action": "deny",
        "src_ips": [{"type": "ip", "value": "10.0.0.1"}],
        "description": "test desc",
        "position": 1
    })
    print("Проверено обновление существующего правила.")

@patch("integrations.utm_xmlrpc.rpc.ServerProxy")
def test_add_firewall_rule_error(mock_server, utm):
    mock_proxy = MagicMock()
    mock_server.return_value = mock_proxy
    utm._server = mock_proxy
    utm._auth_token = "test_token"

    mock_proxy.v1.firewall.rules.list.return_value = {"items": []}
    mock_proxy.v1.firewall.rule.add.side_effect = rpc.Fault(500, "Internal error")

    result = utm.add_firewall_rule("block_rule", "10.0.0.1", "deny", "test desc")
    assert result is False
    print("Проверена ошибка при добавлении правила.")
