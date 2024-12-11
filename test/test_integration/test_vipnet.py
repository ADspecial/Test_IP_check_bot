import sys
sys.path.append('/app')

import pytest
from unittest.mock import MagicMock, patch
from integrations.vipnet import ViPNetHW

@pytest.fixture
def hw():
    return ViPNetHW(host="192.168.0.1", username="user", password="pass", enable_password="enable")

@patch("integrations.vipnet.paramiko.SSHClient")
def test_hw_connect(mock_ssh, hw):
    mock_client = MagicMock()
    mock_ssh.return_value = mock_client
    hw.connect()
    mock_client.connect.assert_called_once_with(hostname="192.168.0.1", username="user", password="pass")
    mock_client.invoke_shell.assert_called_once()

@patch("integrations.vipnet.paramiko.SSHClient")
def test_hw_connect_exception(mock_ssh, hw):
    mock_client = MagicMock()
    mock_ssh.return_value = mock_client
    mock_client.connect.side_effect = Exception("Connection error")
    with pytest.raises(Exception) as exc:
        hw.connect()
    assert "Connection error" in str(exc.value)

@patch("integrations.vipnet.time.sleep", return_value=None)
@patch("integrations.vipnet.paramiko.SSHClient")
def test_hw_enable_success(mock_ssh, mock_sleep, hw):
    mock_client = MagicMock()
    mock_ssh.return_value = mock_client
    hw.connect()

    # Первый вызов recv возвращает приглашение ввести пароль
    # Второй вызов recv возвращает "#", что означает успешный вход в админ режим
    outputs = [b"Type the administrator password:", b"#"]
    hw.ssh.recv.side_effect = lambda *args, **kwargs: outputs.pop(0)

    hw.enable()  # Должно пройти без ошибок

@patch("integrations.vipnet.time.sleep", return_value=None)
@patch("integrations.vipnet.paramiko.SSHClient")
def test_hw_enable_incorrect_password(mock_ssh, mock_sleep, hw):
    mock_client = MagicMock()
    mock_ssh.return_value = mock_client
    hw.connect()

    # Первый recv - запрос пароля
    # Второй recv - "Admin login failed", что должно вызвать ошибку
    outputs = [b"Type the administrator password:", b"Admin login failed"]
    hw.ssh.recv.side_effect = lambda *args, **kwargs: outputs.pop(0)

    with pytest.raises(ValueError) as exc:
        hw.enable()
    assert "Неверный пароль администратора." in str(exc.value)

@patch("integrations.vipnet.time.sleep", return_value=None)
@patch("integrations.vipnet.paramiko.SSHClient")
def test_hw_add_ip_object_success(mock_ssh, mock_sleep, hw):
    mock_client = MagicMock()
    mock_ssh.return_value = mock_client
    hw.connect()
    hw.ssh.recv.return_value = b"Ok"
    hw.add_ip_object("test_obj", ["1.1.1.1", "2.2.2.2"])
    hw.ssh.send.assert_any_call("firewall ip-object add name @test_obj 1.1.1.1,2.2.2.2\n")

@patch("integrations.vipnet.time.sleep", return_value=None)
@patch("integrations.vipnet.paramiko.SSHClient")
def test_hw_add_ip_object_error(mock_ssh, mock_sleep, hw):
    mock_client = MagicMock()
    mock_ssh.return_value = mock_client
    hw.connect()
    hw.ssh.recv.return_value = b"Error: something wrong"
    with pytest.raises(ValueError) as exc:
        hw.add_ip_object("test_obj", ["1.1.1.1"])
    assert "Ошибка создания объекта" in str(exc.value)

@patch("integrations.vipnet.time.sleep", return_value=None)
@patch("integrations.vipnet.paramiko.SSHClient")
def test_hw_add_blocking_rule_success(mock_ssh, mock_sleep, hw):
    mock_client = MagicMock()
    mock_ssh.return_value = mock_client
    hw.connect()
    hw.ssh.recv.return_value = b"Ok"
    hw.add_blocking_rule("test_obj")
    hw.ssh.send.assert_any_call("firewall forward add src @any dst @test_obj drop\n")
    hw.ssh.send.assert_any_call("firewall forward add src @test_obj dst @any drop\n")

@patch("integrations.vipnet.time.sleep", return_value=None)
@patch("integrations.vipnet.paramiko.SSHClient")
def test_hw_add_blocking_rule_error(mock_ssh, mock_sleep, hw):
    mock_client = MagicMock()
    mock_ssh.return_value = mock_client
    hw.connect()
    hw.ssh.recv.return_value = b"Error: src->dst error"
    with pytest.raises(ValueError) as exc:
        hw.add_blocking_rule("test_obj")
    assert "Ошибка создания правила" in str(exc.value)

@patch("integrations.vipnet.time.sleep", return_value=None)
@patch("integrations.vipnet.paramiko.SSHClient")
def test_hw_exit(mock_ssh, mock_sleep, hw):
    mock_client = MagicMock()
    mock_ssh.return_value = mock_client
    hw.connect()
    hw.ssh.recv.return_value = b">"
    hw.exit()
    hw.ssh.send.assert_any_call("exit\n")

@patch("integrations.vipnet.paramiko.SSHClient")
def test_hw_disconnect(mock_ssh, hw):
    mock_client = MagicMock()
    mock_ssh.return_value = mock_client
    hw.connect()
    hw.disconnect()
    mock_client.close.assert_called_once()
