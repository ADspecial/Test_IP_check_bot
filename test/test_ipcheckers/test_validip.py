import sys
sys.path.append('/app')

import pytest
from ipcheckers.valid_ip import is_valid_ip, is_valid_dns, extract_and_validate

def test_is_valid_ip():
    """Тест функции is_valid_ip."""
    # Валидные IP-адреса
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("255.255.255.255") is True
    assert is_valid_ip("0.0.0.0") is True

    # Невалидные IP-адреса
    assert is_valid_ip("256.256.256.256") is False  # Значения больше 255
    assert is_valid_ip("192.168.1") is False  # Неполный IP
    assert is_valid_ip("192.168.1.256") is False  # Одна часть больше 255
    assert is_valid_ip("192.168.1.1.1") is False  # Лишняя часть
    assert is_valid_ip("192.168.-1.1") is False  # Отрицательные значения
    assert is_valid_ip("192.168.1.abc") is False  # Некорректные символы

def test_is_valid_dns():
    """Тест функции is_valid_dns."""
    # Валидные DNS-имена
    assert is_valid_dns("example.com") is True
    assert is_valid_dns("sub.example.com") is True
    assert is_valid_dns("a.b-c.de") is True
    assert is_valid_dns("xn--d1acufc.xn--p1ai") is True  # Punycode

    # Невалидные DNS-имена
    assert is_valid_dns("-example.com") is False  # Начинается с "-"
    assert is_valid_dns("example-.com") is False  # Заканчивается на "-"
    assert is_valid_dns("ex..com") is False  # Пустая часть
    assert is_valid_dns("toolongpart"*10 + ".com") is False  # Слишком длинная часть
    assert is_valid_dns("example") is False  # Нет TLD


def test_extract_and_validate():
    """Тест функции extract_and_validate."""
    text = """
    Here are some IPs and domains:
    Valid: 192.168.1.1, 8.8.8.8, example.com, sub.example.com
    Invalid: 256.256.256.256, ex..com, -example.com, example-.com, example
    Mixed content: 192.168.1.300, valid-example.com, 10.0.0.1
    """

    valid_ips, valid_dns = extract_and_validate(text)

    # Ожидаемые результаты
    expected_ips = ["192.168.1.1", "8.8.8.8", "10.0.0.1"]
    expected_dns = ["example.com", "sub.example.com", "valid-example.com"]

    # Сравнение списков как множеств
    assert set(valid_ips) == set(expected_ips)
    assert set(valid_dns) == set(expected_dns)
