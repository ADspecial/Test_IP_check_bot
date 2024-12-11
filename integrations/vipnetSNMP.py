from pysnmp.hlapi import CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, getCmd, nextCmd
from pysnmp.hlapi import SnmpEngine

class ViPNetSNMP:
    def __init__(self, host, community, port=161, snmp_version='v2c'):
        """
        Инициализация SNMP-агента.
        :param host: Адрес ViPNet Coordinator HW.
        :param community: Строка community для доступа.
        :param port: Порт для SNMP (по умолчанию 161).
        :param snmp_version: Версия SNMP ('v1', 'v2c', 'v3').
        """
        self.host = host
        self.community = community
        self.port = port
        self.snmp_version = snmp_version

    def get_oid(self, oid):
        """
        Выполняет SNMP GET-запрос для получения значения по OID.
        :param oid: Строка OID (например, '.1.3.6.1.2.1.1.1.0').
        :return: Значение OID.
        """
        try:
            iterator = getCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=0 if self.snmp_version == 'v1' else 1),
                UdpTransportTarget((self.host, self.port)),
                ContextData(),
                ObjectType(ObjectIdentity(oid))
            )
            errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

            if errorIndication:
                raise RuntimeError(f"SNMP Error: {errorIndication}")
            elif errorStatus:
                raise RuntimeError(f"SNMP Error: {errorStatus.prettyPrint()}")
            else:
                for varBind in varBinds:
                    return f"{varBind[0]} = {varBind[1]}"
        except Exception as e:
            print(f"Ошибка получения OID {oid}: {e}")
            return None

    def walk_oid(self, oid):
        """
        Выполняет SNMP WALK-запрос для получения информации о группе OID.
        :param oid: Строка OID для группового запроса.
        :return: Список пар OID и их значений.
        """
        try:
            iterator = nextCmd(
                SnmpEngine(),
                CommunityData(self.community, mpModel=0 if self.snmp_version == 'v1' else 1),
                UdpTransportTarget((self.host, self.port)),
                ContextData(),
                ObjectType(ObjectIdentity(oid)),
                lexicographicMode=False
            )
            results = []
            for errorIndication, errorStatus, errorIndex, varBinds in iterator:
                if errorIndication:
                    raise RuntimeError(f"SNMP Error: {errorIndication}")
                elif errorStatus:
                    raise RuntimeError(f"SNMP Error: {errorStatus.prettyPrint()}")
                else:
                    for varBind in varBinds:
                        results.append((str(varBind[0]), str(varBind[1])))
            return results
        except Exception as e:
            print(f"Ошибка выполнения SNMP WALK {oid}: {e}")
            return None
