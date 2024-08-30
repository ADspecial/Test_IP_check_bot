def dict_to_string(data, indent=0):
    result = ""
    for key, value in data.items():
        if isinstance(value, dict):
            result += " " * indent + f"{key}:\n"
            result += dict_to_string(value, indent + 2)
        else:
            result += " " * indent + f"{key}: {value}\n"
    return result

def listdict_to_string(data_list):
    result = ''
    for data in data_list:
        result += f'{dict_summary(data)}\n'
    return result

def dict_summary(data):
    verdict = data['verdict']
    ip = data['ip']
    country = data['country']
    stats = data['stats']

    malicious_count = stats.get('🔴 malicious', 0)
    suspicious_count = stats.get('🟡 suspicious', 0)
    harmless_count = stats.get('🟢 harmless', 0)
    undetected_count = stats.get('⚫️ undetected', 0)

    summary = f"{verdict} IP: {ip} | Country: {country} | Malicious: {malicious_count}, Suspicious: {suspicious_count}, Harmless: {harmless_count}, Undetected: {undetected_count}"

    return summary
