def dict_to_string(data, indent=0):
    return "\n".join(
        " " * indent + f"{key}: {value}" if not isinstance(value, dict)
        else " " * indent + f"{key}:\n{dict_to_string(value, indent + 2)}"
        for key, value in data.items()
    )

def listdict_to_string(data_list):
    return "\n".join(dict_summary(data) for data in data_list)

def dict_summary(data):
    verdict = data['verdict']
    ip = data['ip']
    country = data['country']
    stats = data['stats']

    malicious_count = stats.get('🔴 malicious', 0)
    suspicious_count = stats.get('🟡 suspicious', 0)
    harmless_count = stats.get('🟢 harmless', 0)
    undetected_count = stats.get('⚫️ undetected', 0)

    summary = f"{verdict} IP: {ip} | Country: {country} \n Malicious: {malicious_count} \n Harmless: {harmless_count} \n Suspicious: {suspicious_count} \n Undetected: {undetected_count} \n ================ "

    return summary
