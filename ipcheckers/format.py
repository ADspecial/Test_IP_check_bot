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

    malicious_count = stats.get('malicious', 0)
    suspicious_count = stats.get('suspicious', 0)
    harmless_count = stats.get('harmless', 0)
    undetected_count = stats.get('undetected', 0)

    summary = f"{verdict} IP: {ip} | Country: {country} \n 🔴 Malicious: {malicious_count} \n 🟢 Harmless: {harmless_count} \n 🟡 Suspicious: {suspicious_count} \n ⚫️ Undetected: {undetected_count} \n ================ "

    return summary

def format_to_output_dict(data):
    votes = data['users_votes']
    stats = data['stats']
    output = {
        'verdict': '❌' if data['verdict'] == False else '✅',
        'ip': data['ip'],
        'network': data['network'],
        'owner': data['owner'],
        'country': data['country'],
        'rep_score': data['rep_score'],
        'users_votes': {'🔴 malicious': votes['malicious'],
                        '🟢 harmless': votes['harmless']},
        'stats': {'total engines' : stats['total engines'],
                  '🔴 malicious' : stats['malicious'],
                  '🟡 suspicious' : stats['suspicious'],
                  '🟢 harmless' : stats['harmless'],
                  '⚫️ undetected' : stats['undetected']},
        'last_analysis_date': data['last_analysis_date']
    }
    return output
