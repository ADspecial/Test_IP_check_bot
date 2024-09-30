from typing import Dict, Any, List

def dict_to_string(data: Dict[str, Any], indent: int = 0) -> str:
    """
    Convert a dictionary to a string representation.

    Args:
        data: The dictionary to convert.
        indent: The number of spaces to indent each line.

    Returns:
        The string representation of the dictionary.
    """
    lines = []
    for key, value in data.items():
        lines.append(" " * indent + f"{key}: {value}" if not isinstance(value, dict)
            else " " * indent + f"{key}:")
        if isinstance(value, dict):
            lines.extend(" " * (indent + 2) + line
                for line in dict_to_string(value, indent + 2).splitlines())
    return "\n".join(lines)

def listdict_to_string(data_list: List[Dict[str, Any]]) -> str:
    """
    Convert a list of dictionaries to a string representation.

    Args:
        data_list: The list of dictionaries to convert.

    Returns:
        The string representation of the list of dictionaries.
    """
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
