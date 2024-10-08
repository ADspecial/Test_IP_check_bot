import requests

from ipaddress import ip_address

from datetime import datetime

# from .geo_ip import geo_ip

from config import settings


# if "passive_dns" in response["sections"]:
#     print(requests.request(method='GET', url=(url_base+url_ip+"185.138.131.234"+"/passive_dns"), headers=headers).text)
# else:
#     print("there is no passive dns found")


def make_request_alien(ip_address: ip_address, endpoint="general"):
    url = "https://otx.alienvault.com/api/v1/indicators/IPv4/"
    headers = {
        'Accept': 'application/json',
        'Key': settings.ALIENVAULT_TOKEN
    }
    response = requests.request(method='GET', url=(url+ip_address+"/"+endpoint), headers=headers).json()
    return response


def get_report_alien(ip_address: ip_address):
    response = make_request_alien(ip_address=ip_address)
    report = {}
    try:
        report["info"] = ', '.join(source["source"] for source in response["validation"])
        if not report["info"]:
            report.pop("info", None)
        pass
    except KeyError:
        pass
    try:
        report["asn"] = response["asn"]
    except KeyError:
        pass
    try:
        tags = set()
        for pulse in response["pulse_info"]["pulses"]:
            for tag in pulse["tags"]:
                tags.add(tag)
        if tags: report["tags"] = ', '.join(tag for tag in list(tags)[:10])
    except KeyError:
        pass
    try:
        #report["country"] = geo_ip.get_geo_response(ip_address)
        pass
    except KeyError:
        pass
    try:
        pulse_dates = set()
        for pulse in response["pulse_info"]["pulses"]:
            pulse_date = datetime.strptime(pulse["modified"][:10], "%Y-%m-%d")
            pulse_dates.add(pulse_date)
        now = datetime.now()
        try:
            report["otx_7days"] = True if (now - max(pulse_dates)).days <= 7 else False
        except Exception as e:
            report["otx_7days"] = False
        try:
            report["otx_30days"] = True if (now - max(pulse_dates)).days <= 7 else False
        except Exception as e:
            report["otx_30days"] = False
        try:
            report["otx_historical"] = True if (now - max(pulse_dates)).days <= 7 else False
        except Exception as e:
            report["otx_historical"] = False
    except KeyError:
        pass
    verdict = "⚫️ no info"
    try:
        if report["otx_7days"] or report["otx_30days"] or ("brute" or "ssh" or "attack" or "botnet" or "scan" or "malicious") in ''.join(tag.lower() for tag in tags):
            verdict = "🔴 malicious"
        elif report["otx_historical"]:
            verdict = "🟡 suspicious"
        else:
            verdict = "🟢 harmless"
    except Exception as e:
        try:
            new_report = {}
            new_report["detail"] = response["detail"]
            new_report["verdict"] = verdict
            return new_report
        except KeyError:
            pass
    report["verdict"] = verdict
    return report

# reverse dns, OTX telemetry, verdict

#reputation', 'url_list', 'passive_dns', 'malware', 'nids_list', 'http_scans']}
