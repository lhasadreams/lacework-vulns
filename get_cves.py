import requests
import sys
import json
from pprint import pprint as pprint


def get_bearer_token(keyId, secret, account):
    url = "https://" + account + "/api/v2/access/tokens"

    headers = {}
    headers["X-LW-UAKS"] = secret
    headers["Content-Type"] = "application/json"

    data = {}
    data["keyId"] = keyId
    data["expiryTime"] = 3600

    res = requests.post(url, headers=headers, json=data)
    if res.status_code == 201:
        json_data = json.loads(res.text)
    else:
        print(f"Error: {res.status_code}")
        print(res.text)
    return json_data["token"]


def get_lacework_credentials():
    path = sys.argv[1]
    with open(path) as json_file:
        data = json.load(json_file)
    return data


def get_host_vulnerabilities(account, token):
    url = "https://" + account + "/api/v2/Vulnerabilities/Hosts/search"

    headers = {}
    headers["Authorization"] = "Bearer " + token
    headers["Content-Type"] = "application/json"

    data = {
        # Defaults to the last 24 hours, but you can be specific
        # "timeFilter": {
        #     "startTime": "2024-01-19T01:00:00Z",
        #     "endTime": "2024-01-19T02:00:00Z",
        # },
        # Filter how ever you see fit
        "filters": [
            {"field": "severity", "expression": "eq", "value": "Critical"},
            # {"field": "severity", "expression": "eq", "value": "High"},
            # {"field": "severity", "expression": "eq", "value": "Medium"},
            # {"field": "severity", "expression": "eq", "value": "Low"},
            {"field": "status", "expression": "ne", "value": "Fixed"},
            {"field": "fix_info.fix_available", "expression": "ne", "value": "1"},
        ],
    }
    res = requests.post(url, headers=headers, json=data)
    json_data = json.loads(res.text)
    pprint("Total Rows = " + str(json_data["paging"]["totalRows"]))
    return json_data


def get_next_host_vuln_page(url, token):
    headers = {}
    headers["Authorization"] = "Bearer " + token
    headers["Content-Type"] = "application/json"

    res = requests.get(url, headers=headers)
    json_data = json.loads(res.text)
    # pprint(json_data)
    return json_data


def parse_data(raw_data):
    for vuln in raw_data["data"]:
        # print(vuln["machineTags"])
        if "Account" in vuln["machineTags"]:
            account = vuln["machineTags"]["Account"]
        else:
            account = "NoAccountName"
        if "Hostname" in vuln["machineTags"]:
            hostname = vuln["machineTags"]["Hostname"]
        else:
            hostname = "NoHostname"
        if "severity" in vuln:
            severity = vuln["severity"]
        else:
            severity = "NoSeverity"
        if "status" in vuln:
            status = vuln["status"]
        else:
            status = "NoStatus"
        if "metadata" in vuln["cveProps"]:
            score = vuln["cveProps"]["metadata"]["NVD"]["CVSSv3"]["Score"]
        else:
            score = "NoCVSSscore"
        if "vulnId" in vuln:
            vulnid = vuln["vulnId"]
        else:
            vulnid = "NoVulnID"

        meta_tup = (
            account,
            hostname,
            severity,
            score,
            status,
            vulnid,
        )
        acc_list.append(meta_tup)
    return acc_list


def read_list(acc_list):
    acc_list = list(dict.fromkeys(acc_list))
    acc_list.sort(key=lambda x: x[0])

    # for acc in acc_list:
    #     print(acc)
    return acc_list


def get_next_page(raw_data):
    # print(raw_data["paging"])
    result = raw_data["paging"]["urls"]["nextPage"]
    return result


def write_csv(acc_list):
    csv_columns = "Account,Hostname,Severity,Score,Status,CVE"
    csv_file = "vulnerabilities.csv"
    i = 0
    with open(csv_file, "w") as data:
        data.write(csv_columns + "\n")
        while i < len(acc_list):
            for tup in range(6):
                data.write(str(acc_list[i][tup]))
                if tup != 5:
                    data.write(",")
            i += 1
            data.write("\n")


if __name__ == "__main__":
    # Read the file creds.json to get the API key to use
    credentials = get_lacework_credentials()
    # Get a bearer token from the API key to use for this session
    token = get_bearer_token(
        credentials["keyId"], credentials["secret"], credentials["account"]
    )
    # pprint(token)
    # Get the first page of Vulnerabilites, they are paged in 5000 row blocks
    cves = get_host_vulnerabilities(credentials["account"], token)
    # Initialise the Vulnerability List
    acc_list = []
    # Parse the returned list into the structure required
    acc_list = parse_data(cves)
    # Go any other pages and parse them into what is required.
    while True:
        result = get_next_page(cves)
        if result == None:
            break
        else:
            cves = get_next_host_vuln_page(result, token)
            acc_list = parse_data(cves)
            # print(result)
    # Sort the final list into AWS Account order
    acc_list = read_list(acc_list)
    # Write the final list out as a CSV File
    write_csv(acc_list)
