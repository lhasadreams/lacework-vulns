# lacework-vulns

## Set up Python3
Create an virtual environment<br>
`python3 -m venv venv`<br>
`source venv/bin/activate`<br>
`python -m pip install requests`<br>
To clean up<br>
`deactivate`

Create a `creds.json` file, see the template `creds.json.template` for the format - obtain the API key and secret from your Lacework UI<br>

## Get Host Vulnerabilies
`python3 get_cves.py creds.json`<br>
It will tell you how many rows it has found and create a `vulnerabilities.csv`<br>
Modify `timefilter` in the `get_host_vulnerabilities`function to set a different time range (default is last 24 hours)<br>
Modify `filters` in the `get_host_vulnerabilities`function to filter on different fields<br>
