import requests
import smtplib
import urllib3
import yaml

from flask import Flask,request,json, abort
from yaml.loader import SafeLoader

with open("config.yaml", "r") as ymlfile:
    var = yaml.load(ymlfile, Loader=SafeLoader)

urllib3.disable_warnings()

# smtpObj = smtplib.SMTP('var['host']['mail_server']', 587)

def blockIP(ip):
    payload = f'''<uid-message>
    <type>update</type>
    <payload>
        <register>
            <entry ip="{ip}" persistent="1">
                <tag>
                    <member timeout="0">malicious</member>
                </tag>
            </entry>
        </register>
    </payload>
</uid-message>'''
    #payload = f'''<?xml version='1.0' encoding='utf-8'?><uid-message><type>update</type><payload><register><entryip="{ip}"persistent="1"><tag><membertimeout="0">malicious</member></tag></entry></register></payload></uid-message>'''

    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    # headers = {'Content-Type': 'application/xml'}
    # headers = {'Content-Type': 'text/xml'}
    # response = requests.POST('https://<your_firewall_url>/api/?type=user-id&key=<your_api_key>', headers=headers, data=payload, verify=False)

    success_message = f"""From: From SIEM <{var['host']['sender']}>
To: To Admin <{var['host']['receiver']}>
Subject: IP block successful

Dear admin,
IP {ip} got blocked successful.
"""

    fail_message = f"""From: From SIEM <{var['host']['sender']}>
To: To Admin <{var['host']['receiver']}>
Subject: Fail to block IP

Dear admin,
Tools fail to block IP {ip}.
Please check.
"""

    #if "success" in response:
    #    smtpObj.sendmail(var['host']['sender'], var['host']['receiver'], success_message)
    #    return True
    #else:
    #    smtpObj.sendmail(var['host']['sender'], var['host']['receiver'], fail_message)
    #    return False
    print(payload)
    return True

app = Flask(__name__)

@app.route('/webhook', methods=['POST'])
def getip():
    if request.remote_addr != var['host']['remote_ip']:
        abort(403)
    else:
        if request.method == 'POST':
            data = request.json
            result = blockIP(data['ip'])
            if result:
                return "OK\n", 200
            else:
                return "Not OK\n", 200
        else:
            abort(400)


if __name__ == '__main__':
    app.run(host=var['host']['ip'], port=443)