import requests
import urllib3
import yaml
import subprocess

from flask import Flask,request,json, abort
from yaml.loader import SafeLoader

with open("config.yaml", "r") as ymlfile:
    var = yaml.load(ymlfile, Loader=SafeLoader)

urllib3.disable_warnings()


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

    with open('autoblockIP_payload.xml', "w") as f:
        print(payload, file=f)

    response = subprocess.run( ['curl', '-k', '-XPOST', f'https://{var['host']['pa_server']}/api/?type=user-id&key={var['host']['api_key']}', '--data-urlencode', 'cmd@autoblockIP_payload.xml'] )

    if "success" in response:
        return True
    else:
        return False

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
