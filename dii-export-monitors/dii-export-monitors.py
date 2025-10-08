#!/usr/bin/env python3
import requests, json, argparse, re
from datetime import datetime as dt, timedelta as td
from collections import abc, UserDict
from openpyxl import Workbook

# argument parsing
parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description = '* Export monitors from NetApp Data Infrastructure Insights (DII).',
    )
myprog = parser.prog.replace('.py','')
parser.add_argument('-u','--url', action='store', required=True, help='URL to DII Tenant: https://dii_tenant.cloudinsights.netapp.com')
parser.add_argument('-t','--token', action='store', required=True, help='Token file containing the actual token for the DII Tenant')
parser.add_argument('-px','--proxy', action='store', required=False, default=None, help='Proxy for http(s) connections to Tenant: proxy.yourdomain.com:3128')
parser.add_argument('-pxu','--proxy-user', action='store', required=False, default=None, help='User to authenticate with at proxy.')
parser.add_argument('-pxp','--proxy-passwd', action='store', required=False, default=None, help='Password to authenticate with at proxy.')
parser.add_argument('-ll','--loglevel', action='store', required=False, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],\
                    type=lambda txt: txt.upper(), default='INFO', help='Loglevel for console output')
args = parser.parse_args()

proxy = requests.utils.get_environ_proxies(args.url)
if args.proxy:
        pr = requests.utils.urlparse(args.proxy)
        if args.proxy_user and args.proxy_passwd:
            proxy = {'http':f'http://{args.proxy_user}:{args.proxy_passwd}@{pr.netloc}','https':f'http://{args.proxy_user}:{args.proxy_passwd}@{pr.netloc}'}
        else:
            proxy = {'http':f'http://{pr.netloc}','https':f'http://{pr.netloc}'}

with open(args.token, 'r') as fp:
    lines = fp.readlines()
token = None
for line in lines:
    if not line.startswith('#') and len(line) > 420:
        token = line.rstrip('\n') if line.endswith('\n') else line

if not token:
    raise Exception('MissingToken: Reading token from file {} failed.'.format(args.token))

class ciSession(requests.Session):
    def __init__(self, token, base_url = None, proxy={}, loglevel='INFO', verify=True, DisableInsecureRequestWarning = False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if DisableInsecureRequestWarning: requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.verify = verify
        self.base_url = base_url
        self.loglevel = loglevel
        self.proxies.update(proxy)
        self.sysinfo = self.request('GET','systemInfo')
        self.headers.update({'Accept-Encoding':'gzip','X-CloudInsights-ApiKey':token})
    def mount(self,prefix,adapter):
        adapter.max_retries = requests.packages.urllib3.util.retry.Retry(total=5, backoff_factor=0.5, status_forcelist=[500,502,503,504])
        super().mount(prefix,adapter)
    def request(self, method, uri, base_path='/rest/v1', ReturnRawResponse = False, *args, **kwargs):
        # example: uri = assets/storages
        if uri.strip("/")[:7] == 'rest/v1': url = requests.sessions.urljoin(self.base_url, f'{uri.strip("/")}')
        else: url = requests.sessions.urljoin(self.base_url, f'{base_path.strip("/")}/{uri.strip("/")}')
        r = super().request(method, url, *args, **kwargs)
        # print requests on console, not using a logger at loglevel debug
        if self.loglevel == 'DEBUG':
            print(method, r.elapsed, r.status_code, requests.utils.unquote(r.request.url))
        if ReturnRawResponse: return r
        elif not r.ok: raise Exception(f'apiRequestError: <{r.status_code}> {method} {r.request.url}\n{r.text}')
        elif not r.text: return {} # some calls return no payload
        else: return r.json()

class flattenDict(UserDict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.flat = {k:v for k,v in self.flatten()}
    def flatten(self, _dict=None,parent_key=None,  delimiter='.'):
        if not _dict: _dict = self.data
        for key, value in _dict.items():
            new_key = parent_key + delimiter + key if parent_key else key
            if isinstance(value, abc.MutableMapping):
                if value:
                    yield from self.flatten(_dict=value, parent_key=new_key, delimiter=delimiter)
                else: yield new_key, None
            elif isinstance(value, list):
                if value:
                    my_items = {}
                    for val in value:
                        if isinstance(val, abc.MutableMapping):
                            for k,v in val.items():
                                if new_key + delimiter + k not in my_items.keys(): my_items[new_key + delimiter + k] = [v]
                                else: my_items[new_key + delimiter + k].append(v)
                        else:
                            if new_key not in my_items.keys(): my_items[new_key] = [val]
                            else: my_items[new_key].append(val)
                    if my_items: 
                        for k,v in my_items.items():
                            yield k,json.dumps(v) # return string formatted json values
                else: 
                    yield new_key, None
            else:
                yield new_key, value

def main():
    wb = Workbook()
    wb.remove(wb.active)
    monitor_groups = api.get('monitors/groups')
    monitors = list(flattenDict(mon).flat for mon in api.get('monitors/monitors'))
    fields = []
    for monitor in monitors:
        for key in monitor.keys():
            if key not in fields: fields.append(key)

    for n,mg in enumerate(monitor_groups):
        # excel sheet names are case insensitive, adding index to create unique names
        mg_name = '{}|{}'.format(str(n).rjust(3,'0'),re.sub(r'\[|\]|\*|\/|\\|\?|\:','_',mg['name'][:26]))
        ws = wb.create_sheet(title=mg_name)
        ws.append(fields)

    for mon in monitors:
        row = []
        for field in fields:
            if field in ['created', 'updated', 'immutableConfigUpdated']:
                mon[field] = dt.fromtimestamp(mon[field]/1000)
            if field in mon: row.append(mon[field])
            else: row.append(None)
        wb['000|All Monitors'].append(row)
        if 'groupId' not in mon: continue
        else:
            for n,mg in enumerate(monitor_groups):
                mg_name = '{}|{}'.format(str(n).rjust(3,'0'),re.sub(r'\[|\]|\*|\/|\\|\?|\:','_',mg['name'][:26]))
                if mon['groupId'] == mg['id']:
                    if mg['groupType'] == 'Custom':
                        wb['001|Custom Monitors'].append(row)
                    wb[mg_name].append(row)
    wb.save(f"{dt.now().strftime('%y%m%d')}_{requests.utils.urlparse(args.url).netloc.split('.')[0]}_monitors.xlsx")
    exit(0)

if __name__ == '__main__':
    with ciSession(token=token, proxy=proxy, base_url=args.url, loglevel=args.loglevel) as api:
        main()
