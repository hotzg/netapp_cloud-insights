#!/usr/bin/env python3
import re, requests, argparse, threading, csv
from datetime import datetime as dt, timedelta as td

# global vars
MAX_THREADS = 12
LIMIT = 2000

# argument parsing
parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description = '* Export activities from NetApp Cloud Secure into SCV file')
myprog = parser.prog.replace('.py','')
parser.add_argument('-u','--url', action='store', required=True, help='URL to CS Tenant: https://xy1234.cs0[1|2].cloudinsights.netapp.com')
parser.add_argument('-t','--token', action='store', required=True, help='Token file containing the actual token for the CI Tenant')
parser.add_argument('-px','--proxy', action='store', required=False, default=None, help='Proxy for http(s) connections to Tenant: proxy.yourdomain.com:3128')
parser.add_argument('-pxu','--proxy-user', action='store', required=False, default=None, help='User to authenticate with at proxy.')
parser.add_argument('-pxp','--proxy-passwd', action='store', required=False, default=None, help='Password to authenticate with at proxy.')
parser.add_argument('-tr','--time-range', action='store', required=False, choices=['FIFTEEN_MINUTES', 'THIRTY_MINUTES', 'ONE_HOUR', 'TWO_HOURS', 'THREE_HOURS', 'SIX_HOURS', 'TWELVE_HOURS', 'ONE_DAY', 'TWO_DAYS', 'THREE_DAYS', 'ONE_WEEK', 'THIRTY_DAYS'], type=lambda txt: txt.upper(), default='ONE_HOUR', help='Time range for queries')
parser.add_argument('-ft','--from-to', nargs=2, action='store', required=False, type=lambda txt: [dt.strptime(d,'%Y-%m-%d_%H:%M:%S') for d in txt.split()][0], help='From-To datetimes for custom time range (overrides --time-range): YYYY-mm-dd_HH:MM:SS YYYY-mm-dd_HH:MM:SS')
parser.add_argument('-ex','--exclude', action='store', required=False, default=None, help='Exclude param:pattern from result output. Example: entityPath:/some/random/path')
args = parser.parse_args()

proxy = requests.utils.get_environ_proxies(args.url)
if args.proxy:
    pr = requests.utils.urlparse(args.proxy)
    if args.proxy_user and args.proxy_passwd:
        proxy = {'http':f'http://{args.proxy_user}:{args.proxy_passwd}@{pr.netloc}','https':f'http://{args.proxy_user}:{args.proxy_passwd}@{pr.netloc}'}
    else:
        proxy = {'http':f'http://{pr.netloc}','https':f'http://{pr.netloc}'}

token = None
with open(args.token, 'r') as fp:
    token = fp.read().rstrip('\n')

from_time = None
to_time = None
if args.from_to:
    if (args.from_to[1]-args.from_to[0]).total_seconds() < 0:
        print('--from-to: from-time needs to come before to-time')
        exit(1)
    elif (args.from_to[1]-args.from_to[0]).days > 30:
        print('--from-to: diffrence between from-time and to-time cannot be more than 30 days')
        exit(1)
    else:
        for d in args.from_to:
            if d > dt.now():
                print('--from-to: datetime cannot be set to the future.')
                exit(1)
        from_time = int(args.from_to[0].timestamp())*1000
        to_time = int(args.from_to[1].timestamp())*1000

# Convert relative time_range to absolute from_time/to_time values
# can't use timeRange attributes in calls due to the nature of timeRange being relative to the time a given api call is being made
# and the constant flow of new data into the system
# multiple subsequent calls would have diffrent start/end times, yielding diffrent results
# hence, always use fromTime and toTime in parameters instead, even if script was called with time_range argument
def convert_timerange(time_range):
    now = dt.now().astimezone()
    ranges = {'FIFTEEN_MINUTES':15, 'THIRTY_MINUTES':30, 'ONE_HOUR':60, 'TWO_HOURS':120, 'THREE_HOURS':180, 'SIX_HOURS':360, 'TWELVE_HOURS':720, 'ONE_DAY':1440, 'TWO_DAYS':2880, 'THREE_DAYS':4320, 'ONE_WEEK':10080, 'THIRTY_DAYS':43200}
    to_time = int(now.timestamp())*1000
    from_time = int((now-td(minutes=ranges[time_range])).timestamp())*1000
    return from_time, to_time

if from_time == None or to_time == None:
    from_time,to_time = convert_timerange(args.time_range)

class ciSession(requests.Session):
    def __init__(self, token, base_url = None, proxy={}, loglevel='INFO', verify=True, DisableInsecureRequestWarning=False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if DisableInsecureRequestWarning: requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.verify = verify
        self.base_url = re.sub(r'.c([0-9]{2}).',r'.cs\1.',base_url) # update URL to point to SWS
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

def main():
    results = []
    params = {
        'limit':LIMIT,
        'fromTime':from_time,
        'toTime':to_time
    }
    while True:
        q = api.get('cloudsecure/activities',base_path='/rest/v2',params=params)
        results.extend(q['results'])
        if q['meta']['page'].get('after'):
            params.update({'after':q['meta']['page']['after']})
        else:
            break
    
    if results:
        with open(myprog+'_'+dt.strftime(dt.now(),'%y%m%d%H%M%S')+'.csv','w',newline='',encoding='utf-8') as fp:
            writer = csv.DictWriter(fp, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    else:
        print('Query returned no results.')
    exit(0)

if __name__ == '__main__':
    with ciSession(token=token, proxy=proxy, base_url=args.url) as api:
        main()
