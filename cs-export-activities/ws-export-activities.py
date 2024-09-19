#!/usr/bin/env python3
import pathlib, requests, math, json, argparse, os, time, threading, concurrent.futures, csv
from datetime import datetime as dt, timedelta as td, timezone as tz

# global vars
MAX_THREADS = 25
LIMIT = 1000

# argument parsing
parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description = '* Export activities from NetApp Cloud Secure into SCV file')
myprog = parser.prog.replace('.py','')
parser.add_argument('-u','--url', action='store', required=True, help='URL to CS Tenant: https://xy1234.cs0[1|2].cloudinsights.netapp.com')
parser.add_argument('-t','--token_file', type=pathlib.Path, help='Token file containing the actual token for the CS Tenant')
parser.add_argument('-px','--proxy', action='store', required=False, default=None, help='Proxy for http(s) connections to Tenant: proxy.yourdomain.com:3128')
parser.add_argument('-pxu','--proxy-user', action='store', required=False, default=None, help='User to authenticate with at proxy.')
parser.add_argument('-pxp','--proxy-passwd', action='store', required=False, default=None, help='Password to authenticate with at proxy.')
parser.add_argument('-tr','--time-range', action='store', required=False, choices=['FIFTEEN_MINUTES', 'THIRTY_MINUTES', 'ONE_HOUR', 'TWO_HOURS', 'THREE_HOURS', 'SIX_HOURS', 'TWELVE_HOURS', 'ONE_DAY', 'TWO_DAYS', 'THREE_DAYS', 'ONE_WEEK', 'THIRTY_DAYS'], type=lambda txt: txt.upper(), default='ONE_HOUR', help='Time range for queries')
parser.add_argument('-ft','--from-to', nargs=2, action='store', required=False, type=lambda txt: [dt.strptime(d,'%Y-%m-%d_%H:%M:%S') for d in txt.split()][0], help='From-To datetimes for custom time range (overrides --time-range): YYYY-mm-dd_HH:MM:SS YYYY-mm-dd_HH:MM:SS')
args = parser.parse_args()

proxy = None
if args.proxy:
    if args.proxy_user and args.proxy_passwd:
        proxy = {'https':f'https://{args.proxy_user}:{args.proxy_passwd}@{args.proxy}'}
    else:
        proxy = {'https':f'https://{args.proxy}'}

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
# hance, always use fromTime and toTime in parameters instead, even if script was called with time_range argument
def convert_timerange(time_range):
    utcnow = dt.utcnow()
    ranges = {'FIFTEEN_MINUTES':15, 'THIRTY_MINUTES':30, 'ONE_HOUR':60, 'TWO_HOURS':120, 'THREE_HOURS':180, 'SIX_HOURS':360, 'TWELVE_HOURS':720, 'ONE_DAY':1440, 'TWO_DAYS':2880, 'THREE_DAYS':4320, 'ONE_WEEK':10080, 'THIRTY_DAYS':43200}
    to_time = int(utcnow.timestamp())*1000
    from_time = int((utcnow-td(minutes=ranges[time_range])).timestamp())*1000
    return from_time, to_time

if from_time == None or to_time == None:
    from_time,to_time = convert_timerange(args.time_range)

token_file = args.token_file.resolve().__str__()
token = None
if args.token_file.exists():
    with args.token_file.open(mode='r') as fp:
        lines = fp.readlines()
    for line in lines:
        if not line.startswith('#') and len(line) > 472:
            # look for the first uncommented line of sufficient length as the token
            token = line.rstrip('\n') if line.endswith('\n') else line
            break
if not token:
    raise Exception('MissingToken: Reading token from file {} failed.'.format(token_file))

thread_local = threading.local()
def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = ciSession(token = token, base_url = args.url)
    return thread_local.session

def fetch_results(url,_params):
    session = get_session()
    return session.get(url,base_path='/rest/v1',params=_params)

class ciSession(requests.Session):
    def __init__(self, token, base_url = None, proxy=None, verify=True, DisableInsecureRequestWarning = False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if DisableInsecureRequestWarning: requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.headers['X-CloudInsights-ApiKey'] = token
        self.verify = verify
        self.base_url = base_url
        if proxy: self.proxies.update(proxy)
    def request(self, method, uri, base_path='/rest/v1', *args, **kwargs):
        # example: uri = assets/storages
        url = requests.sessions.urljoin(self.base_url, f'{base_path.strip("/")}/{uri.strip("/")}')
        r = super().request(method, url, *args, **kwargs)
        if r.ok:
            #print(f"{method} {r.status_code} {r.request.url}")
            return r.json()
        else:
            print(f'API request for "{uri}" returned status code {r.status_code} - exiting!');
            print(f'Status message: "{r.text}"')
            exit(1)

def main():
    params={'limit':LIMIT,'fromTime':from_time,'toTime':to_time}
    q = api.get('cloudsecure/activities',params=params)
    if q['count'] > LIMIT:
        num_queries = math.ceil(q['count']/LIMIT)
        if num_queries > 1: # spin up threads as needed
            params_list = [] # prepare list of adjusted parameters
            for num in range(1,num_queries):
                my_params = params.copy()
                my_params['offset'] = num*q['limit']
                params_list.append(my_params)
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_THREADS,num_queries)) as executor:
                results = executor.map(fetch_results, ['cloudsecure/activities' for i in range(1,num_queries)],params_list)
                for item in results:
                    q['results'].extend(item['results'])
    if q['results']:
        with open(myprog+'_'+dt.strftime(dt.now(),'%y%m%d%H%M%S')+'.csv','w') as fp:
            writer = csv.DictWriter(fp, fieldnames=q['results'][0].keys())
            writer.writeheader()
            writer.writerows(q['results'])
    else:
        print('Query returned no results.')
    exit(0)
if __name__ == '__main__':
    with ciSession(token = token, proxy=proxy, base_url = args.url) as api:
        main()
