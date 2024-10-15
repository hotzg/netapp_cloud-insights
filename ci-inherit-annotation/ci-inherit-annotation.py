#!/usr/bin/env python3
import platform, getpass, logging, logging.handlers, requests, json, argparse
from InquirerPy import inquirer as inq
from InquirerPy.base.control import Choice
from datetime import datetime as dt

# global vars
LOG_TO_CI = False
CI_LOGLEVEL = 'INFO'
CI_LOGTYPE = 'custom_script'
MAX_PAYLOAD_TARGETS = 2000

# argument parsing
parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description = '* Inherit annotations from one object-type to another in NetApp Cloud Insights.'
    )
myprog = parser.prog.replace('.py','')
parser.add_argument('-u','--url', action='store', required=True, help='URL to CI Tenant: https://ci_tenat.cloudinsights.netapp.com')
parser.add_argument('-t','--token', action='store', required=True, help='Token file containing the actual token for the CI Tenant')
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

class CiHttpHandler(logging.Handler):
    def __init__(self,session,*args,**kwargs):
        super().__init__(*args, **kwargs)
        self.session = session
    def emit(self, record):
        payload = [self.format(record)]
        return self.session.post('logs/ingest', json=payload)

class CiJsonFormatter(logging.Formatter):
    def __init__(self, log_type=parser.prog, *args,**kwargs):
        super().__init__(*args, **kwargs)
        self.fields = {"timestamp":dt.now().timestamp(), "type": f"logs.{log_type}", "source": my_ip(), "hostname": platform.node(),
            "user": getpass.getuser(), "program": myprog, "level":"%(levelname)s", "message": "%(message)s"}
        self.formatter = logging.Formatter(json.dumps(self.fields))
    def format(self, record, *args,**kwargs):
        self.fields.update({"timestamp":dt.now().timestamp()}) # update the timestamp for each message
        formatted = json.loads(self.formatter.format(record))
        if "extra" in record.__dict__ and isinstance(record.__dict__['extra'], dict):
            for k,v in record.__dict__['extra'].items():
                formatted[k] = v
        return formatted

class cfFormatter(logging.Formatter):
    def __init__(self, *args,**kwargs):
        super().__init__(*args, **kwargs)
    def format(self, record, *args,**kwargs):
        if "extra" in record.__dict__.keys() and isinstance(record.__dict__['extra'], dict):
            formatter = logging.Formatter("%(name)s: [%(levelname)s]: %(message)s - %(extra)s")
        else: formatter = logging.Formatter("%(name)s: [%(levelname)s]: %(message)s")
        return formatter.format(record)

def my_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("10.255.255.255", 1))
    return s.getsockname()[0]

if not token:
    raise Exception('MissingToken: Reading token from file {} failed.'.format(args.token))

def obj_to_asset(obj_type):
    return obj_type[0].lower() + obj_type[1:] + 's' if obj_type != 'Switch' else 'switches'

def asset_to_obj(asset):
    return asset[0].upper() + asset[1:-1] if asset != 'switches' else 'Switch'

def main():
    log.debug('{} invoked by user {}'.format(myprog, getpass.getuser()))
    obj_tree = {
        'Storage': ['StorageNode','StoragePool','StorageVirtualMachine','InternalVolume','Volume','Qtree','Share','Port','Disk'],
        'StorageNode' :['StoragePool','InternalVolume','Volume','Port'],
        'StoragePool':['StorageVirtualMachine','InternalVolume','Volume','Disk'],
        'StorageVirtualMachine': ['StoragePool','InternalVolume','Volume','Qtree','Share'],
        'InternalVolume':['Volume','Qtree','Share','Quota'],
        'Volume':['DataStore','Port'],
        'Qtree':['Share','Quota'],
        'Host':['VirtualMachine','Port','Volume'],
        'DataStore':['Host','Vmdk'],
        'Switch':['Port'],
        'VirtualMachine':['Vmdk'] }
    annots = api.get('assets/annotations')
    if not annots:
        log.warning('No annotations found on tenant {}, tenantId: {}. Exiting.'.format(requests.utils.urlparse(api.base_url).netloc,api.sysinfo['tenantId']))
        exit(0)
    my_annot = None
    obj_from = None
    obj_to = None
    while not obj_to:
        if not my_annot:
            my_annot = inq.select(
                message="Select annotation:",
                choices=[Choice(annot, name=annot['name'],enabled=False) for annot in sorted(annots,key=lambda annot: annot['name'].casefold())],
                default=None, border=True, qmark='1.', amark=u'\u2713', pointer=u'\u25BA', show_cursor=False, instruction='(or press CTRL-C to abort)'
            ).execute()
        if not obj_to:
            obj_from = inq.select(
                message='Select object type to inherit annotation "{}" from (source):'.format(my_annot['name']),
                choices=sorted([t for t in my_annot['supportedObjectTypes'] if t in obj_tree.keys()]), default=None, border=True, qmark='2.', 
                amark=u'\u2713', pointer=u'\u25BA', show_cursor=False, instruction='(or press CTRL-Z to go back)', mandatory = False
            ).execute()
            if obj_from:
                obj_to = inq.select(
                    message='Select object type to inherit annotation "{}" to (target):'.format(my_annot['name']),
                    choices=sorted(obj_tree[obj_from]), default=None, border=True, qmark='3.', amark=u'\u2713',
                    pointer=u'\u25BA', show_cursor=False, instruction='(or press CTRL-Z to go back)', mandatory = False
                    ).execute()
            else:
                my_annot = None

    log.info(f'Annotation {my_annot["name"]} selected to inherit from {obj_from} to {obj_to}')
    annots_from = api.get('{}/values/{}'.format(my_annot['self'],obj_from))
    payloads = []
    if not annots_from:
        log.info(f'No {obj_from} with annotation {my_annot["name"]} found.')
        exit()
    for annot in annots_from:
        for tgt in annot['targets']:
            targets = api.get('{}/{}'.format(tgt,obj_to_asset(obj_to)))
            if targets:
                if not payloads: payloads.append({"objectType": obj_to,"values": []})
                # iterate through targets and add to payloads in batches of MAX_PAYLOAD_TARGETS
                for target in targets:
                    if sum([len(v['targets']) for v in payloads[-1]['values']]) < MAX_PAYLOAD_TARGETS:
                        if annot['rawValue'] not in [rv['rawValue'] for rv in payloads[-1]['values']] :
                            payloads[-1]['values'].append({'rawValue': annot['rawValue'], 'targets': []})
                        for val in payloads[-1]['values']:
                            if val['rawValue'] == annot['rawValue']: val['targets'].append(target['id'])
                    else: # MAX_PAYLOAD_TARGETS reached, add new batch to payloads
                        payloads.append({"objectType": obj_to,"values": [{'rawValue': annot['rawValue'], 'targets': [target['id']]}]})
            else:
                asset = api.get(tgt) # retrieve asset name for log message
                log.warning(f'No {obj_to_asset(obj_to)} found for {obj_from} {asset["name"]}')
    if payloads:
        log.info('Submitting payload of annotation assignments in batches of up to {} targets'.format(MAX_PAYLOAD_TARGETS))
        for n,payload in enumerate(payloads,1):
            tgt_count = sum([len(val['targets']) for val in payload['values']])
            log.debug(f'Submitting annotations payload {n} with {tgt_count} targets',extra={'extra':{'payload':[payload]}})
            resp = api.put(my_annot['self']+'/values', json=[payload])
            log.info(f'Payload {n}: Annotations applied: {resp}')
    
    print('All done, have a nice day!')
    exit(0)

if __name__ == '__main__':
    with ciSession(token = token, proxy=proxy, base_url = args.url, loglevel=args.loglevel) as api:
        # Set up logging with console handler and custom ci handler
        log = logging.getLogger(f'{myprog}') # create logger instance
        ch = logging.StreamHandler()
        ch.setLevel(args.loglevel)
        ch_fmt = cfFormatter()
        ch.setFormatter(ch_fmt)
        log.addHandler(ch)
        if LOG_TO_CI == True:
            cih = CiHttpHandler(api)
            cih_fmt = CiJsonFormatter(log_type=CI_LOGTYPE)
            cih.setLevel(CI_LOGLEVEL)
            cih.setFormatter(cih_fmt)
            log.addHandler(cih)
            log.setLevel(min(cih.level,ch.level))
        else:
            log.setLevel(ch.level)
        main()
