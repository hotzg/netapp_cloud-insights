#!/usr/bin/env python3
import requests, logging, logging.handlers, json, argparse, os, platform, socket, uuid, signal, pathlib, stat
from datetime import datetime as dt, timedelta as td, timezone as tz

# argument parsing
parser = argparse.ArgumentParser()
myprog = parser.prog.replace('.py','')
parser.add_argument('-u','--url', action='store', required=True, help='URL to CI Tenant: https://xy1234.c0[1|2].cloudinsights.netapp.com')
parser.add_argument('-t','--token', action='store', required=True, help='Token file containing the actual token for the CI Tenant')
parser.add_argument('-d','--dir', action='store', required=True, help='Target directory to scan and submit info about')
parser.add_argument('-dry','--dryrun', action='store_true', required=False, help='Dryrun mode - Don\'t send data to the CI Tenant')
parser.add_argument('-ll','--loglevel', action='store', required=False, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], type=lambda txt: txt.upper(), default='INFO', help='Loglevel for console output (default: INFO)')
args = parser.parse_args()

# global vars
LOGFILE_LOGLEVEL = 'DEBUG'
DATA_SOURCE = myprog # optionally change to desired value
DATA_CATEGORY='directory' # this is the name of the category (i.e. dir_stats.abc.xyz) under which the data will be published in CI

workdir = os.path.dirname(os.path.abspath(__file__))
os.chdir(workdir)
if not os.path.isdir(os.path.join(workdir,'logs')):
    os.makedirs(os.path.join(workdir,'logs'), mode=0o700, exist_ok=True)

class ciSession(requests.Session):
    def __init__(self, token, base_url = None, verify=True, DisableInsecureRequestWarning = False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if DisableInsecureRequestWarning: requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.headers['X-CloudInsights-ApiKey'] = token
        self.verify = verify
        self.base_url = base_url
    def request(self, method, url, *args, **kwargs):
        # example: url = /rest/v1/assets/switches
        url = requests.sessions.urljoin(self.base_url, url.strip('/'))
        #requests.logging.debug(f'{method} {url}')
        return super().request(method, url, *args, **kwargs)

# Set up logging with rotating file handler and console handler
log = logging.getLogger(f'{myprog}') # create logger instance
requests.urllib3.connectionpool.log = log
rfh = logging.handlers.RotatingFileHandler('%s' %(os.path.join('logs',f'{myprog}.log')), maxBytes=26214400, backupCount=10)
rhf_fmt = logging.Formatter(fmt='%(asctime)s %(name)s %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
rfh.setLevel(LOGFILE_LOGLEVEL)
rfh.setFormatter(rhf_fmt)
log.addHandler(rfh)
ch = logging.StreamHandler()
ch.setLevel(args.loglevel)
ch_fmt = logging.Formatter(fmt="%(name)s: [%(levelname)s]: %(message)s")
ch.setFormatter(ch_fmt)
log.addHandler(ch)
log.setLevel(min(rfh.level,ch.level))

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

def submit_metrics(metrics, category):
    headers = {'X-CloudInsights-Lake-Category': category}
    r = api.post('/rest/v1/lake/ingest/influxdb', json = metrics, headers=headers)
    if r.status_code == 200:
        return r.json()
    else: return r.text

def main():
    # meta = api.delete('/rest/v1/lake/metadata/dir_stats',headers={ "accept": "*/*"}).json()
    # print(meta)
    # exit(0)
    log.debug(f'### {myprog}.py invoked by user: {os.getlogin()} ###')
    path = pathlib.Path(args.dir)
    if not path.exists(): log.error(f'Specified directory {args.dir} does not exist. Exiting!')
    else:
        my_ip = get_ip()
        ts = int(dt.now().timestamp()*1000)
        stats = {'metrics' : []}
        for p in path.rglob('.'): # for all subdirs
            _st = p.stat()
            stats['metrics'].append(
            {'name': 'stats',
             'tags': {'agent_host':socket.getfqdn(), 'agent_node_ip':my_ip,
             'agent_node_uuid':uuid.NAMESPACE_DNS.urn.split(':')[-1].upper(),'agent_node_os':platform.platform(), 'source':DATA_SOURCE,
             'base_name':p.name,'absolute':p.absolute().__str__(),'stem':p.stem,'parent':p.parent.__str__(),
             'owner':p.owner() if platform.system() != 'Windows' else 'N/A',
             'group':p.group() if platform.system() != 'Windows' else 'N/A',
             'uid': _st.st_uid, 'gid': _st.st_gid,
             'atime': dt.fromtimestamp(_st.st_atime,tz=tz.utc).replace(microsecond=0).isoformat(),
             'ctime': dt.fromtimestamp(_st.st_ctime,tz=tz.utc).replace(microsecond=0).isoformat(),
             'mtime': dt.fromtimestamp(_st.st_mtime,tz=tz.utc).replace(microsecond=0).isoformat(),
             'filemode': stat.filemode(_st.st_mode)
             },
             'fields':{'size_bytes': p.stat().st_size # size of subdir
                        + sum([f.stat().st_size for f in p.rglob('*') if not f.is_symlink()]) # size of all files exept smlinks
                        + sum([f.lstat().st_size for f in p.rglob('*') if f.is_symlink()]), # size of all symlinks (incl. broken)
             'subdir_count': len([d for d in p.iterdir() if d.is_dir()]), 'file_count': len([d for d in p.iterdir() if not d.is_dir()])
             },
             'timestamp':ts
            })
        if args.dryrun:
            log.info('DRYRUN: Metrics are not being sent:')
            log.debug(f'Metrics: {stats}')
            print()
        else:
            log.info(f'Submitting event data to Tenant {requests.utils.urlparse(args.url).netloc}')
            log.debug(f'Metrics: {stats}')
            log.info('Result: {}'.format(submit_metrics(stats, category=DATA_CATEGORY)))
            print()
    print('All done, have a nive day!')
    exit(0)

if __name__ == '__main__':
    with open(args.token, 'r') as fp:
         token = fp.read()
    with ciSession(token = token, base_url = args.url) as api:
        main()
