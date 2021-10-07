#!/usr/bin/env bin/python3
import requests, logging, logging.handlers, json, argparse, os

# global vars
LOGFILE_LOGLEVEL = 'INFO'

# argument parsing
parser = argparse.ArgumentParser()
myprog = parser.prog

parser.add_argument('-u','--url', action='store', required=True, help='URL to CI Tenant: https://xy1234.c0[1|2].cloudinsights.netapp.com')
parser.add_argument('-t','--token', action='store', required=True, help='Token file containing the actual token for the CI Tenant')
parser.add_argument('-ll','--loglevel', action='store', required=False, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], type=lambda txt: txt.upper(), default='INFO', help='Loglevel for console output (default: INFO)')
args = parser.parse_args()

myprg = os.path.basename(__file__).replace('.py','')
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
log = logging.getLogger(f'{myprg}') # create logger instance
requests.urllib3.connectionpool.log = log
rfh = logging.handlers.RotatingFileHandler('%s' %(os.path.join('logs',f'{myprg}.log')), maxBytes=26214400, backupCount=10)
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

def main():
    log.info('{} invoked by user {}'.format(myprog, os.getlogin()))
    annotations = api.get('/rest/v1/assets/annotations').json()
    # create annotation if doesn't exist
    if 'isMirrored' not in [a['name'] for a in annotations]:
         my_annot = api.post('/rest/v1/assets/annotations', json={"name": "isMirrored", "type": "BOOLEAN", "description": "Aggregate is mirrored", "enumValues": [], "supportedObjectTypes": ["StoragePool"]}).json()
    else: # else look up isMirrored annotation
        for annot in annotations:
            if annot['name'] == 'isMirrored': my_annot = annot
    payload = [{"objectType": "StoragePool","values": [{"rawValue": "true", "targets": []},{"rawValue": "false", "targets": []}]}]
    storages = api.get('/rest/v1/assets/storages').json()
    if not storages:
        # throw warning and exit if no storages found
        log.warning('No storages to be found on {} - Exiting.'.format(requests.utils.urlparse(api.base_url).netloc))
        exit(0)
    for sto in storages:
        # iterate through storages
        log.info('Looking at storage: {}'.format(sto['name']))
        if sto['vendor'] != 'NetApp' or 'clustered Data ONTAP' not in sto['microcodeVersion']:
            log.info('Ignoring storage {} - vendor {}; microcode {}'.format(sto['name'],sto['vendor'],sto['microcodeVersion']))
            continue # move on to next storage
        # get ths storage pools
        pools = api.get(sto['self']+'/storagePools').json()
        # iterate through pools
        for pool in pools:
            # get the disks
            disks = api.get(pool['self']+'/disks').json()
            plexes = []
            # iterate through disks
            for disk in disks:
                if disk['diskGroup'] != 'N/A' and disk['isVirtual'] == False:
                    # get the plex name
                    plex = disk['diskGroup'].split('/')[-2]
                    if plex not in plexes:
                        plexes.append(plex)
            # determine isMirrored value based on number of plexes
            is_mirrord = True if len(plexes) == 2 else False
            log.info('pool: {} - plexes: {} - isMirrored: {}'.format(pool['name'], len(plexes), is_mirrord))
            #build payload to update annotations with
            for val in payload[0]['values']:
                if val['rawValue'] == "true":
                    if is_mirrord == True: val['targets'].append(pool['id'])
                if val['rawValue'] == "false":
                    if is_mirrord == False: val['targets'].append(pool['id'])
    # submit payload
    submit = api.put(my_annot['self']+'/values', json = payload)
    log.info('isMirrored annotations updated: {}'.format(submit.json()))
    print('All done, have a nive day!')
    exit(0)

if __name__ == '__main__':
    with open(args.token, 'r') as fp:
         token = fp.read()
    with ciSession(token = token, base_url = args.url) as api:
        main()
