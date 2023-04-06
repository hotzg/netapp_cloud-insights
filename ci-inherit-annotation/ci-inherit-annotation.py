#!/usr/bin/env python3
import os, logging, logging.handlers, requests, math, json, re, argparse, curses
from curses import panel
from datetime import datetime as dt, timedelta as td, timezone as tz

# global VARS
LOGFILE_LOGLEVEL = 'DEBUG'

# argument parsing
parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description = '* Inherit annotations from one object-type to another in NetApp Cloud Insights.'
    )
myprog = parser.prog.replace('.py','')
parser.add_argument('-u','--url', action='store', required=True, help='URL to CI Tenant: https://ci_tenat.cloudinsights.netapp.com')
parser.add_argument('-t','--token', action='store', required=True, help='Token file containing the actual token for the CI Tenant')
parser.add_argument('-mx','--max-payload-targets', action='store', required=False, type=int, default=5000, help='Split payload and annotate no more than MAX_PAYLOAD_TARGETS at a time to avoid server timeouts')
parser.add_argument('-ld','--log-dir', action='store', required=False, default=os.path.join(os.path.expanduser("~"),'.'+myprog,'log'), help='Log directory in which to write log files in')
parser.add_argument('-ll','--loglevel', action='store', required=False, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],\
                    type=lambda txt: txt.upper(), default='INFO', help='Loglevel for console output')
args = parser.parse_args()

with open(args.token, 'r') as fp:
    lines = fp.readlines()
token = None
for line in lines:
     if not line.startswith('#') and len(line) > 472:
         token = line.rstrip('\n') if line.endswith('\n') else line

class Menu(object):
    def __init__(self, stdscreen, items, title = None, back_button = False):
        self.window = stdscreen.subwin(0, 0)
        self.window.keypad(1)
        self.panel = panel.new_panel(self.window)
        self.panel.hide()
        panel.update_panels()
        self.margin_top = 0
        self.offset = 0
        self.position = 1
        self.title = title
        self.items = items
        self.back_button = back_button
        if len(self.items) >= curses.LINES:
            self.max_items = math.ceil(len(self.items)/math.ceil(len(self.items)/curses.LINES))-2
        else:
            self.max_items = len(self.items)
        self.select = None
    def navigate(self, n):
        if n > 0: # navigating down
            if self.position +n <= self.max_items + self.offset: # scroll with cursor only
                self.position += n
            elif self.position +n >= len(self.items): # stop scrolling at end of list
                if self.back_button:
                    self.position = len(self.items) +2
                    self.offset = self.position - self.max_items -2
                else:
                    self.position = len(self.items)
                    self.offset = self.position - self.max_items
            else: # scroll with cursor and items
                self.position += n
                self.offset = self.position - self.max_items
        else: #navigating up
            if self.position + n <= 0:
                self.position = 1
                self.offset = 0
            elif self.back_button and self.position == len(self.items) +2:
                self.position += n-1
            elif self.offset > 0:
                if self.position + n > self.offset:
                    self.position += n
                else:
                    self.position += n
                    self.offset += n
            else:
                self.position += n
    def display(self):
        self.panel.top()
        self.panel.show()
        self.window.clear()
        max_item_len = max(max([len(itm) for itm in self.items])+4,len(self.title)+4)
        if self.title:
            self.margin_top = 1
            curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
            self.window.addstr(0, 1, "{}".format(self.title.center(max_item_len+4)), curses.A_REVERSE)
        while True:
            self.window.refresh()
            curses.doupdate()
            for index, item in enumerate(self.items[self.offset:self.max_items+self.offset], self.offset+1):
                if index == self.position: mode = curses.A_REVERSE
                else: mode = curses.A_NORMAL
                msg = "{:<4}{}".format(index, item.rjust(max_item_len))
                self.window.addstr(index+self.margin_top-self.offset, 1, msg, mode)
            if self.back_button:
                if self.position == len(self.items) + 2: mode = curses.A_REVERSE
                else: mode = curses.A_NORMAL
                self.window.addstr(self.margin_top+self.max_items+2, 1, 'Back', mode)
            key = self.window.getch()
            if key in [curses.KEY_ENTER, ord("\n")]:
                if self.position <= len(self.items):
                    self.select = self.position-1
                elif self.back_button and self.position == len(self.items)+2:
                    self.select = -1
                break
            elif key == curses.KEY_UP: self.navigate(-1)
            elif key == curses.KEY_PPAGE: self.navigate(math.ceil(self.max_items*-0.25))
            elif key == curses.KEY_HOME: self.navigate(self.position*-1)
            elif key == curses.KEY_DOWN: self.navigate(1)
            elif key == curses.KEY_NPAGE: self.navigate(math.ceil(self.max_items*0.25))
            elif key == curses.KEY_END: self.navigate(len(self.items) - self.position)
            elif key == ord("q"): break
            elif self.back_button and key == ord("b"): self.select = -1; break
        self.window.clear()
        self.panel.hide()
        panel.update_panels()
        curses.doupdate()

class SelectFromList(object):
    def __init__(self, stdscreen, menuitems, title = None, back_button = False):
        self.screen = stdscreen
        curses.curs_set(0)
        curses.use_default_colors()
        menu_items = [itm for itm in menuitems]
        main_menu = Menu(self.screen, menu_items, title = title, back_button = back_button)
        main_menu.display()
        self.pick = main_menu.select

class ciSession(requests.Session):
    def __init__(self, token, base_url = None, verify=True, DisableInsecureRequestWarning = False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if DisableInsecureRequestWarning: requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.headers['X-CloudInsights-ApiKey'] = token
        self.verify = verify
        self.base_url = base_url
        self.sysinfo = requests.get(requests.sessions.urljoin(base_url,'rest/v1/systemInfo')).json()
    def request(self, method, url, base_path='/rest/v1', strip_token=False, *args, **kwargs):
        if strip_token: self.headers.pop('X-CloudInsights-ApiKey')
        url = requests.sessions.urljoin(self.base_url, f'{base_path.strip("/")}/{url.strip("/")}')
        r = super().request(method, url, *args, **kwargs)
        if not r.ok: raise Exception(f'apiRequestError: <{r.status_code}>, url: {r.request.url}, {r.text}')
        return r.json()

# Set up logging with rotating file handler and console handler
if not os.path.isdir(args.log_dir): os.makedirs(args.log_dir, mode=0o700, exist_ok=True)
log = logging.getLogger(f'{myprog}') # create logger instance
requests.urllib3.connectionpool.log = log
rfh = logging.handlers.RotatingFileHandler('%s' %(os.path.join(args.log_dir,f'{myprog}.log')), maxBytes=26214400, backupCount=10)
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

log.debug('{} invoked by user {}'.format(myprog, os.getlogin()))

if not token:
    log.critical('Reading token from file {} failed. Exiting'.format(args.token))
    raise Exception('MissingToken: Reading token from file {} failed.'.format(args.token))

def obj_to_asset(obj_type):
    return obj_type[0].lower() + obj_type[1:] + 's' if obj_type != 'Switch' else 'switches'

def asset_to_obj(asset):
    return asset[0].upper() + asset[1:-1] if asset != 'switches' else 'Switch'

def split_payload(payload,max_targets):
    # returns list of payloads dicts
    payloads = []
    # total_targets: num of targets passed in
    total_targets = sum([len(val['targets']) for val in payload['values']])
    # max_tgts: max targets per list item to return
    max_tgts = math.ceil(total_targets/math.ceil(total_targets/max_targets))
    for n,val in enumerate(payload['values']):
        for i in range(0,len(val['targets']),max_tgts):
            diff = max_tgts - sum([len(val['targets']) for val in payloads[-1]['values']]) if len(payloads) > 0 else 0
            my_tgt = val['targets'][i:i+max_tgts]
            if diff == 0:
                payloads.append({'objectType': payload['objectType'],'values': [{'rawValue': val['rawValue'], 'targets': my_tgt}]})
            elif len(my_tgt) <= diff:
                if val['rawValue'] not in [v['rawValue'] for v in payloads[-1]['values']]:
                    payloads[-1]['values'].append({'rawValue': val['rawValue'], 'targets': my_tgt})
                else:
                    for v in payloads[-1]['values']:
                        if val['rawValue'] == v['rawValue']:
                            v['targets'].extend(my_tgt)
            else:
                if val['rawValue'] not in [v['rawValue'] for v in payloads[-1]['values']]:
                    payloads[-1]['values'].append({'rawValue': val['rawValue'], 'targets': my_tgt[:diff]})
                    payloads.append({'objectType': payload['objectType'],'values': [{'rawValue': val['rawValue'], 'targets': my_tgt[diff:]}]})
                else:
                    for v in payloads[-1]['values']:
                        if val['rawValue'] == v['rawValue']:
                            v['targets'].extend(my_tgt[:diff])
                    payloads.append({'objectType': payload['objectType'],'values': [{'rawValue': val['rawValue'], 'targets': my_tgt[diff:]}]})
    return payloads

def main():
    obj_tree = {
        'Storage': ['StorageNode','StoragePool','StorageVirtualMachine','InternalVolume','Volume','Qtree','Share','Port','Disk'],
        'StorageNode' :['StoragePool','InternalVolume','Volume','Port'],
        'StoragePool':['StorageVirtualMachine','InternalVolume','Volume','Disk'],
        'StorageVirtualMachine': ['StoragePool','InternalVolume','Volume','Qtree','Share'],
        'InternalVolume':['Volume','Qtree','Share','Quota'],
        'Volume':['DataStore','Port'],
        'Qtree':['Share'],
        'Host':['VirtualMachine','Volume'],
        'DataStore':['Host','Vmdk'],
        'Switch':['Port'],
        'VirtualMachine':['Vmdk'] }
    annots = sorted(api.get('assets/annotations'),key=lambda annot: annot['name'])
    if not annots:
        log.warning('No annotations found on tenant {}, tenantId: {}. Exiting.'.format(requests.utils.urlparse(api.base_url).netloc,api.sysinfo['tenantId']))
        exit(0)
    annot_names = [annot['name'] for annot in annots]
    my_annot = obj_from = obj_to = None
    while not obj_to:
        if not my_annot:
            choice = curses.wrapper(SelectFromList, annot_names, title = "Select annotation")
            if choice.pick == None:
                print('No annotation selected. Good bye.' )
                exit(0)
            my_annot = annots[choice.pick]
        inherit_from = sorted([t for t in my_annot['supportedObjectTypes'] if t in obj_tree.keys()])
        if not obj_from:
            if inherit_from:
                choice = curses.wrapper(SelectFromList, inherit_from, title = "Select object type to inherit {} from (source)".format(my_annot['name']), back_button=True)
                if choice.pick == None:
                    print('No object type to inherit from (source) selected. Exiting.' )
                    exit(0)
                elif choice.pick == -1:
                    my_annot = None
                    continue
                else: obj_from = inherit_from[choice.pick]
            else:
                print(f"No supported object types found for annotation {my_annot['name']} to inherit from. Exiting.")
                exit(0)
        inherit_to = sorted(obj_tree[inherit_from[choice.pick]])
        choice = curses.wrapper(SelectFromList, inherit_to, title = "Select object type to inherit {} to (target)".format(my_annot['name']), back_button=True)
        if choice.pick == None:
            print('No object type to inherit to (target) selected. Exiting.' )
            exit(0)
        elif choice.pick == -1: obj_from = None
        else: obj_to = inherit_to[choice.pick]

    log.info(f'Annotation {my_annot["name"]} selected to inherit from {obj_from} to {obj_to}')
    annots_from = api.get(my_annot['self']+f'/values/{obj_from}',base_path='')
    annots_to = {"objectType": obj_to,"values": []}
    for annot in annots_from:
        for num,src in enumerate(annot['targets']):
            obj = api.get(src,base_path='')
            targets = api.get(src+f'/{obj_to_asset(obj_to)}',base_path='')
            if targets:
                if not annots_to['values'] or annot['rawValue'] not in [v['rawValue'] for v in annots_to['values']]:
                    annots_to['values'].append({"rawValue": annot['rawValue'],"targets": []})
                for n,val in enumerate(annots_to['values']):
                    if val['rawValue'] == annot['rawValue']:
                        log.debug('Adding annotation targets for {}: {}'.format(obj['name'],', '.join([obj['name'] for obj in targets])))
                        val['targets'].extend([obj['id'] for obj in targets])
            else:
                log.warning(f'No {obj_to_asset(obj_to)} found for {obj_from} {obj["name"]}')

    for num,val in enumerate(annots_to['values']):
        if not val['targets']:
            log.info(f"No target {annots_to['objectType']} found for annotation {my_annot['name']}, value {val['rawValue']}.")
            log.debug(f"Removing from payload: {annots_to['values'].pop(num)}")
    if not annots_to['values']:
        log.info(f"No annotation values for \"{my_annot['name']}\" found. Nothing to inherit.")
        exit()
    if sum([len(val['targets']) for val in annots_to['values']]) > args.max_payload_targets:
        payloads = split_payload(annots_to,args.max_payload_targets)
        log.debug(f'Annotation targets exceed MAX_PAYLOAD_TARGETS = {args.max_payload_targets}. Perfroming staggered payload submit.')
        for n,payload in enumerate(payloads):
            log.debug(f'Submitting annotations payload {n}: {payload}')
            resp = api.put(my_annot['self']+'/values',base_path='', json=[payload])
            log.info(f'Payload {n}: Annotations applied: {resp}')
    else:
        log.debug(f'Submitting annotations payload: {annots_to}')
        resp = api.put(my_annot['self']+'/values',base_path='', json=[annots_to])
        log.info(f'Annotations applied: {resp}')
    print('All done, have a naice day!')
    exit(0)

if __name__ == '__main__':
    with ciSession(token = token, base_url = args.url) as api:
        main()
