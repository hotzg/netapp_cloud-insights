#!/usr/bin/env python3
import os, pathlib, concurrent.futures, requests, threading
import logging, logging.handlers, json, csv, re, argparse, math
from datetime import datetime as dt, timedelta as td, timezone as tz
from collections import abc

# global VARS
LOGFILE_LOGLEVEL = 'DEBUG'
LOGDIR = './log'
LIMIT = 1000 # adjust this to tune number of results per query
MAX_THREADS = 50 # adjust this to tune max number of threads to spin up

# argument parsing
parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description = '* Import applications business entites, custom annotations from CSV file to NetApp CloudInsights')
myprog = parser.prog.rstrip('.py')
parser.add_argument('-u','--url', action='store', required=True, help='URL to CI Tenant: https://xy1234.c0[1|2].cloudinsights.netapp.com')
parser.add_argument('-t','--token', action='store', type=pathlib.Path, required=True, help='Token file containing the actual token for the CI Tenant')
parser.add_argument('-f', '--csv-file', action='store', type=pathlib.Path, required=True, help='CSV file containing applications, business entites, custom annotations.')
parser.add_argument('-mm','--match-mode', action='store', required=False, choices=['STRICT', 'LAX'], type=lambda txt: txt.upper(), default='STRICT', help='Option for matching assets exactly/case-sensitive or partially/case-insensitive')
parser.add_argument('-del','--delete', action='store_true', required=False, default=False, help='Option for deleting ALL applications or the annotation of the corresponding column when row value empty.')
parser.add_argument('-ll','--loglevel', action='store', required=False, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], type=lambda txt: txt.upper(), default='INFO', help='Loglevel for console output')
args = parser.parse_args()

if args.delete:
    answer = None
    while answer not in ['Yes','No','no','N','n']:
        print('\n\x1b[1;31m Warning! Running with --delete Option. For rows with empty values for application/annotation,\n this will remove ALL applications or the annotation of the corresponding column from the identified target.\x1b[0m Continue? ',end='')
        answer = input('(Yes/No): ')
    if answer == 'Yes': pass
    else: exit()

token_file = args.token.resolve().__str__()
token = None
if args.token.exists():
    with args.token.open(mode='r') as fp:
        lines = fp.readlines()
    for line in lines:
        if not line.startswith('#') and len(line) > 472:
            # look for the first uncommented line of sufficient length as the token
            token = line.rstrip('\n') if line.endswith('\n') else line
            break
if not token:
    raise Exception('MissingToken: Reading token from file {} failed.'.format(token_file))

# Set up logging with rotating file handler and console handler
if not os.path.isdir(LOGDIR): os.makedirs(LOGDIR, mode=0o700, exist_ok=True)
log = logging.getLogger(f'{myprog}') # create logger instance
requests.urllib3.connectionpool.log = log
rfh = logging.handlers.RotatingFileHandler('%s' %(os.path.join(LOGDIR,f'{myprog}.log')), maxBytes=26214400, backupCount=10)
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

class ciSession(requests.Session):
    def __init__(self, token, base_url = None, verify=True, DisableInsecureRequestWarning = False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if DisableInsecureRequestWarning: requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.headers['X-CloudInsights-ApiKey'] = token
        self.verify = verify
        self.base_url = base_url
        #self.sysinfo = requests.get(requests.sessions.urljoin(base_url,'rest/v1/systemInfo')).json()
    def request(self, method, url, base_path='/rest/v1', strip_token=False, *args, **kwargs):
        if strip_token: self.headers.pop('X-CloudInsights-ApiKey')
        url = requests.sessions.urljoin(self.base_url, f'{base_path.strip("/")}/{url.strip("/")}')
        r = super().request(method, url, *args, **kwargs)
        if not r.ok: raise Exception(f'apiRequestError: <{r.status_code}>, url: {r.request.url}, {r.text}')
        return r.json()

thread_local = threading.local()
def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = ciSession(token = token, base_url = args.url)
    return thread_local.session

def fetch_results(url,params):
    session = get_session()
    return session.get(url,params=params)

def obj_to_asset(obj):
    if obj == 'Switch': return 'switches'
    elif obj == 'VM': return 'virtualMachines'
    else: return obj[0].lower() + obj[1:] +'s'

def asset_to_obj(asset):
    if asset == 'switches': return 'Switch'
    else: return asset[0].upper() + asset[1:-1]

def is_ip(addr):
    import ipaddress
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False

def find_asset(asset_type, asset_name_or_id, match_mode, ci_assets):
    """
    # from API docs: /assets/import
    1. Host             id-><id> or <Name> or <IP>
    2. VM               id-><id> or <Name>
    3. StoragePool      id-><id> or <Storage Name>-><Storage Pool Name>
    4. InternalVolume   id-><id> or <Storage Name>-><Internal Volume Name>
    5. Volume           id-><id> or <Storage Name>-><Volume Name>
    6. Storage          id-><id> or <Name> or <IP>
    7. Switch           id-><id> or <Name> or <IP>
    8. Port             id-><id> or <WWN>
    9. Qtree            id-><id> or <Storage Name>-><Internal Volume Name>-><Qtree Name>
    10. Share           id-><id> or <Storage Name>-><Internal Volume Name>-><Share Name>-><Protocol>[-><Qtree Name>]
    """
    asset_found = None
    if re.match(r'^id->', asset_name_or_id):
        for asset in ci_assets:
            if asset_name_or_id.split('->')[1] == asset['id']:
                asset_found = asset
                break
    else:
        if asset_type == 'Port':
            for asset in ci_assets:
                if asset_name_or_id == asset['wwn']:
                    asset_found = asset
                    break
        elif asset_type in ['VM','Host','Storage','Switch']:
            if is_ip(asset_name_or_id):
                for asset in ci_assets:
                    if asset_name_or_id == asset['ip']:
                        asset_found = asset
                        break
            else:
                for asset in ci_assets:
                    if match_mode == 'LAX':
                        # look for characters up to first dot.
                        if asset['name'].lower().split('.')[0] == asset_name_or_id.lower().split('.')[0]:
                            asset_found = asset
                            break
                    else:
                        if asset['name'] == asset_name_or_id:
                            asset_found = asset
                            break
        elif asset_type in ['StoragePool', 'InternalVolume', 'Volume']:
            parts = asset_name_or_id.split('->')
            if len(parts) == 2:
                for asset in ci_assets:
                    if match_mode == 'LAX':
                        sto, obj = [pt.lower() for pt in parts]
                        if "clustered Data ONTAP" in asset['storage']['microcodeVersion']:
                            if sto == asset['storage']['name'].lower() and asset['name'].lower().split(':')[-1] == obj.split(':')[-1]:
                                asset_found = asset
                                break
                        else:
                            if sto == asset['storage']['name'].lower() and asset['name'].lower() == obj:
                                asset_found = asset
                                break
                    else:
                        if parts == [asset['storage']['name'], asset['name']]:
                            asset_found = asset
                            break
            else:
                log.warning(f"Asset Type {asset_type} name format seperator count mismatch: {asset_name_or_id} \"->\" count = {len(parts)}")
        elif asset_type == 'Qtree':
            # to be added
            pass
        elif asset_type == 'Share':
            # to be added
            pass
    return asset_found

def main():
    rows = []
    with args.csv_file.open(mode='r') as fp:
        reader = csv.reader(fp.readlines())
        for row in reader:
            rows.append(row)
    columns = rows.pop(0)
    ci_applications = api.get('assets/applications')
    ci_annotations = api.get('assets/annotations')
    be_parts = ['Tenant', 'Line_of_Business', 'Business_Unit', 'Project']
    business_entity = None
    for annot in ci_annotations:
        if annot['name'] == 'Business Entity': business_entity = annot
    if not business_entity:
        log.critical('Business Entity annotation could not be found in CI. Aborting')
        BuMissingError =  Exception(f'Business Entity missing in CI.')
        raise BuMissingError
    ci_apps_missing, ci_annots_missing, ci_be_missing = list(), list(), list()
    applications_payload = dict()
    applications_delete_payload = list()
    annotations_payload = dict()
    annotations_delete_payload = dict()
    for num,col in enumerate(columns[2:],2):
        if col == 'Application':
            for app_name in set([row[num].strip() for row in rows if row[num]]):
                if app_name in [app['name'] for app in ci_applications]:
                    log.info(f'Application found in CI tenant - skipping create: {app_name}')
                else:
                    log.info(f'Application missing in CI tenant - to be created: {app_name}')
                    ci_apps_missing.append(app_name)
        else:
            if col in be_parts:
                log.info(f'Annotation is part of Business_Entity - skipping create: {col}')
            elif col in [annot['name'] for annot in ci_annotations]:
                log.info(f'Annotation found in CI tenant - skipping create: {col}')
            else:
                log.info(f'Annotation missing in CI tenant - to be created: {col}')
                ci_annots_missing.append(col)
    stats = { 'apps_created': len(ci_apps_missing),
              'apps_assigned':0,
              'apps_unassigned':0,
              'annots_created': len(ci_annots_missing),
              'annots_assigned':0,
              'annots_unassigned':0,
              'be_added':0,
              'be_assigned':0,
              'be_unassigned':0 }
    ci_assets = dict()
    for obj in set([row[0] for row in rows]):
        if obj == None or obj not in ["Host", "VM", "StoragePool", "InternalVolume", "Volume", "Storage", "Switch", "Port", "Qtree", "Share"]:
            log.error(f'Invalid objectType in column 1 detected: "{obj}"')
            raise ValueError('Invalid objectType in CSV.')
        params = {'objectType':asset_to_obj(obj_to_asset(obj)),'limit':LIMIT}
        if asset_to_obj(obj_to_asset(obj)) in ['Volume','InternalVolume','StoragePool','StorageVirtualMachine','Qtree','Share']:
            params['fields'] = 'storage.name'
        q1 = api.get('query',params=params)
        ci_assets[obj_to_asset(obj)] = q1['results']
        num_queries = math.ceil(q1['count']/LIMIT)
        if num_queries > 1: # spin up threads as needed for additional queries
            params_list = []
            for num in range(1,num_queries):
                my_params = params.copy()
                my_params['offset'] = num*LIMIT
                params_list.append(my_params)
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_THREADS,num_queries-1)) as executor:
                query_results = executor.map(fetch_results, ['query' for i in range(num_queries-1)], params_list)
                for item in query_results:
                    ci_assets[obj_to_asset(obj)].extend(item['results'])
    for n,row in enumerate(rows):
        if len(row) != len(columns):
            log.critical(f'Malformed CSV row {n+2}: number of value fields different from number of columns')
            raise Exception(f'malformedCsvError: number of value fields different from number of columns')
        if not row[0] or not row[1]:
            log.critical(f'Malformed CSV row {n+2}: values expected in columns 1 and 2')
            raise ValueError(f'malformedCsvError: values missing in columns 1 and/or 2')
        my_be_parts = ['N/A','N/A','N/A','N/A']
        my_asset = find_asset(row[0], row[1], args.match_mode, ci_assets[obj_to_asset(row[0])])
        my_annot = None
        if not my_asset:
            log.debug(f"MISMATCH: {row[0]} {row[1]} not found in CI!")
            continue
        else:
            log.debug(f"MATCH: {row[0]} {row[1]} found - id: {my_asset['id']}; name: {my_asset['name']}")
            # loop through columns 2+
            for num,col in enumerate(columns[2:],2):
                if col == 'Application':
                    if row[num] == '':
                        if args.delete:
                            log.debug(f"Application value empty in row {num}, Applications to be deleted from target.")
                            to_be_unassigned = api.get(f"/assets/{obj_to_asset(row[0])}/{my_asset['id']}/applications")
                            if to_be_unassigned:
                                if to_be_unassigned[0]['id'] not in [[k for k in app.keys()][0] for app in applications_delete_payload]:
                                    applications_delete_payload.append({
                                    to_be_unassigned[0]['id']: [{"objectType": asset_to_obj(obj_to_asset(row[0])), "targets": [my_asset['id']]}]})
                                    stats['apps_unassigned'] += 1
                                else:
                                    for app in applications_delete_payload:
                                        if to_be_unassigned[0]['id'] in app.keys():
                                            if asset_to_obj(obj_to_asset(row[0])) not in [itm['objectType'] for itm in app[to_be_unassigned[0]['id']]]:
                                                app[to_be_unassigned[0]['id']].append({"objectType": asset_to_obj(obj_to_asset(row[0])), "targets": [my_asset['id']]})
                                                stats['apps_unassigned'] += 1
                                            else:
                                                for itm in app[to_be_unassigned[0]['id']]:
                                                    if itm['objectType'] == asset_to_obj(obj_to_asset(row[0])):
                                                        if my_asset['id'] not in itm['targets']:
                                                            itm['targets'].append(my_asset['id'])
                                                            stats['apps_unassigned'] += 1
                            else:
                                log.debug(f"No applications assigned to target {my_asset['name']}, nothing to delete.")
                                continue
                        else: continue
                    elif row[num] in ci_apps_missing:
                        my_app = api.post('assets/applications', json = {"name":row[num],"priority":"Medium", "ignoreShareViolations":False})
                        log.info(f'Application {row[num]} create response: {my_app}')
                        ci_apps_missing.remove(row[num])
                        ci_applications.append(my_app)
                    else:
                        for app in ci_applications:
                            if app['name'] == row[num]:
                                my_app = app
                    if my_app['id'] not in applications_payload.keys():
                        applications_payload[my_app['id']] = [{"objectType": asset_to_obj(obj_to_asset(row[0])), "targets": [my_asset['id']]}]
                        stats['apps_assigned'] += 1
                        continue
                    elif asset_to_obj(obj_to_asset(row[0])) not in [itm['objectType'] for itm in applications_payload[my_app['id']]]:
                        applications_payload[my_app['id']].append({"objectType": asset_to_obj(obj_to_asset(row[0])), "targets": [my_asset['id']]})
                        stats['apps_assigned'] += 1
                        continue
                    else:
                        for record in applications_payload[my_app['id']]:
                            if record["objectType"] == asset_to_obj(obj_to_asset(row[0])):
                                record["targets"].append(my_asset['id'])
                                stats['apps_assigned'] += 1
                                break
                        continue
                elif col in be_parts:
                    for n,part in enumerate(be_parts):
                        if row[num] and col.lower() == part.lower():
                            my_be_parts[n] = row[num].strip()
                else:
                    if col in ci_annots_missing:
                        pass
                        log.info(f'Annotation {col} create response: my_annot')
                        my_annot = api.post('assets/annotations', json = {"name":col,"type":"TEXT", "description":f"Created by custom script {myprog}, {dt.now(tz=tz.utc).replace(microsecond=0).isoformat()}"})
                        log.info(f'Annotation {col} create response: {my_annot}')
                        ci_annots_missing.remove(col)
                        ci_annotations.append(my_annot)
                    for annot in ci_annotations:
                        if col == annot['name']:
                            if args.delete and row[num] == '':
                                log.debug(f"Annotation value for {col} empty, deleting from target: {my_asset['name']}")
                                if annot['id'] not in annotations_delete_payload.keys():
                                    annotations_delete_payload[annot['id']] = []
                                if asset_to_obj(obj_to_asset(row[0])) not in [itm['objectType'] for itm in annotations_delete_payload[annot['id']]]:
                                    annotations_delete_payload[annot['id']].append({"objectType": asset_to_obj(obj_to_asset(row[0])),"targets": [my_asset['id']]})
                                    stats['annots_unassigned'] += 1
                                else:
                                    for record in annotations_delete_payload[annot['id']]:
                                        if record['objectType'] == asset_to_obj(obj_to_asset(row[0])):
                                            if my_asset['id'] not in record['targets']:
                                                record['targets'].append(my_asset['id'])
                                                stats['annots_unassigned'] += 1
                                continue
                            elif annot['id'] not in annotations_payload.keys():
                                annotations_payload[annot['id']] = [{"objectType": asset_to_obj(obj_to_asset(row[0])),
                                    "values": [{"rawValue": row[num],"targets": [my_asset['id']]}]}]
                                stats['annots_assigned'] += 1
                            else:
                                for annot_id in annotations_payload:
                                    if annot_id == annot['id']:
                                        if asset_to_obj(obj_to_asset(row[0])) not in [itm["objectType"] for itm in annotations_payload[annot_id]]:
                                            annotations_payload[annot_id].append({"objectType": asset_to_obj(obj_to_asset(row[0])),
                                                                    "values": [{"rawValue": row[num],"targets": [my_asset['id']]}]})
                                            stats['annots_assigned'] += 1
                                        else:
                                            for itm in annotations_payload[annot_id]:
                                                if itm["objectType"] == asset_to_obj(obj_to_asset(row[0])):
                                                    if row[num] not in [val["rawValue"] for val in itm["values"]]:
                                                        itm["values"].append({"rawValue": row[num],"targets": [my_asset['id']]})
                                                        stats['annots_assigned'] += 1
                                                    else:
                                                        for val in itm["values"]:
                                                            if val["rawValue"] == row[num]:
                                                                val["targets"].append(my_asset['id'])
                                                                stats['annots_assigned'] += 1
        my_be = '.'.join(my_be_parts)
        if args.delete and my_be == 'N/A.N/A.N/A.N/A':
            log.debug(f"All parts of business entity in row {n+2} empty, deleting from target: {my_asset['name']}")
            if business_entity['id'] not in annotations_delete_payload.keys():
                annotations_delete_payload[business_entity['id']] = [{"objectType": asset_to_obj(obj_to_asset(row[0])), "targets": [my_asset['id']]}]
            else:
                if asset_to_obj(obj_to_asset(row[0])) not in [itm['objectType'] for itm in annotations_delete_payload[business_entity['id']]]:
                    annotations_delete_payload[business_entity['id']].append({"objectType": asset_to_obj(obj_to_asset(row[0])), "targets": [my_asset['id']]})
                else:
                    for itm in annotations_delete_payload[business_entity['id']]:
                        if itm['objectType'] == asset_to_obj(obj_to_asset(row[0])):
                            if my_asset['id'] not in itm['targets']:
                                itm['targets'].append(my_asset['id'])
            stats['be_unassigned'] += 1
            continue
        elif my_be != 'N/A.N/A.N/A.N/A':
            if my_be not in [be['name'] for be in business_entity['enumValues']] and my_be not in ci_be_missing:
                log.info(f'Business Entity missing in CI tenant - to be added: {my_be}')
                ci_be_missing.append(my_be)
                stats['be_added'] += 1
            if business_entity['id'] not in annotations_payload.keys():
                annotations_payload[business_entity['id']] = [{"objectType": asset_to_obj(obj_to_asset(row[0])),"values": [{"rawValue": my_be,"targets": [my_asset['id']]}]}]
                stats['be_assigned'] += 1
            elif asset_to_obj(obj_to_asset(row[0])) not in [itm["objectType"] for itm in annotations_payload[business_entity['id']]]:
                annotations_payload[business_entity['id']].append({"objectType": asset_to_obj(obj_to_asset(row[0])),"values": [{"rawValue": my_be,"targets": [my_asset['id']]}]})
                stats['be_assigned'] += 1
            else:
                for itm in annotations_payload[business_entity['id']]:
                    if itm["objectType"] == asset_to_obj(obj_to_asset(row[0])):
                        if my_be not in [val["rawValue"] for val in itm["values"]]:
                            itm["values"].append({"rawValue": my_be,"targets": [my_asset['id']]})
                            stats['be_assigned'] += 1
                        else:
                            for val in itm["values"]:
                                if val == my_be and my_asset['id'] not in val["targets"]:
                                    val["targets"].append(my_asset['id'])
                                    stats['be_assigned'] += 1
    if ci_be_missing:
        for be in ci_be_missing:
            business_entity['enumValues'].append({"name": be, "description": "", "label": "", "isUserDefined": True})
        resp = api.patch(business_entity['self'],base_path='',json=business_entity)
        log.info(f"Business entities update response: {resp}")

    # submit payloads
    if applications_payload:
        resp = api.patch('assets/applications/assets',json=[applications_payload])
        log.debug(f"Applications assigned: {resp}")
    if applications_delete_payload:
        resp = api.delete('assets/applications/assets',json=applications_delete_payload)
        log.debug(f"Applications unassigned: {resp}")
    if annotations_payload:
        for id in annotations_payload:
            resp = api.put(f'assets/annotations/{id}/values',json=annotations_payload[id])
            log.debug(f"Annotations assigned: {resp}")
    if annotations_delete_payload:
        for id in annotations_delete_payload:
            resp = api.delete(f'assets/annotations/{id}/values',json=annotations_payload[id])
            log.debug(f"Annotations unassigned: {resp}")

    log.info(f"Summary : Applications created: {stats['apps_created']}, Applications assigned: {stats['apps_assigned']}, Applications unassigned: {stats['apps_unassigned']}, Annotations created: {stats['annots_created']}, Annotations assigned: {stats['annots_assigned']}, Annotations unassigned: {stats['annots_unassigned']}, Business Entities added: {stats['be_added']}, Business Entities assigned: {stats['be_assigned']}, Business Entities unassigned: {stats['be_unassigned']}")

    print('All done. Have a nice day!')
    exit(0)

if __name__ == '__main__':
    with ciSession(token = token, base_url = args.url) as api:
        main()
