#!/usr/bin/env python3
import pathlib, concurrent.futures, requests, threading, json, re, argparse, math, pandas as pd
from datetime import datetime as dt, timedelta as td, timezone as tz
from collections import abc

# global VARS
LIMIT = 1000 # adjust this to tune number of results per query
MAX_THREADS = 50 # adjust this to tune max number of threads to spin up

# argument parsing
parser = argparse.ArgumentParser(
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description = '* Export saved queries from NetApp CloudInsights into Excel file')
myprog = parser.prog.rstrip('.py')
parser.add_argument('token_file', type=pathlib.Path, help='Token file containing the actual token for the CI Tenant')
parser.add_argument('url', action='store', help='URL to CI Tenant: https://<xyz1234>.<region>.cloudinsights.netapp.com')
parser.add_argument('-a','--rollup-aggregation', action='store', required=False, choices=['min', 'max', 'avg', 'sum'],\
                    type=lambda txt: txt.lower(), default='avg', help='Rollup aggregation for metrics')
parser.add_argument('-tr','--time-range', action='store', required=False, choices=['FIFTEEN_MINUTES', 'THIRTY_MINUTES', 'ONE_HOUR', 'TWO_HOURS', 'THREE_HOURS', 'SIX_HOURS', 'TWELVE_HOURS', 'ONE_DAY', 'TWO_DAYS', 'THREE_DAYS', 'ONE_WEEK', 'THIRTY_DAYS'],\
                    type=lambda txt: txt.upper(), default='ONE_DAY', help='Time range for queries')
parser.add_argument('-ft','--from-to', nargs=2, action='store', required=False, type=lambda txt: [dt.strptime(d,'%Y-%m-%d_%H:%M:%S') for d in txt.split()][0], help='From-To datetimes for custom time range (overrides --time-range): YYYY-mm-dd_HH:MM:SS YYYY-mm-dd_HH:MM:SS')
args = parser.parse_args()
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

class ciSession(requests.Session):
    def __init__(self, token, base_url = None, verify=True, DisableInsecureRequestWarning = False, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if DisableInsecureRequestWarning: requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        self.headers['X-CloudInsights-ApiKey'] = token
        self.verify = verify
        self.base_url = base_url
        self.sysinfo = requests.get(requests.sessions.urljoin(base_url,'rest/v1/systemInfo')).json()
    def request(self, method, url, base_path='/rest/v1', *args, **kwargs):
        url = requests.sessions.urljoin(self.base_url, f'{base_path.strip("/")}/{url.strip("/")}')
        r = super().request(method, url, *args, **kwargs)
        # uncommend below to print request url for troubleshooting
        # print(method, requests.utils.unquote(r.request.url))
        return r

thread_local = threading.local()
def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = ciSession(token = token, base_url = args.url)
    return thread_local.session

def fetch_results(url,_params):
    session = get_session()
    with session.get(url,base_path='',params=_params) as resp:
        if resp.ok: return resp.json()
        else: print(resp,resp.request.url,resp.text); exit(code=resp.status_code)

def parse_result(result,fields,obj_type):
    row = {}
    for field in fields:
        parts = field.split('.')
        hold = result
        for lev, part in enumerate(parts,1):
            if lev < len(parts):
                if isinstance(hold, dict):
                    if part in hold.keys():
                        hold = hold[part]
                    else:
                        row[field] = None
                        break
            else:
                if isinstance(hold, dict):
                    if part in hold.keys():
                        if isinstance(hold[part], dict) and 'unitType' in hold[part] and args.rollup_aggregation in hold[part]:
                            row['{} ({})'.format(re.sub(r'performance\.','',field),hold[part]['unitType'])] = hold[part][args.rollup_aggregation]
                        elif isinstance(hold[part], dict) and 'unitType' in hold[part] and 'value' in hold[part]:
                            row['{} ({})'.format(re.sub(r'performance\.','',field),hold[part]['unitType'])] = hold[part]['value']
                        elif isinstance(hold[part], dict) and 'value' in hold[part]:
                            row[field] = hold[part]['value']
                        else:
                            if parts[0] == 'annotationValues': row['[{}]'.format(re.sub(r'annotationValues\.','',field))] = hold[part]
                            else:
                                if obj_type == 'Disk' and part == 'speed': row['{} (RPM)'.format(field)] = None
                                else: row[field] = hold[part]
                    else:
                        if parts[0] == 'annotationValues': row['[{}]'.format(re.sub(r'annotationValues\.','',field))] = None
                        else: row[field] = None
                elif isinstance(hold, list):
                    items = []
                    for item in hold:
                        if isinstance(item, dict):
                            if parts[lev-2] in item.keys(): items.append(item[parts[lev-2]][part])
                            else: items.append(item[part])
                        else: items.append(item)
                    row[field] = ', '.join(items)
    return row

def main():
    queries = None
    pick_valid = False
    resp = api.get('/queries')
    if resp.ok: queries = resp.json()
    else: print(resp, resp.json()); exit(code=resp.status_code)
    if queries:
        for page in range(math.ceil(len(queries)/50)):
            if pick_valid: break
            print()
            width = math.floor(max([len(q['name']) for q in queries[page*50:page*50+50]])/2)
            print('{:>4}  {:<{}}  {:<20}'.format('NUM','Query Name', width*2+3, 'Object Type'))
            print('=' * width,'Page', page+1, 'of', math.ceil(len(queries)/50), '=' * (width+max([len(q['objectType']) for q in queries[page*50:page*50+50]])-3))
            for num,q in enumerate(queries[page*50:(page*50)+50],1):
                print('{:>4}  {:<{}}  {:<20}'.format((page*50)+num,q['name'], width*2+3, q['objectType']))
            print()
            while not pick_valid:
                if page < math.ceil(len(queries)/50)-1:
                    pick = input('Please enter NUM for query to export or "n|N" for next page: ')
                    if re.match(r'\d{1,3}$',pick) and page*50 < int(pick) <= page*50+50:
                        pick_valid = True
                    elif re.match(r'[nN]{1}$',pick):
                        break
                else:
                    pick = input('Please enter NUM for query to export: ')
                    if re.match(r'\d{1,3}$',pick) and page*50 < int(pick) <= len(queries):
                        pick_valid = True
    else:
        print('No saved queries found on tenant {}, tenantId: {}'.format(requests.utils.urlparse(api.base_url).netloc,api.sysinfo['tenantId']))
    qpick = queries[int(pick)-1]
    timer_start = dt.now()
    data = {}
    if from_time and to_time: params = {'fromTime':from_time,'toTime':to_time,'offset':0,'limit':LIMIT}
    else: params = {'timeRange':args.time_range,'offset':0,'limit':LIMIT}
    if re.match(r'^logs\.',qpick['objectType']):
        print(f"Queries for objectType {qpick['objectType']} not supported by the API at this time. Maybe someday soon...")
        exit()
    elif not qpick['objectCategory']:
        print('Exporting query {}: {}'.format(pick,qpick['name']))
        q = api.get(qpick['self']+'/result',base_path='',params=params)
        if q.ok: query = q.json()
        else: print(q, q.request.url, q.json()); exit(code=q.status_code)
        if query and query['count'] > 0:
            for res in query['results']:
                result = parse_result(res,qpick['fields'],qpick['objectType'])
                for k,v in result.items():
                    if k not in data.keys(): data[k] = []
                    data[k].append(v)
            num_queries = math.ceil(query['count']/query['limit'])
            if num_queries > 1: # spin up threads as needed for additional queries
                params_list = []
                for num in range(1,num_queries):
                    my_params = params.copy()
                    my_params['offset'] = num*LIMIT
                    params_list.append(my_params)
                with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_THREADS,num_queries-1)) as executor:
                    query_results = executor.map(fetch_results, [qpick['self']+'/result' for i in range(num_queries-1)], params_list)
                    for item in query_results:
                        for res in item['results']:
                            result = parse_result(res,qpick['fields'],qpick['objectType'])
                            for k,v in result.items():
                                if k not in data.keys(): data[k] = []
                                data[k].append(v)
        else: print('Query contains no results.'); exit(0)
    else:
        print('Exporting query {}: {}'.format(pick,qpick['name']))
        q = api.get('/lake/metadata/{}/{}'.format(qpick['objectCategory'],qpick['objectMeasurement']))
        if q.ok: meta = q.json()
        else: print(q, q.request.url, q.text); exit(code=q.status_code)
        metrics = []
        timeAggregations = []
        rollUpAggregations = []
        for metric in meta['metricSet']:
            if metric in qpick['fields']:
                metrics.append(meta['metricSet'][metric]['name'])
                timeAggregations.append(meta['metricSet'][metric]['timeAggregation'])
                rollUpAggregations.append(meta['metricSet'][metric]['rollUpAggregation']) if args.rollup_aggregation == 'avg' else args.rollup_aggregation.upper()
        tags = []
        for tag in meta['tagSet']:
            if (tag in qpick['fields'] or tag in qpick['groupBy']) and tag not in tags:
                tags.append(tag)
        params.update({'category':qpick['objectCategory'],'measurement':qpick['objectMeasurement']})
        if metrics: params['metrics'] = ','.join(metrics)
        if tags: params['tags'] = ','.join(tags)
        if qpick['sort'] and (re.sub(r'^-','',qpick['sort']) in metrics or re.sub(r'^-','',qpick['sort']) in tags or re.sub(r'^-','',qpick['sort']) in qpick['groupBy']):
            params['sort'] = re.sub(r'^-','',re.sub(r'^_all','All',qpick['sort']))
            params['isSortAsc'] = str(not re.match(r'^-',qpick['sort'])).lower()
        else:
            params['sort'] = re.sub(r'^_all','All',qpick['groupBy'][0])
        if qpick['filters']:
            filters = []
            for filter in qpick['filters']:
                if 'value' in filter.keys() and filter['value']:
                    if isinstance(filter['value'], dict):
                        if [k for k in filter['value'].keys()] == ['from','to']:
                            if [v for v in filter['value'].values() if v]:
                                filters.append(filter['field']+':['+'{} TO {}'.format(filter['value']['from'], filter['value']['to']).strip()+']')
                    elif isinstance(filter['value'], str):
                        filters.append('{}:{}'.format(filter['field'],re.sub(r' ','\\ ',filter['value'])))
                    elif isinstance(filter['value'], list):
                        filters.append('{}:{}'.format(filter['field'],','.join([re.sub(r' ','\\ ',v) for v in filter['value']])))
            if filters: params['filter'] = ' AND '.join(filters)
        params.update({'rollupAggregations': ','.join(rollUpAggregations),'timeAggregations':','.join(timeAggregations),'rollups':','.join([re.sub(r'^_all','All',v) for v in qpick['groupBy']])})
        if 'fromTime' in params.keys() and 'toTime' in params.keys():
            params['fromTimeMs'] = params.pop('fromTime')
            params['toTimeMs'] = params.pop('toTime')
        else:
            params['relativeTimeRange'] = params.pop('timeRange',args.time_range)
        if tags: params['tags'] = ','.join(tags)
        q = api.get('/lake/query/table',params=params)
        if q.ok: table = q.json()
        else: print(q, q.request.url, q.text); exit(code=q.status_code)
        if 'rows' in table.keys():
            for row in table['rows']:
                for rlup in row['rollups']:
                    if rlup not in data: data[rlup] = []
                    data[rlup].append(row['rollups'][rlup])
                for field in qpick['fields']:
                    if field in row['rollups']: continue
                    if field not in data: data[field] = []
                    _found = False
                    for _set in ['tagSet','metricSet']:
                        if _set in row and field in row[_set]:
                            data[field].append(row[_set][field])
                            _found = True
                            break
                    if not _found: data[field].append(None)
            if table['count'] > LIMIT:
                num_queries = math.ceil(table['count']/table['limit'])
                if num_queries > 1: # spin up threads as needed
                    params_list = [] # prepare list of adjusted parameters
                    for num in range(1,num_queries):
                        my_params = params.copy()
                        my_params['offset'] = num*table['limit']
                        params_list.append(my_params)
                    with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_THREADS,num_queries-1)) as executor:
                        table_results = executor.map(fetch_results, ['rest/v1/lake/query/table' for i in range(num_queries-1)],params_list)
                        for table in table_results:
                            if 'rows' in table.keys():
                                for row in table['rows']:
                                    for rlup in row['rollups']:
                                        if rlup not in data: data[rlup] = []
                                        data[rlup].append(row['rollups'][rlup])
                                    for field in qpick['fields']:
                                        if field in row['rollups']: continue
                                        if field not in data: data[field] = []
                                        _found = False
                                        for _set in ['tagSet','metricSet']:
                                            if _set in row and field in row[_set]:
                                                data[field].append(row[_set][field])
                                                _found = True
                                                break
                                        if not _found: data[field].append(None)
                            else:
                                print('Warning: Too many queries fired, result contains no data.')
        else: print('Query contains no results.'); exit(0)
    xlsx = 'CIQ-Export_{}_{}.xlsx'.format(qpick['name'].replace(' ','_'),dt.strftime(dt.now(),'%Y%m%d%H%M'))
    writer = pd.ExcelWriter(xlsx,engine='xlsxwriter')
    df = pd.DataFrame(data = data)
    print(df)
    df.to_excel(writer, index = False, sheet_name = qpick['name'][:31])
    workbook = writer.book
    worksheet = workbook.add_worksheet('Filtering and Grouping')
    worksheet.write(0, 0, 'ObjectType', workbook.add_format({'bold': True, 'border': True, 'bg_color': '#b0d7fa'}))
    worksheet.write(1, 0, qpick['objectType'], workbook.add_format({'bold': False, 'border': True, 'bg_color': '#F5F184'}))
    worksheet.write(0, 2, 'Filter', workbook.add_format({'bold': True, 'border': True, 'bg_color': '#b0d7fa'}))
    worksheet.write(1, 2, 'Value' , workbook.add_format({'bold': True, 'border': True, 'bg_color': '#b0d7fa'}))
    for n,filter in enumerate(qpick['filters'],3):
        worksheet.write(0, n, filter['field'], workbook.add_format({'bold': True, 'border': True, 'center_across': True, 'bg_color': '#b0d7fa'}))
        if isinstance(filter['displayValue'], list): worksheet.write(1, n, ' '.join(['['+v+']' for v in filter['displayValue']]), workbook.add_format({'bold': False, 'border': True, 'bg_color': '#F5F184'}))
        elif not filter['displayValue']:
            if 'value' in filter.keys() and filter['value']:
                if isinstance(filter['value'], list): worksheet.write(1, n, ' '.join(['['+v+']' for v in filter['value']]), workbook.add_format({'bold': False, 'border': True, 'bg_color': '#F5F184'}))
                elif isinstance(filter['value'], dict):
                    if [k for k in filter['value'].keys()] == ['from','to'] and [v for v in filter['value'].values() if v]:
                        worksheet.write(1, n, filter['field']+':['+'{} TO {}'.format(filter['value']['from'], filter['value']['to']).strip()+']', workbook.add_format({'bold': False, 'border': True, 'bg_color': '#F5F184'}))
                    else: worksheet.write(1, n, None, workbook.add_format({'bold': False, 'border': True, 'bg_color': '#F5F184'}))
                else: worksheet.write(1, n, filter['value'], workbook.add_format({'bold': False, 'border': True, 'bg_color': '#F5F184'}))
            else: worksheet.write(1, n, None, workbook.add_format({'bold': False, 'border': True, 'bg_color': '#F5F184'}))
        else: worksheet.write(1, n, filter['displayValue'], workbook.add_format({'bold': False, 'border': True, 'bg_color': '#F5F184'}))
    if qpick['objectCategory']:
        worksheet.write(3, 2, 'Group:', workbook.add_format({'bold': True, 'border': True, 'bg_color': '#b0d7fa'}))
        if isinstance(qpick['groupBy'], list): worksheet.write(3, 3, ' '.join(['['+v+']' for v in qpick['groupBy']]), workbook.add_format({'bold': False, 'border': True, 'bg_color': '#F5F184'}))
        else: worksheet.write(3, 3, qpick['groupBy'], workbook.add_format({'bold': False, 'border': True, 'bg_color': '#F5F184'}))
    writer.save()
    timer_end = dt.now()
    runtime = timer_end - timer_start
    print('Query exported to file {} in {} h:mm:ss.µs. Have a nice day!'.format(xlsx,runtime))
    exit(0)

if __name__ == '__main__':
    with ciSession(token = token, base_url = args.url) as api:
        main()
