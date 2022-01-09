#!/usr/bin/python3

try:
    import config
    import datetime
    import json
    import re
    import requests
    import time
    import yaml
    from billing_api.billingauth import billing_user, billing_token
    from concurrent.futures import ThreadPoolExecutor
    from netaddr import IPNetwork
except (ModuleNotFoundError, ImportError) as module:
    quit(f'The following module needs to be installed:\n {module}\n Use "pip install $MODULE" then try again.\n')

"""Global Variables"""
Assignments = {}
exclude_list = []


def debug(name, data):
    """Future implementation."""
    file = open('./debug/' + name + '.txt', 'w')
    file.write(str(data))
    file.close()
    return print(f'Debug wrote to {file.name}')


class GatherData:
    """All functions that pull data from the API."""
    def __init__(self):
        self.user = billing_user
        self.token = billing_token
        self.days = datetime.date.today() - datetime.timedelta(days=7)
        self.api = 'https://api.example.com/'

    def get_data(self, param, url, page_size=None):
        """Grab data from billing"""

        def api(params):
            """API call"""
            req = requests.post(url, auth=(self.user, self.token), data=json.dumps({'params': params}))
            return req.json()

        def loop(par):
            """When API call returns multiple pages."""
            if page_size:
                par['page_num'] = 1
                par['page_size'] = page_size

            r = api(par)

            try:
                page_total = r['page_total']
                r = r['items']
                if page_total == 1:
                    return r
                else:
                    pages = list(range(2, page_total + 1))
                    for page in pages:
                        par['page_num'] += 1
                        inner_r = api(par)['items']
                        r.extend(inner_r)
            except KeyError:
                return r

            return r

        data = loop(param)
        # print(json.dumps(data, sort_keys=True, indent=4))
        return data

    def get_details(self, keys, api2):
        """Multi-Threading get_data w/ UUID"""
        url = self.api + api2

        def go(k):
            param = {'uniq_id': Assignments[k]['uniq_id']}
            return self.get_data(param, url), k

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = executor.map(go, keys)
            for fut, key in futures:
                if 'ipDetails' in url:
                    parse_ip_details(fut, key)
                else:
                    parse_data(fut, key)

    def get_excluded_accounts(self, traits):
        """Get Employee, internal, & Test accounts."""
        """Future: May look into combining into get_details"""
        accounts_list = []
        url = self.api + 'Account/list'

        def go(t):
            param = {
                'account_status': ['active', 'pending-modify', 'pending-new'],
                'order_by': {
                    'field': 'accnt'
                },
                'trait': t,
            }
            return self.get_data(param, url, 1000)

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = executor.map(go, traits)
            for fut in futures:
                for f in fut:
                    accounts_list.append(f['accnt'])

        return accounts_list

    def get_initial_assignments(self):
        """Get billing logs of network assignments."""
        url = self.api + 'Logging/info'
        param = {
            'search': [
                {'data': str(self.days),
                 'field': 'date',
                 'method': 'greater'
                 },
                {'data': 'network_assignment',
                 'field': 'type',
                 'method': 'contains'
                 }
            ],
        }
        return self.get_data(param, url, 5000)

    def get_ip_list(self, uid):
        """Generate list of IP addresses netblocked to server."""
        url = self.api + 'Network/Assignment'
        param = {'uniq_id': uid}
        ip_info = self.get_data(param, url, 1000)
        list_ips = []
        count = 0
        for i in ip_info:
            i = count
            netrange = ip_info[i]['network']
            """Cheap way of skipping IPv6 IP addresses."""
            if ':' not in netrange:
                for ip in IPNetwork(str(netrange)):
                    list_ips.append(str(ip))
            count = i + 1
        return list_ips


def parse_data(data, index='none'):
    """Parse through data and send it to update_assignments()"""
    try:
        count = len(Assignments) + 1
        keys = config.nested_keys
        for i in data:
            for num in range(len(keys)):
                k = str(keys[num])
                d = i.get(k)
                if k and d is not None:
                    akey = 'Asgmt' + str(count).zfill(4)
                    update_assignments(akey, k, d)
            count += 1
    except (KeyError, AttributeError):
        keylist = ['activeStatus', 'domain', 'type', 'uniq_id']
        for key in keylist:
            update_assignments(index, key, data.get(key, 'ERROR'))


def parse_ip_details(data, key):
    """Parse IP billing per server."""

    def update(k, nest, value):
        """Update nested dictionaries inside Assignments{}"""
        try:
            Assignments[k][nest].update(value)
        except KeyError:
            Assignments[k].update({nest: value})

    try:
        nip = data['netblock_ips']
        ip_change = data['ip_change']
        ccost = data['current']['total_price']
        pcost = int(float(data['proposed']['total_price']))
        features = data['current']['features']
    except KeyError:
        if data['error']:
            nip = ip_change = ccost = pcost = features = 'ERROR'
        else:
            quit(f'Something went wrong with {parse_ip_details.__name__} data:\n{debug(parse_ip_details.__name__, data)}')
    finally:
        update(key, 'ipdetails', {'netblock_ips': nip})
        update(key, 'ipdetails', {'ip_change': ip_change})
        update(key, 'ipdetails', {'current_cost': ccost})
        update(key, 'ipdetails', {'proposed_cost': pcost})
        update(key, 'ipdetails', {'features': features})


def parse_feature_data(features):
    """
    IP Address billing features.
    ===
    LegacyIP = "Number of Additional Public IPs (Legacy Pricing)"
    ExtraIp = "(TBD units) Additional Public IPs"
    PublicIPAddresses = "Public IP Addresses"
    """
    tempdict = {}
    legacyip = 'Number of Additional Public IPs (Legacy Pricing)'
    extraip = '(TBD units) Additional Public IPs'
    publicipaddresses = 'Public IP Addresses'

    for i in features:
        tempdict.update({i['feature']: i['count']})
    if len(tempdict) == 2:
        if 'PublicIPAddresses' and 'LegacyIP' in tempdict:
            return publicipaddresses, tempdict['PublicIPAddresses'], legacyip, tempdict['LegacyIP']
        elif 'ExtraIp' and 'LegacyIP' in tempdict:
            return extraip, tempdict['ExtraIp'], legacyip, tempdict['LegacyIP']
        else:
            return 'ERROR', 'ERROR', 'ERROR', 'ERROR'
    elif len(tempdict) == 1:
        if 'PublicIPAddresses' in tempdict:
            return publicipaddresses, tempdict['PublicIPAddresses'], None, None
        elif 'ExtraIp' in tempdict:
            return extraip, tempdict['ExtraIp'], None, None
        elif 'LegacyIP' in tempdict:
            return legacyip, tempdict['LegacyIP'], None, None
        else:
            return 'ERROR', 'ERROR', 'ERROR', 'ERROR'
    else:
        return 'ERROR', 'ERROR', 'ERROR', 'ERROR'


def del_cleanup_assignments(key, data='none'):
    """Remove Assignments not relevant to the end goal."""
    bad_key = []
    for k, v in Assignments.items():
        try:
            if v[key] in data or v[key] == 'ERROR':
                bad_key.append(k)
        except KeyError:
            quit(f'Invalid key {key}')

    for remove in bad_key:
        Assignments.pop(remove)

    return len(bad_key)


def del_duplicate_assignments(key):
    """Delete Assignments extra assignments with the same UUID."""
    good_key = []
    bad_key = []
    for k, v in Assignments.items():
        try:
            if v[key] in good_key:
                bad_key.append(k)
            else:
                good_key.append(v[key])
        except KeyError:
            bad_key.append(k)

    for remove in bad_key:
        Assignments.pop(remove)

    return len(bad_key)


def del_final_assignments():
    """Determine if the Assignments left need a billing adjustment."""
    gather = GatherData()
    key_remove = []
    key_error = []

    for (k, v) in Assignments.items():
        a = v['ipdetails']['ip_change']
        b = v['ipdetails']['netblock_ips']
        c = v['ipdetails']['proposed_cost']
        u = v['uniq_id']
        '''There is a bug with ipdetails API that will pull ExtraIP w/ quantity of 1 when in the web front you 
        can confirm it is set to a quantity of 0. The below line removes changes of such.'''
        if ('ExtraIp' in str(v) and a == -1 and b == 1 and c == 0) or a == 0:
            key_remove.append(k)
        elif b == 'ERROR' and len(gather.get_ip_list(u)) <= 1:
            key_remove.append(k)
        elif a == 'ERROR':
            key_error.append(k)
        elif c < 0 and 'legacyip' not in str(v):
            key_remove.append(k)

    for remove in key_remove:
        Assignments.pop(remove)

    return len(key_remove), len(key_error)


def update_assignments(key, nested_key='none', value='none'):
    """Update Assignments{} with parsed data provided by other functions."""
    try:
        Assignments[key].update({nested_key: value})
        if nested_key == 'message':
            m = re.findall(r'[A-Z0-9]{6}\]', value)
            Assignments[key].update({'uniq_id': str(m).strip('\'[]')})
        if nested_key == 'type' and 'network_assignment' in value:
            Assignments[key].update({'assignment_type': value})
    except KeyError:
        Assignments.update({key: {nested_key: value}})
        if nested_key == 'message':
            m = re.findall(r'[A-Z0-9]{6}\]', value)
            Assignments.update({key: {'uniq_id': str(m).strip('\'[]')}})
        if nested_key == 'type' and 'network_assignment' in value:
            Assignments.update({key: {'assignment_type': value}})


def do_report():
    """Generate final report and write to file."""
    gather = GatherData()

    message = f'Subject: Subaccounts IP Billing assistance\n\n\n' \
              f'Hello Billing Team,\n\n We could use some assistance with adjusting subaccount IP billing.  ' \
              f'Currently, there is a bug in Netblock where some of the time billing does not get adjusted ' \
              f'appropriately. We try to catch these as we fulfill IP Requests, but we are not always successful.' \
              f'\n\n * https://example.com/internal/ticket/number123\n\n'

    for (outer_k, outer_v) in Assignments.items():
        accvar = str(outer_v['accnt'])
        datevar = str(re.findall(r'\d{4}-\d{2}-\d{2}', outer_v['date'])).strip('\'[]')
        hostvar = str(outer_v['domain'])
        typevar = str(outer_v['type'])
        uidvar = str(outer_v['uniq_id'])
        uservar = str(outer_v['remote_user'])
        if outer_v['ipdetails']['ip_change'] == 'ERROR':
            feature1 = feature2 = ipchange = padjust = 'MANUALLY_CHECK'
            feature3 = feature4 = None
            netblockvar = len(gather.get_ip_list(uidvar))
        else:
            feature1, feature2, feature3, feature4 = parse_feature_data(outer_v['ipdetails']['features'])
            netblockvar = str(outer_v['ipdetails']['netblock_ips'])
            ipchange = outer_v['ipdetails']['ip_change']
            padjust = str(int(feature2) + ipchange)
        message += f'\nAccount: {accvar}' \
                   f'\nHost: {hostvar} - {uidvar} - {typevar}' \
                   f'\nNetblock adjustment made on "{datevar}" by admin "{uservar}' \
                   f'\nhttps://example.com/address/to/subaccnt/product_page.html' \
                   f'?accnt={accvar}&uniq_id={uidvar}'
        '''If Public IPs greater than 15 switch over to (TBD units Additional Public IPs'''
        if feature1 == 'Public IP Addresses' and int(padjust) > 15:
            message += f'\nHost has {netblockvar} IPs netblocked.  Please change from "{feature1}" to "(TBD units)' \
                       f' Additional Public IPs" and set quantity to "{int(padjust) - 1}".'
        else:
            message += f'\nHost has {netblockvar} IPs netblocked.  Please adjust "{feature1}" quantity from' \
                       f' "{feature2}" to "{padjust}".'
        if feature3 and feature4 is not None:
            message += f'\n\tPlease leave "{feature3}" quantity at "{feature4}".'
    message += f'\n\n\nThank you in advance for your assistance. As mentioned before if there is anything we can do' \
               f' to make the above easier please let us know.' \
               f'\n\n=====\n\n{json.dumps(Assignments, sort_keys=True, indent=4)}'

    file1 = open('netaudit.txt', 'w')
    file1.write(message)
    file1.close()

    return print(f'The report has been wrote to {file1.name}\n')


def main():
    start = time.perf_counter()
    gather = GatherData()

    '''STEP 1'''
    print(f'One moment while I gather data...\n')
    parse_data(gather.get_initial_assignments())
    print(f'Step 1\n- {str(len(Assignments))} initial assignments found.')
    num_ex_traits = del_cleanup_assignments('accnt', gather.get_excluded_accounts(config.excluded_traits))
    print(f'- {num_ex_traits} internal account assignments removed.')
    num_ex_users = del_cleanup_assignments('remote_user', config.excluded_users)
    print(f'- {num_ex_users} provisioned assignments removed.\n- {str(len(Assignments))} assignments remain.\n')

    '''STEP 2'''
    print(f'Step 2 \n- Gathered select information \n - Hostnames\n - Product Types\n - Unique IDs\n- Removed '
          f'selected Assignments.\n - {str(del_duplicate_assignments("uniq_id"))} duplicate Unique IDs.')
    gather.get_details(Assignments.keys(), 'Subaccnt/details')
    print(f' - {str(del_cleanup_assignments("uniq_id"))} terminated Unique IDs.\n'
          f' - {str(del_cleanup_assignments("type", config.excluded_devices))} incompatible product types.\n'
          f' - {str(del_cleanup_assignments("activeStatus", "Pending-Termination"))} host(s) pending termination.\n'
          f' - {str(len(Assignments))} assignments remain.\n ')

    '''STEP 3'''
    gather.get_details(Assignments.keys(), 'Subaccnt/Network/details')
    var1, var2 = del_final_assignments()
    print(f'Step 3 Complete \n- IP billing info gathered.\n- IP billing cleanup:'
          f'\n - {str(var1)} hosts removed w/ no adjustments needed.'
          f'\n - {str(var2)} hosts to manually check.'
          f'\n - {str(len(Assignments) - var2)} host(s) needing billing adjustments.\n')

    '''STEP4'''
    do_report()

    finish = time.perf_counter()
    print(f'Script finished in {round(finish - start, 2)} second(s)')


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        quit('')
