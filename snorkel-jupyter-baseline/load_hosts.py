import os
from utils import ABSTAIN, BENIGN, MALICIOUS, ADULT
from snorkel.labeling import labeling_function

# dir = r'hosts_data/'
categories = {
         MALICIOUS: set([
            'add.Risk',
            'add.Spam',
            'hostsVN',
            'minecraft-hosts',
            'mvps.org',
            'shady-hosts',
            'someonewhocares.org',
            'tiuxo',
            'yoyo.org',
            'adaway.org',
            'add.2o7Net',
            'add.Dead',
            'Badd-Boyz-Hosts',
            'KADhosts',
            'MetaMask',
            'StevenBlack',
            'UncheckyAds',
            'URLHaus'
         ]),
         ADULT: set([
            'someonewhocares.org',
            'StevenBlack'
         ])
}  


def list_files(dir):
    # r = []
    dict_hosts = {}
    print(dir)
    for root, dirs, files in os.walk(dir):
        for name in files:
            if name == 'hosts':
                subdir = str(root).split('/')[-1]
                path = os.path.join(root, name)
                # r.append(path)
                for k, v in parse_hosts(path, subdir).items():
                    if k not in dict_hosts:
                        dict_hosts[k] = []
                    dict_hosts[k] += v
    return dict_hosts


def parse_hosts(hosts_file_path, subdir):
    dict_hosts = {}
    with open(hosts_file_path, 'r') as hosts:
          for line in hosts:
                if line.startswith('0.0.0.0 '):
                      host = line.strip()
                      host = host.split(' ')[1]
                      if host not in dict_hosts:
                        dict_hosts[host] = []
                      dict_hosts[host] += [subdir]
    return dict_hosts

hosts_file_paths = list_files(os.path.dirname(os.path.realpath(__file__)) + '/hosts_data/')

@labeling_function()
def lf_outgoing_host_is_malicious(doc):
    for outgoing_link in doc['outgoing_links']:
        if is_malicious_host(outgoing_link):
            return MALICIOUS
    return ABSTAIN

@labeling_function()
def lf_host_is_malicious(doc):
    return MALICIOUS if is_malicious_host(doc['url']) else ABSTAIN

@labeling_function()
def lf_outgoing_host_is_adult(doc):
    for outgoing_link in doc['outgoing_links']:
        if is_adult_host(outgoing_link):
            return ADULT
    return ABSTAIN

@labeling_function()
def lf_host_is_adult(doc):
    return ADULT if is_adult_host(doc['url']) else ABSTAIN

def is_adult_host(url):
    from urllib.parse import urlparse
    host = urlparse(url).netloc
    if host not in hosts_file_paths:
        return False
    
    for directory in hosts_file_paths[host]:
        if directory in categories[ADULT]:
            return True
    return False

def is_malicious_host(url):
    from urllib.parse import urlparse
    host = urlparse(url).netloc
    if host not in hosts_file_paths:
        return False
    
    for directory in hosts_file_paths[host]:
        if directory in categories[MALICIOUS]:
            return True
    return False
