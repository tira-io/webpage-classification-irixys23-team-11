import os
from utils import ABSTAIN, BENIGN, MALICIOUS, ADULT


# dir = r'hosts_data/'
categories = {
         MALICIOUS: [
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
         ],
         ADULT:[
            'someonewhocares.org',
            'StevenBlack'
         ]
}  



'''def list_files(dir):                                                                                                  
    r = []                                                                                                            
    subdirs = [x[0] for x in os.walk(dir)]                                                                            
    for subdir in subdirs:                                                                                            
        files = os.walk(subdir).next()[2]                                                                             
        if (len(files) > 0):                                                                                          
            for file in files:
                print(subdir, file)    
                if file == 'hosts':                                                                                    
                    r.append(os.path.join(subdir, file))                                                                         
    return r'''


def list_files(dir):
    # r = []
    dict_hosts = {}
    for root, dirs, files in os.walk(dir):
        for name in files:
            if name == 'hosts':
                subdir = str(root).split('/')[-1]
                path = os.path.join(root, name)
                # r.append(path)
                dict_hosts = dict_hosts | parse_hosts(path, subdir)
    return dict_hosts


def parse_hosts(hosts_file_path, subdir):
    dict_hosts = {}
    with open(hosts_file_path, 'r') as hosts:
          for line in hosts:
                if line.startswith('0.0.0.0 '):
                      host = line.strip()
                      host = host.split(' ')[1]
                      dict_hosts[host] = subdir
    return dict_hosts


dict = hosts_file_paths = list_files('snorkel-jupyter-baseline/hosts_data/')
print(dict)
#for hosts in hosts_file_paths:
 #   parse_hosts(hosts)
