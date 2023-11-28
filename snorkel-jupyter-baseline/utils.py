from resiliparse.extract.html2text import extract_plain_text
import json
from tqdm import tqdm
import pandas as pd
import re

ABSTAIN = -1
BENIGN = 0
MALICIOUS = 1
ADULT = 2

def url_tokenizetion(identifier):
    identifier = re.sub(r'https?://|www.', '', identifier)
    identifier = re.split(r'[^a-zA-Z0-9]+', identifier)
    identifier = ' '.join([token for token in identifier if token])
    matches = re.finditer('.+?(?:(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|$)', identifier)
    ret = []
    for i in [m.group(0) for m in matches]:
        ret += i.split()
    return [i.lower() for i in ret]

assert ['123', 'com', 'hello', 'world'] == url_tokenizetion('123.com/helloWorld')

def url_params(url):
    if '?' not in url:
        return ''
    
    return url_tokenizetion(url.split('?')[1])

def url_fragment(url):
    if '#' not in url:
        return ''

    return url_tokenizetion(url.split('#')[1]) 

def load_data(file_path):
  data = []
  with open(file_path, 'r') as file:
      for line in tqdm(file):
          json_data = json.loads(line)
          if 'html' in json_data:
            json_data['plain_text'] = extract_plain_text(json_data['html'])
            json_data['main_content'] = extract_plain_text(json_data['html'], main_content=True)
            json_data['url_tokenized'] = ' '.join(url_tokenizetion(json_data['url']))
            json_data['url_params'] = ' '.join(url_params(json_data['url']))
            json_data['url_fragment'] = ' '.join(url_fragment(json_data['url']))
          data.append(json_data)
  df = pd.DataFrame(data)
  return df