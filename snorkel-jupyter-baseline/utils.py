from resiliparse.extract.html2text import extract_plain_text
import json
from tqdm import tqdm
import pandas as pd
import re

ABSTAIN = -1
BENIGN = 0
MALICIOUS = 1
ADULT = 2

def extract_all_tags(parsed_html, tag_name):
    ret = []

    for tag in [parsed_html.body, parsed_html.head]:
        if not tag:
            continue

        for matching_tag in tag.get_elements_by_tag_name(tag_name):
            ret += [matching_tag]
    
    return ret

def extract_all_text_of_tags(html_code, tag_name):
    ret = []
    for i in extract_all_tags(html_code, tag_name):
        ret += [i.text]
    return ' '.join(ret)

def url_tokenizetion(identifier):
    identifier = re.sub(r'https?://|www.', '', identifier)
    identifier = re.split(r'[^a-zA-Z0-9]+', identifier)
    identifier = ' '.join([token for token in identifier if token])
    matches = re.finditer('.+?(?:(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|$)', identifier)
    ret = []
    for i in [m.group(0) for m in matches]:
        ret += i.split()
    return [i.lower() for i in ret]

def media_elements_to_human_readable_text(html, media_type):
    ret = []
    for i in extract_all_tags(html, media_type):
        if 'src' in i.attrs:
            ret += [' '.join(url_tokenizetion(i.getattr('src')))]
        
        for k in ['alt', 'src', 'desc', 'description']:
            if k in i.attrs:
                ret += [i.getattr(k)]

    return ret

assert ['123', 'com', 'hello', 'world'] == url_tokenizetion('123.com/helloWorld')

def url_params(url):
    if '?' not in url:
        return ''
    
    return url_tokenizetion(url.split('?')[1])

def url_fragment(url):
    if '#' not in url:
        return ''

    return url_tokenizetion(url.split('#')[1]) 

def all_outgoing_links(parsed_html):
    ret = set()
    if not parsed_html or not parsed_html.body:
        return []

    for a in parsed_html.body.get_elements_by_tag_name('a'):
        if a and 'href' in a.attrs:
            ret.add(a.getattr('href'))
    
    return list(ret)

def load_data(file_path, fields):
  from resiliparse.parse.html import HTMLTree
  data = []
  with open(file_path, 'r') as file:
      for line in tqdm(file):
          json_data = json.loads(line)
          if 'html' in json_data:
            if 'plain_text' in fields:
                json_data['plain_text'] = extract_plain_text(json_data['html'])
            if 'main_content' in fields:
                json_data['main_content'] = extract_plain_text(json_data['html'], main_content=True)
            if 'url_tokenized' in fields:
                json_data['url_tokenized'] = ' '.join(url_tokenizetion(json_data['url']))
            if 'url_params' in fields:
                json_data['url_params'] = ' '.join(url_params(json_data['url']))
            if 'url_fragment' in fields:
                json_data['url_fragment'] = ' '.join(url_fragment(json_data['url']))
            
            if 'outgoing_links' in fields or 'image_text' in fields or 'video_text' in fields:
                parsed_html = HTMLTree.parse(json_data['html'])
                if 'outgoing_links' in fields:
                    json_data['outgoing_links'] = all_outgoing_links(parsed_html)
            
                if 'image_text' in fields:
                    json_data['image_text'] = ' '.join(media_elements_to_human_readable_text(parsed_html, 'img'))
                
                if 'video_text' in fields:
                    json_data['video_text'] = ' '.join(media_elements_to_human_readable_text(parsed_html, 'video'))
          data.append(json_data)
  df = pd.DataFrame(data)
  return df