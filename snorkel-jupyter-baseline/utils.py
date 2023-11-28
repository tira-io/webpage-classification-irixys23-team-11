from resiliparse.extract.html2text import extract_plain_text
import json
from tqdm import tqdm
import pandas as pd

ABSTAIN = -1
BENIGN = 0
MALICIOUS = 1
ADULT = 2

def load_data(file_path):
  data = []
  with open(file_path, 'r') as file:
      for line in tqdm(file):
          json_data = json.loads(line)
          if 'html' in json_data:
            json_data['plain_text'] = extract_plain_text(json_data['html'])
          data.append(json_data)
  df = pd.DataFrame(data)
  return df