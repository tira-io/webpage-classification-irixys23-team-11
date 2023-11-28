
from snorkel.labeling import labeling_function
from utils import ABSTAIN, BENIGN, MALICIOUS, ADULT

@labeling_function()
def lf_educational_content(x):
    edu_keywords = ['academic', 'research', 'conference', 'student','school','education', 'university']
    url = x['url']
    if any(keyword in url for keyword in edu_keywords):
        return BENIGN
    return ABSTAIN

@labeling_function()
def lf_sexual_innuendos(x):
    innuendos = ['booty', 'babe', 'milf', 'daddy','chick']
    url = x['url']
    if any(innuendo in url for innuendo in innuendos):
        return ADULT
    return ABSTAIN

@labeling_function()
def lf_malicious_keywords(x):
    malicious_keywords = ['hack', 'phish', 'malware', 'spyware']
    url = x['url']
    if any(keyword in url for keyword in malicious_keywords):
        return MALICIOUS
    return ABSTAIN
