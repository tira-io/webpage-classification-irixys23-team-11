from snorkel.labeling import labeling_function
from utils import ABSTAIN, BENIGN, MALICIOUS, ADULT

@labeling_function()
def lf_plain_text_adult_content(x):
    adult_keywords = ['sex', 'porn', 'hot','erotic']
    html = x['plain_text']
    if any(keyword in html for keyword in adult_keywords):
        return ADULT
    return ABSTAIN