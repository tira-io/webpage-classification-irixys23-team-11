from snorkel.labeling import labeling_function
from utils import ABSTAIN, BENIGN, MALICIOUS, ADULT, LABEL_MAPPING

@labeling_function()
def lf_plain_text_adult_content(x):
    adult_keywords = ['sex', 'porn', 'hot','erotic']
    html = x['plain_text']
    if any(keyword in html for keyword in adult_keywords):
        return ADULT
    return ABSTAIN

from sklearn_utils import SkLearnClassifier
sk_plain_text = SkLearnClassifier('plain_text')

sk_url = SkLearnClassifier('url_tokenized')

@labeling_function()
def lf_sk_plain_text(x):
    return LABEL_MAPPING[sk_plain_text.predict(x)[0]]


@labeling_function()
def lf_sk_url(x):
    return LABEL_MAPPING[sk_url.predict(x)[0]]