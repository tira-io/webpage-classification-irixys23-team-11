from snorkel.labeling import labeling_function
from utils import ABSTAIN, BENIGN, MALICIOUS, ADULT
from content_filter import Filter

filter = Filter()
def is_adult_content(text, additional_terms=[], length=250):
    if filter.check(text[:length]).as_bool:
        return ADULT
    return ABSTAIN


@labeling_function()
def lf_main_content_has_adult_content(doc):
    return is_adult_content(doc['main_content'])

@labeling_function()
def lf_plain_text_has_adult_content(doc):
    return is_adult_content(doc['plain_text'])

@labeling_function()
def lf_html_has_adult_content(doc):
    return is_adult_content(doc['html'])


@labeling_function()
def lf_url_has_adult_content(doc):
    return is_adult_content(doc['url_tokenized'])

@labeling_function()
def lf_url_param_has_adult_content(doc):
    return is_adult_content(doc['url_params'])

@labeling_function()
def lf_url_fragment_has_adult_content(doc):
    return is_adult_content(doc['url_fragment'])

@labeling_function()
def lf_image_text_has_adult_content(doc):
    return is_adult_content(doc['image_text'])


@labeling_function()
def lf_video_text_has_adult_content(doc):
    return is_adult_content(doc['video_text'])
