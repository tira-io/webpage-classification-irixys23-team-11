
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
def lf_malicious_keywords(x):
    malicious_keywords = ['hack', 'phish', 'malware', 'spyware']
    url = x['url']
    if any(keyword in url for keyword in malicious_keywords):
        return MALICIOUS
    return ABSTAIN
    

@labeling_function()
def lf_explicit_adult_keywords(row):
    explicit_keywords = ['nude', 'hot', 'erotic', 'escort', 'camgirl']
    url = row['url']
    if any(keyword in url for keyword in explicit_keywords):
        return ADULT
    return ABSTAIN


@labeling_function()
def lf_age_restriction(row):
    age_keywords = ['18+', 'adults-only', 'mature']
    url = row['url']
    if any(keyword in url for keyword in age_keywords):
        return ADULT
    return ABSTAIN


@labeling_function()
def lf_adult_industry_domains(row):
    adult_domains = ['.xxx', '.adult', '.sex']
    url = row['url'].split('?')[0].split('#')[0].split('/')[0]
    if any(url.endswith(domain) for domain in adult_domains):
        return ADULT
    return ABSTAIN


@labeling_function()
def lf_adult_url_structure(row):
    url = row['url']
    if '/adult/' in url or '/sex/' in url:
        return ADULT
    return ABSTAIN


@labeling_function()
def lf_euphemisms_for_adult(row):
    euphemisms = ['nsfw', 'afterdark', 'kinky']
    url = row['url']
    if any(euphemism in url for euphemism in euphemisms):
        return ADULT
    return ABSTAIN


@labeling_function()
def lf_common_adult_content_keywords(row):
    keywords = ['porn', 'fetish', 'bdsm', 'swinger']
    url = row['url']
    if any(keyword in url for keyword in keywords):
        return ADULT
    return ABSTAIN


@labeling_function()
def lf_sexual_innuendos(row):
    innuendos = ['booty', 'babe', 'milf', 'daddy']
    url = row['url']
    if any(innuendo in url for innuendo in innuendos):
        return ADULT
    return ABSTAIN


@labeling_function()
def lf_adult_product_references(row):
    products = ['dildo', 'vibrator', 'lingerie', 'condom']
    url = row['url']
    if any(product in url for product in products):
        return ADULT
    return ABSTAIN


@labeling_function()
def lf_explicit_usernames(row):
    usernames = ['sexy', 'slutty', 'horny', 'naughty']
    url = row['url']
    if any(username in url for username in usernames):
        return ADULT
    return ABSTAIN


@labeling_function()
def lf_common_benign_domains(row):
    common_domains = ['google.com', 'wikipedia.org', 'youtube.com']
    url = row['url'].split('/')[0]
    if any(domain in url for domain in common_domains):
        return BENIGN
    return ABSTAIN


@labeling_function()
def lf_adult_keywords(row):
    adult_keywords = ['adult', 'sex', 'xxx', 'porn']
    url = row['url']
    if any(keyword in url for keyword in adult_keywords):
        return ADULT
    return ABSTAIN
