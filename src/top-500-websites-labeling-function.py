from snorkel.labeling import labeling_function
from utils import ABSTAIN, BENIGN, MALICIOUS, ADULT

@labeling_function()
def lf_is_top_website(x):
    top_domains = get_top_500_domains()
    url = x['url']
    if any(domain in url for domain in top_domains):
        return BENIGN
    return ABSTAIN


def get_top_500_domains():
    import csv
    ret=[]         #an empty list to store the second column
    with open('snorkel-jupyter-baseline/top500Domains.csv', 'r') as rf:
        reader = csv.reader(rf, delimiter=',')
        for row in reader:
            ret.append(row[1])
    ret.remove('Root Domain')
    return ret

# print(get_top_500_domains())
# print(lf_is_top_website({
 #    'url': 'https://www.google.com/?search=dfdbf'
# }))