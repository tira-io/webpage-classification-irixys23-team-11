
import argparse
import pandas as pd
from utils import load_data, MALICIOUS, LABEL_MAPPING

from url_labeling_functions import lf_educational_content, lf_sexual_innuendos,lf_malicious_keywords, \
    lf_adult_keywords, lf_malicious_keywords, lf_common_benign_domains, lf_explicit_usernames, lf_adult_product_references, \
    lf_common_adult_content_keywords, lf_euphemisms_for_adult, lf_adult_url_structure, lf_adult_industry_domains, lf_age_restriction, \
    lf_explicit_adult_keywords   
from plain_text_labeling_functions import lf_sk_plain_text,  lf_sk_url
from load_hosts import lf_outgoing_host_is_malicious, lf_host_is_malicious, lf_outgoing_host_is_adult, lf_host_is_adult
from snorkel.labeling import PandasLFApplier
from snorkel.labeling.model import MajorityLabelVoter
from keyword_labeling_functions import lf_url_has_adult_content


def parse_args():
    parser = argparse.ArgumentParser(description='Classify a webpage.')
    parser.add_argument("-i", "--input", help="Path to the input file in jsonl.", required=True)
    parser.add_argument("-o", "--output", help="Path to the output directory.", required=True)
    parser.add_argument("-l", "--label-functions", help="Label functions to use.", required=True)
    return parser.parse_args()

def get_label_functions(variant):
    if variant == 'all':
        return PandasLFApplier(lfs=[lf_educational_content, lf_sexual_innuendos, lf_malicious_keywords, lf_url_has_adult_content,
                                    lf_adult_keywords,  lf_common_benign_domains, lf_explicit_usernames, lf_adult_product_references,
                                    lf_common_adult_content_keywords, lf_euphemisms_for_adult, lf_adult_url_structure, lf_adult_industry_domains,
                                    lf_age_restriction, lf_explicit_adult_keywords, lf_outgoing_host_is_malicious, lf_host_is_malicious,
                                    lf_outgoing_host_is_adult, lf_host_is_adult, lf_sk_plain_text,  lf_sk_url])
    if variant == 'top-10':
    	return return PandasLFApplier(lfs=[lf_sexual_innuendos,  lf_url_has_adult_content, lf_adult_keywords,    
                                           lf_common_adult_content_keywords, lf_explicit_adult_keywords,
                                           lf_outgoing_host_is_malicious, lf_host_is_malicious, lf_outgoing_host_is_adult, 
                                           lf_sk_plain_text,  lf_sk_url])
    if variant == 'top-5':
    	return return PandasLFApplier(lfs=[lf_url_has_adult_content, lf_outgoing_host_is_malicious, lf_host_is_malicious, 
                                           lf_sk_plain_text,  lf_sk_url])

    raise ValueError('Unknown variant ' + variant)

if __name__ == '__main__':
    args = parse_args()
    ret = []

    lf_applier = get_label_functions(args.label_functions)

    input_data = load_data(args.input, ['url_tokenized', 'url_params', 'url_fragment', 'outgoing_links', 'plain_text'])
    input_data_with_lf = lf_applier.apply(df=input_data)
    
    majority_model = MajorityLabelVoter(cardinality=3, verbose=True)
    predictions = majority_model.predict(L=input_data_with_lf)

    ret = []
    label_mapping = {v:k for k,v in LABEL_MAPPING.items()}
    label_mapping[-1] = 'Malicious'
    for i in range(len(input_data)):
        uid = input_data.loc[i]['uid']
        label = label_mapping[predictions[i]]
        ret += [{'uid': uid, 'prediction': label}]

    pd.DataFrame(ret).to_json(args.output, orient='records', lines=True)
