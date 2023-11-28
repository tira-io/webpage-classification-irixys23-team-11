from snorkel.labeling import labeling_function
from utils import ABSTAIN, BENIGN, MALICIOUS, ADULT
from snorkel_preprocessors import textblob_sentiment

@labeling_function(pre=[textblob_sentiment])
def textblob_polarity(x):
    return BENIGN if x.polarity > 0.9 else ABSTAIN


@labeling_function(pre=[textblob_sentiment])
def textblob_subjectivity(x):
    return BENIGN if x.subjectivity >= 0.5 else ABSTAIN
