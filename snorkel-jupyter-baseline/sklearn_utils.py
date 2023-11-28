#!/usr/bin/env python3
import argparse
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline
import os
import joblib
import pandas as pd
from utils import load_data


class SkLearnClassifier():
    def __init__(self, field):
        self.__field = field
        self.__pipeline_name = os.path.dirname(os.path.realpath(__file__)) + f'sklearn-{self.__field}.pkl'
        try:
            self.pipeline = joblib.load(self.__pipeline_name)
        except:
            self.pipeline = None

    def predict(self, data_point):
        return self.pipeline.predict(self.process(pd.DataFrame([data_point])))

    def train(self, train_inputs, train_truths):
        if self.pipeline is not None:
            raise ValueError('Already trained...')
        train_inputs, train_truths = self.process(train_inputs, train_truths)
        pipeline = self.new_pipeline()
        pipeline.fit(train_inputs, train_truths)
        joblib.dump(pipeline, self.__pipeline_name)

    def process(self, inputs, truths=None):
        inputs = {i['uid']: i[self.__field] for _, i in inputs.iterrows()}
        truths = None if truths is None else {i['uid']: i['label'] for _, i in truths.iterrows()}
        ret_inputs, ret_truths = [], []

        for uuid in inputs.keys():
            ret_inputs += [inputs[uuid]]
            if truths is not None:
                ret_truths += [truths[uuid]]

        return (ret_inputs, ret_truths) if truths is not None else ret_inputs

    def new_pipeline(self):
        return Pipeline([('tfidf', TfidfVectorizer()), ('clf', SGDClassifier())])


def parse_args():
    parser = argparse.ArgumentParser(description='Classify a webpage.')
    parser.add_argument("-i", "--input", help="Path to the input file in jsonl.", required=True)
    parser.add_argument("-o", "--output", help="Path to the output directory.", required=True)
    parser.add_argument("-f", "--field", help="Path to save the trained model.", required=True)
    return parser.parse_args()

if __name__ == '__main__':
    args = parse_args()
    classifier = SkLearnClassifier(args.field)
    ret = []

    for _, i in load_data(args.input, args.field).iterrows():
        ret += [{'uuid': i['uid'], 'prediction': classifier.predict(i.to_dict())[0]}]
    
    pd.DataFrame(ret).to_json(args.output, orient='records', lines=True)
