from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.pipeline import Pipeline


class SkLearnClassifier():
    def __init__(field):
        self.__field = field
        try:
            self.pipeline = joblib.load(f'sklearn-{self.__field}.pkl')
        except:
            self.pipeline = None

    def predict(self, data_point):
        return pipeline.predict(process([data_point])[0])

    def train(self, train_inputs, train_truths):
        if self.pipeline is not None:
            raise ValueError('Already trained...')
        train_inputs, train_truths = self.process(train_inputs, train_truths)
        pipeline = self.new_pipeline()
        pipeline.fit(train_inputs, train_truths)
        joblib.dump(pipeline, f'sklearn-{self.__field}.pkl')

    def process(self, inputs, truths=None):
        inputs = {i['uuid']: i[self.__field] for i in inputs.iterrows()}
        truths = None if not truths else {i['uuid']: i['label'] for i in truths.iterrows()}
	ret_inputs, ret_truths = [], []

        for uuid in inputs.keys():
            ret_inputs += [inputs[uuid]]
            if truths:
                ret_truths += [truths[uuid]]

        return (ret_inputs, ret_truths) if truths else ret_inputs

    def new_pipeline(self):
        return Pipeline([('tfidf', TfidfVectorizer()), ('clf', SGDClassifier())])

