#this is my word preprocessor for nlp  
import re
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
class Preprocessor():

    def __init__(self):
        self.lemmatizer = WordNetLemmatizer()
        self.vectorizer = TfidfVectorizer(max_features=5000)
        self.labelEncoder = LabelEncoder()

    def cleanText(self,text):
        text = re.sub(r'<[^>]+>', '', text)
        text = re.sub(r'http\S+|www\S+|https\S+', '', text, flags=re.MULTILINE)
        text = re.sub(r'\@w+|\#', '', text)
        text = re.sub(r'[^a-zA-Z]', ' ', text)
        text = re.sub(r'\[image:.*?\]', '', text)
        text = re.sub(r'<img.*?>', '', text)
        text = text.lower()
        text = re.sub(r'\s+', ' ', text).strip()

        return text

    def tokenize(self, text):
        tokens = text.split()
        tokens = [self.lemmatizer.lemmatize(word) for word in tokens if not word in set(stopwords.words('english'))]
        return ' '.join(tokens)


if __name__ == '__main__':
    wordProcessor = Preprocessor()
    text = "https://hello my name is michael and I am a small"
    text = wordProcessor.cleanText(text)
    text = wordProcessor.tokenize(text)
    print(text)

