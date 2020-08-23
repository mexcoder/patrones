import urllib, sys, bs4
import urllib.request
from basicFeatures import FeatureExtractor
from FeatureEnum import Feature
from cachetools import cached, LRUCache 


class AlexaExtractor(FeatureExtractor):

    @staticmethod
    @cached(LRUCache(255))
    def fetchAlexaData(url):
        with urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url="+url) as s:
            body = s.read()

        return body

    @staticmethod
    def fetchAlexaRank(url):

        rank = None
        alexaData = AlexaExtractor.fetchAlexaData(url)

        if alexaData:

            reach = bs4.BeautifulSoup(alexaData,"xml").find("REACH")
            if reach:
                rank = int(reach['RANK'])
        
        return rank

class AlexaRankExtractor (AlexaExtractor):

    @staticmethod
    def getName():
        return "having_At_Symbol"

    @staticmethod
    def getFeature(target):

        rank = AlexaExtractor.fetchAlexaRank(target)
        return Feature.Pishing if rank is None else (
               Feature.Legitimate if rank < 100000 else 
               Feature.Suspicious)


if __name__ == "__main__":
        
    print(AlexaRankExtractor.getFeature("mexcoder.com"))
    print(AlexaRankExtractor.getFeature("facebook.com"))
    print(AlexaRankExtractor.getFeature("americanexpress.com"))
