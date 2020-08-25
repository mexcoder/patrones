import whois
from cachetools import cached, LRUCache
from basicFeatures import FeatureExtractor
from FeatureEnum  import Feature
from datetime import timedelta, datetime

class WhoISExtractor(FeatureExtractor):

    @staticmethod
    @cached(LRUCache(255))
    def fetchWhois(url):
        return whois.whois(url)


class DomainRegistrationExtractor(WhoISExtractor):
    @staticmethod
    def getName():
        return "Domain_registeration_length"

    @staticmethod
    def getFeature(target):
        whois = WhoISExtractor.fetchWhois(target)

        if whois["expiration_date"] is None:
            return Feature.Pishing
        return Feature.Pishing if  whois["expiration_date"] - datetime.now() <= timedelta(days=365) else Feature.Legitimate

class DomainAgeExtractor(WhoISExtractor):
    @staticmethod
    def getName():
        return "age_of_domain"

    @staticmethod
    def getFeature(target):
        creationDate = WhoISExtractor.fetchWhois(target).creation_date

        if isinstance(creationDate, list):
            creationDate = creationDate[0]

        if creationDate is None:
            return Feature.Pishing

        return Feature.Pishing if datetime.now() - creationDate  <= timedelta(days=30*6) else Feature.Legitimate

if __name__ == "__main__":
    from pprint import pprint
    
    # pprint(DomainRegistrationExtractor.getFeature("facebook.com"))
    # print ("="*80)
    # pprint(DomainRegistrationExtractor.getFeature("mexcoder.com"))
    # print ("="*80)
    pprint(DomainRegistrationExtractor.getFeature("scotiaportal.ir"))
