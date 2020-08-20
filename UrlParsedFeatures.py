from basicFeatures import FeatureExtractor
from urllib.parse import urlparse
from FeatureEnum import Feature
import re

class UrlParsed(FeatureExtractor):
    pass

class IpExtractor(UrlParsed):

    ipv4Regex = re.compile("^(((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|((0x[0-9a-fA-F]{2,3}.){3}(0x[0-9a-fA-F]{2,3})))$")
    
    @staticmethod
    def getName():
        return "having_IP_Address"

    @staticmethod
    def getFeature(target):
        parsed = urlparse(target)
        isIP = IpExtractor.ipv4Regex.match(parsed.hostname) is not None
        return Feature.Pishing if isIP else Feature.Legitimate

class AtSymbolExtractor(UrlParsed):
    
    @staticmethod
    def getName():
        return "having_At_Symbol"

    @staticmethod
    def getFeature(target):       
        return Feature.Pishing if "@" in target else Feature.Legitimate

class UrlShortenedExtractor(UrlParsed):

    URLShorteners = [
        "bit.ly",
        "www.bit.ly",
        "tinyurl.com",
        "www.tinyurl.com",
        "ow.ly",
        "www.ow.ly"
    ]
    
    @staticmethod
    def getName():
        return "Shortining_Service"

    @staticmethod
    def getFeature(target):
        parsed = urlparse(target)  
        return  Feature.Pishing if (parsed.hostname in
                                     UrlShortenedExtractor.URLShorteners) 
                                else
                Feature.Legitimate

class DashExtractor(UrlParsed):
    
    @staticmethod
    def getName():
        return "having_At_Symbol"

    @staticmethod
    def getFeature(target):  
        parsed = urlparse(target)     
        return Feature.Pishing if "-" in parsed.hostname else Feature.Legitimate


class HttpsTokenExtractor(UrlParsed):
    
    @staticmethod
    def getName():
        return "having_At_Symbol"

    @staticmethod
    def getFeature(target):  
        parsed = urlparse(target)     
        return Feature.Pishing if "https" in parsed.hostname else Feature.Legitimate