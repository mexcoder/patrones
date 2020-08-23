import re
from urllib.parse import urlparse
from tld import get_tld
from basicFeatures import FeatureExtractor
from FeatureEnum import Feature

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
        return  Feature.Pishing if (parsed.hostname in UrlShortenedExtractor.URLShorteners) else \
                Feature.Legitimate

class DashExtractor(UrlParsed):
    
    @staticmethod
    def getName():
        return "Prefix_Suffix"

    @staticmethod
    def getFeature(target):  
        parsed = urlparse(target)     
        return Feature.Pishing if "-" in parsed.hostname else Feature.Legitimate


class HttpsTokenExtractor(UrlParsed):
    
    @staticmethod
    def getName():
        return "HTTPS_token"

    @staticmethod
    def getFeature(target):  
        parsed = urlparse(target)     
        return Feature.Pishing if "https" in parsed.hostname else Feature.Legitimate

class RedirectExtractor(UrlParsed):
    
    @staticmethod
    def getName():
        return "double_slash_redirecting"

    @staticmethod
    def getFeature(target):
        try:
            # index will raise an exception if the substring is not found thus not 
            # performing the return
            hasDoubleSlash = target.index("//", 7)
            return Feature.Pishing
        except:
            pass
        
        return Feature.Legitimate


class NumberSubdomainsExtractor(UrlParsed):
    
    @staticmethod
    def getName():
        return "having_Sub_Domain"

    @staticmethod
    def getFeature(target):
        parsed = urlparse(target)
        subdomains = get_tld(target, as_object=True).subdomains.split(".")
        count = len(subdomains) + 1 # add one to account for the main domain
        if("www" in subdomains):
            count -= 1
        
        return Feature.Legitimate if count == 1 else \
               Feature.Suspicious if count == 2 else \
               Feature.Pishing

class NonStandarPortExtractor(UrlParsed):

    standarPort = {"FTP" : 21,
                   "SSH" : 22,
                   "Telnet" : 23,
                   "HTTP" : 80,
                   "HTTPS" : 443,
                   "SMB" : 445,
                   "MSSQL" : 1433,
                   "ORACLE" : 1521,
                   "MySQL" : 3306,
                   "Remote Desktop" : 3389}

    
    @staticmethod
    def getName():
        return "port"

    @staticmethod
    def getFeature(target):
        parsed = urlparse(target)
        
        defaultport = False


        if(parsed.port is None):
           defaultport = True

        elif parsed.port == NonStandarPortExtractor.standarPort[parsed.scheme.upper()]:
            defaultport = True
       
        
        return Feature.Legitimate if defaultport else \
               Feature.Pishing

if __name__ == "__main__":
    print(NonStandarPortExtractor.getFeature("https://mexcoder.com"))
    print(NonStandarPortExtractor.getFeature("https://mexcoder.com:69"))
    print(NonStandarPortExtractor.getFeature("https://mexcoder.com:8080"))
    print(NonStandarPortExtractor.getFeature("https://mexcoder.com:443"))
