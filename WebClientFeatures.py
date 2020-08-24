from CachingWebClient import CachingWebClient
from basicFeatures import FeatureExtractor
from FeatureEnum import Feature
from datetime import timedelta
from urllib.parse import urlparse
import bs4

class WebClientExtractor(FeatureExtractor):
    webClient = CachingWebClient()

    fetchPage = webClient.fetchURL


class HttpsStatusExtractor (WebClientExtractor):

    @staticmethod
    def getName():
        return "SSLfinal_State"

    @staticmethod
    def getFeature(target):

        data = WebClientExtractor.fetchPage(target)
        useHTTPS = data["certificate"] is not None
        if useHTTPS:
            certIsValid = data["validSsl"]
            age = data["certificate"]["notAfter"] - data["certificate"]["notBefore"]

        legit = useHTTPS and certIsValid and age >= timedelta(days=365)
        suspicious = useHTTPS and not certIsValid

        return Feature.Legitimate if legit else (
               Feature.Suspicious if suspicious else 
               Feature.Pishing )

class FavIconStatusExtractor (WebClientExtractor):

    @staticmethod
    def getName():
        return "Favicon"

    @staticmethod
    def getFeature(target):

        data = WebClientExtractor.fetchPage(target)
        parser = bs4.BeautifulSoup(data["body"], "html.parser")

        favicon = parser.find("link", rel="icon")
        
        veredict = Feature.Legitimate

        if favicon is not None:
            faviconDomain = urlparse(favicon["href"]).hostname
            pageDomain = urlparse(target).hostname
            veredict = Feature.Legitimate if faviconDomain == pageDomain else Feature.Pishing

        return veredict

class RequestURLExtractor (WebClientExtractor):

    @staticmethod
    def getName():
        return "Request_URL"

    @staticmethod
    def getFeature(target):

        data = WebClientExtractor.fetchPage(target)
        parser = bs4.BeautifulSoup(data["body"], "html.parser")
        
        domain = urlparse(target).hostname

        links = parser.findAll("img")

        resources = [urlparse(link["src"]).hostname  for link in links]

        extrasources  = parser.findAll("audio")
        extrasources += parser.find_all("video")

        for resource in extrasources:
            for link in resource.findAll("Source"):
                resources.append(urlparse(link["src"]).hostname)

        external = 0

        for resource in resources:
            if resource != domain:
                external += 1
        if len(resources)>0:
            ratio = (external / len(resources)) * 100 
        else:
            ratio = 0

        return Feature.Legitimate if ratio < 22 else (
               Feature.Suspicious if ratio < 61 else
               Feature.Pishing )

class anchorURLExtractor (WebClientExtractor):

    @staticmethod
    def getName():
        return "URL_of_Anchor"

    @staticmethod
    def getFeature(target):

        data = WebClientExtractor.fetchPage(target)
        parser = bs4.BeautifulSoup(data["body"], "html.parser")
        
        domain = urlparse(target).hostname

        links = parser.findAll("a")

        resources =[]
        for link in links:
            if "href" in link:
                resources.append(urlparse(link["href"]).hostname)

        external = 0

        for resource in resources:
            if resource != domain:
                external += 1
        if len(resources)>0:
            ratio = (external / len(resources)) * 100 
        else:
            ratio = 0

        return Feature.Legitimate if ratio < 31 else (
               Feature.Suspicious if ratio < 67 else
               Feature.Pishing )

class LinksInMetaExtractor (WebClientExtractor):

    @staticmethod
    def getName():
        return "Links_in_tags"

    @staticmethod
    def getFeature(target):

        data = WebClientExtractor.fetchPage(target)
        parser = bs4.BeautifulSoup(data["body"], "html.parser")
        
        domain = urlparse(target).hostname
        
        links = []

        meta = parser.findAll("meta")

        for metadata in meta:
            if "content" in metadata and urlparse(metadata["content"]).scheme != "":
                links.append(urlparse(metadata["content"]).hostname)

        links += [urlparse(script["src"]).hostname for script in parser.findAll("Script")]
        links += [urlparse(link["href"]).hostname for link in parser.findAll("link")]

        external = 0

        for resource in links:
            if resource != domain:
                external += 1
                
        if len(links)>0:
            ratio = (external / len(links)) * 100 
        else:
            ratio = 0

        return Feature.Legitimate if ratio < 17 else (
               Feature.Suspicious if ratio < 81 else
               Feature.Pishing )

class ServerFromHandlerExtractor (WebClientExtractor):

    @staticmethod
    def getName():
        return "SFH"

    @staticmethod
    def getFeature(target):

        data = WebClientExtractor.fetchPage(target)
        parser = bs4.BeautifulSoup(data["body"], "html.parser")
        
        domain = urlparse(target).hostname

        forms = [urlparse(form["action"]).hostname for form in parser.findAll("form")]

        blankSFH = False
        wronfSFH = False

        for form in forms:
            blankSFH = form is None
            wronfSFH = form == domain

        return Feature.Pishing if blankSFH else (
               Feature.Suspicious if wronfSFH else
               Feature.Legitimate)

class MailToInServerFromHandlerExtractor (WebClientExtractor):

    @staticmethod
    def getName():
        return "Submitting_to_email"

    @staticmethod
    def getFeature(target):

        data = WebClientExtractor.fetchPage(target)
        parser = bs4.BeautifulSoup(data["body"], "html.parser")
    
        forms = [urlparse(form["action"]).hostname for form in parser.findAll("form")]

        wronfSFH = False

        for form in forms:
            if form is not None: # form may be None is there are forms whit relative paths
                wronfSFH = "mailto:" in form 

        return Feature.Pishing if wronfSFH else \
               Feature.Legitimate

class IframeExtractor (WebClientExtractor):

    @staticmethod
    def getName():
        return "Iframe"

    @staticmethod
    def getFeature(target):

        data = WebClientExtractor.fetchPage(target)
        parser = bs4.BeautifulSoup(data["body"], "html.parser")

        iframe = parser.find("iframe")


        return Feature.Pishing if iframe is not None else \
               Feature.Legitimate

if __name__ == "__main__":
        print (HttpsStatusExtractor.getFeature("https://mexcoder.com"))
