from cachetools import TTLCache
import time
import urllib.error
import urllib.request
import ssl
from urllib.parse import urlparse
import socket
import OpenSSL
from datetime import datetime

class CachingWebClient (TTLCache):
    # this class uses an in-memory Cache
    # responses will be cached and it
    # will contain a key consisting of the fetched url and the value
    # will be a dictionary with the following keys:
    # - validSssl
    # - sslCertificate
    # - http code
    # - headers
    # - redirected
    # - finalURL
    # - body

    def __init__(self, maxsize = 255, ttl=30*60, timer=time.monotonic, getsizeof=None): # default cache = 30 minutes
        TTLCache.__init__(self, maxsize, ttl, timer=timer, getsizeof=getsizeof)

    # missing will fetch an 
    def __missing__(self, key):
        data = self.__fetch(key)
        if data:
            self[key] = data # store data in cache

        return data
        
    def __fetch(self, url, badssl = False):
        data = None
        try:
            ctx = ssl.create_default_context() if not badssl else ssl._create_unverified_context()
            with urllib.request.urlopen(url, context=ctx) as s:
                body = s.read()

                data = {}
                data["validSsl"] = not badssl
                data["httpCode"] = s.status
                data["originalURL"]  = url
                data["finalUrl"] = s.geturl()
                data["redirected"] = not (url == data["finalUrl"])
                data["certificate"] = self.__fetchSSLCert(data["finalUrl"])
                data["headers"]  = s.getheaders()
                data["body"] = body

        except urllib.error.URLError as e:
            if isinstance(e.reason, ssl.SSLCertVerificationError):
                data = self.__fetch(url, badssl=True)

        return data

    def __fetchSSLCert(self, url, timeout=10):
        parsedURL = urlparse(url)

        cert = None
        
        if parsedURL.scheme == "https":
            context = ssl._create_unverified_context()
            conn = socket.create_connection((parsedURL.hostname, parsedURL.port or 443))
            sock = context.wrap_socket(conn, server_hostname=parsedURL.hostname)
            sock.settimeout(timeout)
            try:
                der_cert = sock.getpeercert(True)
            finally:
                sock.close()

            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, der_cert)

            cert = {
                'subject': dict(x509.get_subject().get_components()),
                'issuer': dict(x509.get_issuer().get_components()),
                'serialNumber': x509.get_serial_number(),
                'version': x509.get_version(),
                'notBefore': datetime.strptime(x509.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ'),
                'notAfter': datetime.strptime(x509.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ'),
            }

            extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
            extension_data = {e.get_short_name(): str(e) for e in extensions}
            cert.update(extension_data)

        return cert

    def fetchURL(self, url, *args, fresh = False, **kwargs):
        if fresh and url in self:
            del self[url]

        return self[url]

if __name__ == "__main__":
    from pprint import pprint
    wc  = CachingWebClient()

    def spacer():
        print()
        print("="*80)
        print()

    pprint(wc.fetchURL("https://expired.badssl.com/"))
    print("="*80)
    pprint(wc.fetchURL("https://mexcoder.com/"))
    print("="*80)
    #print(wc.fetchURL("http://mexcoder.com/"))
    # print(wc.fetchURL("http://mexcoder.com", fresh=True))
    # spacer()
    # print(wc.fetchURL("http://mexcoder.com"))
    # spacer()
    # print(wc.fetchURL("http://mexcoder.com"))
    # spacer()
    # print(wc.fetchURL("http://mexcoder.com"))
    # spacer()
    # print(wc.fetchURL("http://mexcoder.com", fresh=True))
    # spacer()
    # print(wc.fetchURL("http://mexcoder.com"))
    # spacer()
    # print(wc.fetchURL("http://mexcoder.com"))