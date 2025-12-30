import ahocorasick
import gzip
import zlib

from http.client import HTTPResponse
from io import BytesIO

class ResponseSocket():
    def __init__(self, resp):
        self.file = BytesIO(resp)
    
    def makefile(self, *args, **kwargs):
        return self.file

def parse_http_response(response_raw: bytes):
    resp_socket = ResponseSocket(response_raw)
    response = HTTPResponse(resp_socket)
    response.begin()
    response_body = response.read()
    
    encoding = response.getheader("Content-Encoding", "").lower()
    if encoding == "gzip":
        response_body = gzip.decompress(response_body)
    elif encoding == "deflate": 
        try:
            response_body = zlib.decompress(response_body)
        except zlib.error:
            response_body = zlib.decompress(response_body, -zlib.MAX_WBITS)
    
    return response, response_body

def find_common_substrings(targets, long_bytes, min_len=8):
    long_s = long_bytes.decode('latin1')
    shorts_s = [s.decode('latin1') for s in targets]

    A = ahocorasick.Automaton()
    inserted = set()

    for s in shorts_s:
        n = len(s)
        for i in range(0, n - min_len + 1):
            for j in range(i + min_len, n + 1):
                pat = s[i:j]
                if pat not in inserted:
                    inserted.add(pat)
                    A.add_word(pat, pat)

    A.make_automaton()

    matches = set()
    for _, pat in A.iter(long_s):
        matches.add(pat.encode('latin1'))

    return matches