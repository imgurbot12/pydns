"""
dns server implementation for dns-over-https
"""
import base64

from .. import DNSPacket, QR, RCode, SerialCtx

#** Variables **#
__all__ = []

#: raw content-type for dns-over-https
CONTENT_RAW = 'application/dns-message'

#: json content-type for dns-over-https
CONTENT_JSON = 'application/dns-json'

#** Functions **#

def _get_request(method: str, params: dict, headers: dict, body: bytes):
    """parse dns-packet request based on http data"""
    # ensure output is in valid format
    accept = headers.get('Accept')
    if accept not in (CONTENT_RAW, CONTENT_JSON):
        raise ContentTypeError('Accept: %s' % accept)
    # parse packet based on method/query-params/content-type
    ctx   = SerialCtx()
    if method.upper() == 'GET':
        # if question is b64-encoded in params
        if 'dns' in params:
            req = DNSPacket.from_bytes(base64.b64decode(params['dns']), ctx)
        elif 'name' in params and 'type' in params:
            #TODO: form question and full packet here
        else:
            raise NotSpecifiedError('no valid search params found')
    elif method.upper() == 'POST':
        ctype = headers.get('Content-Type')
        if ctype != CONTENT_RAW:
            raise ContentTypeError('Content-Type: %s' % ctype)
        req = DNSPacket.from_bytes(body, ctx)

def global_web_handler(method: str, params: dict, headers: dict, body: bytes):
    """basic web-handler designed to be pluggable into any web-framework"""
    req = _get_request(method, params, headers, body)
    #TODO: pass to handler and handle response generation (especially JSON)
    raise NotImplementedError('function not yet fully implemented. (im lazy)')

#** Exceptions **#

class NotSpecifiedError(Exception):
    """error raised when question is not specified properly"""

class ContentTypeError(Exception):
    """error raised when content-type is not accepted"""
