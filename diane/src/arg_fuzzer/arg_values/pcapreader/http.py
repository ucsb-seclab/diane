import json
import re
import urllib


class HttpPacket():
    ### CONSTANTS
    TYPE_REQUEST = "REQUEST"
    TYPE_RESPONSE = "RESPONSE"
    TYPE_UNKNOWN = "UNKNOWN"
    ACCEPTED_TYPES = [TYPE_REQUEST, TYPE_RESPONSE]

    METHOD_GET = "GET"
    METHOD_POST = "POST"
    METHOD_PUT = "PUT"
    METHOD_UNKNOWN = "UNKNOWN"
    ACCEPTED_METHODS = [METHOD_PUT, METHOD_POST, METHOD_GET]

    CONTENT_TYPE_JSON = "application/json"
    CONTENT_TYPE_URL_ENCODED = "application/x-www-form-urlencoded"
    CONTENT_TYPE_XML = "text/xml"
    CONTENT_TYPE_UNKNOWN = "UNKNOWN"
    ACCEPTED_CONTENT_TYPES = [CONTENT_TYPE_XML, CONTENT_TYPE_URL_ENCODED, CONTENT_TYPE_JSON]

    # Group[1] - var | Group[2] - val
    URL_ENCODED_PARAM_REGEXP = re.compile("([^\&]+)=([^\&]+)\&?")

    ###

    def __init__(self, pyshark_pkt):
        # TODO: HEADERS ARE MISSING
        self.sport = pyshark_pkt.tcp.srcport
        self.dport = pyshark_pkt.tcp.dstport
        self.src = pyshark_pkt.ip.src
        self.dst = pyshark_pkt.ip.dst
        self.raw_pkt = pyshark_pkt
        self.method = self.METHOD_UNKNOWN
        self.type = self.TYPE_UNKNOWN
        self.content_type = self.CONTENT_TYPE_UNKNOWN
        self.query = ""
        self.body = ""
        self.response_code = 0

        # Setting the content type
        if hasattr(pyshark_pkt.http, "content_type"):
            self._set_content_type(pyshark_pkt.http.content_type)

        # Setting the body
        if hasattr(pyshark_pkt.http, "file_data"):
            self.body = urllib.unquote(pyshark_pkt.http.file_data)

        # Setting the type
        if hasattr(pyshark_pkt.http, "request"):
            self.type = self.TYPE_REQUEST
        elif hasattr(pyshark_pkt.http, "response"):
            self.type = self.TYPE_RESPONSE
        else:
            self.type = self.TYPE_UNKNOWN
            return

        # Setting fields if the packet is a REQUEST
        if self.type == self.TYPE_REQUEST:
            self.method = pyshark_pkt.http.request_method
            self.uri = pyshark_pkt.http.request_full_uri

            if hasattr(pyshark_pkt.http, "request_uri_path"):
                self.path = pyshark_pkt.http.request_uri_path
            else:
                self.path = pyshark_pkt.http.request_uri

            if self.method == self.METHOD_GET:
                if hasattr(pyshark_pkt.http, "request_uri_query"):
                    self.query = urllib.unquote(pyshark_pkt.http.request_uri_query)

                    # Horrible fix. //FIXME
                    # We shouldn't be doing this.
                    if self.content_type == self.CONTENT_TYPE_UNKNOWN:
                        self.content_type = self.CONTENT_TYPE_URL_ENCODED
                        
        # Setting fields if the packet is a RESPONSE
        elif self.type == self.TYPE_RESPONSE:
            if hasattr(pyshark_pkt.http, "response_code"):
                self.response_code = int(pyshark_pkt.http.response_code)

    def __str__(self):
        if self.type == self.TYPE_RESPONSE:
            return "<HTTPPacket {:8} | {} -> {}>".format(self.type, self.src, self.dst)
        elif self.type == self.TYPE_REQUEST:
            return "<HTTPPacket {:6} {:8} | {} -> {}>".format(self.method, self.type, self.src, self.dst)
        else:
            return "<HTTPPacket {:8} | {} -> {}>".format(self.type, self.src, self.dst)

    def is_request(self):
        return self.type == self.TYPE_REQUEST

    def is_response(self):
        return self.type == self.TYPE_RESPONSE

    # TODO: To be updated
    def has_parameters(self):
        result = False

        if self.content_type == self.CONTENT_TYPE_JSON:
            result = self.body is not None
        else:
            if self.method == self.METHOD_GET:
                result = self.URL_ENCODED_PARAM_REGEXP.search(self.query) is not None
            elif self.method == self.METHOD_POST:
                result = self.URL_ENCODED_PARAM_REGEXP.search(self.body) is not None
        return result

    def get_parameters(self, specific_content_type = None):
        """
        :return: A dictionary
        """
        if self.content_type == self.CONTENT_TYPE_JSON:
            return self._get_json_parameters()
        elif self.content_type == self.CONTENT_TYPE_URL_ENCODED:
            return self._get_urlenc_parameters()
        elif self.content_type == self.CONTENT_TYPE_XML:
            return self._get_xml_parameters()
        # UNKNOWN
        else:
            return {}

    def _get_xml_parameters(self):
        open_keys = re.findall("<[^/][^>]+>", self.body)
        close_keys = [o[0] + '/' + o[1:].split(' ')[0].replace('>', '') + '>' for o in open_keys]
        keys = zip(open_keys, close_keys)
        vals = [self.body.split(k[0])[1].split(k[1])[0] for k in keys]
        return {k: v for k, v in zip(keys, vals)}

    def _get_json_parameters(self):
        params = {}

        if self.content_type == self.CONTENT_TYPE_JSON and self.body:
            json_res = json.loads(self.body)
            if isinstance(json_res, list):
                for dictionary in json_res:
                    params = merge_dicts(params, dictionary)
            elif isinstance(json_res, dict):
                params = json_res
        return params

    def _get_urlenc_parameters(self):
        params = {}

        # PUT or POST
        if self.method in [self.METHOD_PUT, self.METHOD_POST]:
            for p in self.URL_ENCODED_PARAM_REGEXP.findall(self.body):
                key = " ".join(p[0].split("+"))
                val = " ".join(p[1].split("+"))
                params[key] = val
        # GET
        elif self.method == self.METHOD_GET:
            for p in self.URL_ENCODED_PARAM_REGEXP.findall(self.query):
                key = " ".join(p[0].split("+"))
                val = " ".join(p[1].split("+"))
                params[key] = val

        return params

    def _set_content_type(self, raw_content_type):
        """
        This function sets the field "content_type" to one of the variables exposed by the class.
        If the content type is not one of the variables, "content_type" is set to the argument.
        :param raw_content_type: The content type returned by the pyshark packet
        """

        if self.CONTENT_TYPE_JSON in raw_content_type:
            self.content_type = self.CONTENT_TYPE_JSON
        elif self.CONTENT_TYPE_URL_ENCODED in raw_content_type:
            self.content_type = self.CONTENT_TYPE_URL_ENCODED
        elif self.CONTENT_TYPE_XML in raw_content_type:
            self.content_type = self.CONTENT_TYPE_XML
        else:
            self.content_type = raw_content_type


# TODO: remove me. I am a duplicate of zeppolina.utils.merge_dicts()
def merge_dicts(x, y):
    z = x.copy()
    z.update(y)
    return z
