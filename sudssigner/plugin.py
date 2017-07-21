#!/usr/bin/env python

import logging
from suds.plugin import MessagePlugin
from lxml import etree
from suds.bindings.binding import envns
from suds.wsse import wsuns, dsns, wssens
from libxml2_wrapper import LibXML2ParsedDocument
from xmlsec_wrapper import XmlSecSignatureContext, init_xmlsec, deinit_xmlsec
from SignatureMethods import DSA, RSA
from OpenSSL import crypto
from uuid import uuid4

import xmlsec

log = logging.getLogger(__name__)


def lxml_ns(suds_ns):
    return dict((suds_ns,))


def ns_id(tagname, ns_tuple):
    """Expand element name with namespace

    Args:
        tagname (str): tagname without prefix / namespace
        ns_tuple (tuple(str,str)): prefix, namespace tuple as given by suds
    """
    return '{%s}%s' % (ns_tuple[1], tagname)


HEADER_XPATH = etree.XPath('/$:Envelope/$:Header'.replace('$', envns[0]), namespaces=lxml_ns(envns))
BODY_XPATH = etree.XPath('/$:Envelope/$:Body'.replace('$', envns[0]), namespaces=lxml_ns(envns))
SECURITY_XPATH = etree.XPath('%s:Security' % wssens[0], namespaces=lxml_ns(wssens))
TIMESTAMP_XPATH = etree.XPath('%s:Timestamp' % wsuns[0], namespaces=lxml_ns(wsuns))
C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#'
B64ENC = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary'
X509PROFILE = 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3'
XMLDSIG_SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1'
CERTREF = 'x509cert00'
BEGINCERT = "-----BEGIN CERTIFICATE-----"
ENDCERT = "-----END CERTIFICATE-----"
NSMAP = dict((dsns, wssens, wsuns))
WSU_ID = ns_id('Id', wsuns)
DS_DIGEST_VALUE = ns_id('DigestValue', dsns)
DS_REFERENCE = ns_id('Reference', dsns)
DS_TRANSFORMS = ns_id('Transforms', dsns)
WSSE_BST = ns_id('BinarySecurityToken', wssens)
DS_SIGNATURE = ns_id('Signature', dsns)


class SignerPlugin(MessagePlugin):
    """
    Digital signature plugin for suds >= 0.4.1
    This plugins uses suds plugin "sending" hook to add
    a XML digital signature for the SOAP-ENV:Body tag.
    Arguments:
    - keyfile: RSA/DSA key filename + certificate in PEM format
    - keytype: DSA or RSA. Tries to detect key type
    - pwd: password for encrypted key
    - pwdCallback: callable that returns password
    - pwdCallbackCtx: arguments sent to the pwdCallback callable

    To debug the XML returned, do:
    import logging
    logging.getLogger('sudssigner.plugin').setLevel(logging.DEBUG)
    """
    def __init__(self, keyfile, keytype=None, pwd=None, pwdCallback=None,
            pwdCallbackCtx=None):
        init_xmlsec()
        self.keyfile = keyfile
        self.pwd = pwd
        self.pwdCallback = pwdCallback
        self.pwdCallbackCtx = pwdCallbackCtx
        self.load_keyfile()
        self.keytype = self.handle_keytype(keytype)

    def load_keyfile(self):
        cert = file(self.keyfile, 'rb').read()
        self.cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        self.privatekey = crypto.load_privatekey(crypto.FILETYPE_PEM, cert)

    def handle_keytype(self, keytype):
        if keytype is None:
            return self.detect_keytype()
        elif any(isinstance(keytype, t) for t in (str, unicode)):
            return keytype
        else:
            raise ValueError('keytype must be a string or None')

    def detect_keytype(self):
        algo = self.privatekey.type()
        if algo == crypto.TYPE_DSA:
            return DSA
        if algo == crypto.TYPE_RSA:
            return RSA
        raise ValueError('unknown keytype')

    def marshalled(self, context):
        # !!! Axis needs the same namespace as Header and Envelope
        context.envelope[1].prefix = context.envelope.prefix
        pass

    def sending(self, context):
        """
        sending plugin method: add security headers and sign msg
        """
        env = etree.fromstring(context.envelope)
        try:
            body = BODY_XPATH(env)[0]
        except IndexError:
            raise ValueError("SOAP request has no body.")
        queue = SignQueue()
        queue.push_and_mark(body)
        security = ensure_security_header(env, queue)
        btkn = etree.SubElement(security, WSSE_BST, {
            'EncodingType': B64ENC,
            'ValueType': X509PROFILE,
            WSU_ID: CERTREF,
        }, NSMAP)
        crt = crypto.dump_certificate(crypto.FILETYPE_PEM, self.cert)
        crt = crt.replace('\n', '').replace(BEGINCERT, '').replace(ENDCERT, '')
        btkn.text = crt
        self.insert_signature_template(security, queue)
        text = self.get_signature(etree.tostring(env))
        log.debug("WS call text after signature:\n%s", text)
        context.envelope = text

    def insert_signature_template(self, security, queue):
        signature = etree.SubElement(security, DS_SIGNATURE)
        self.append_signed_info(signature, queue)
        etree.SubElement(signature, ns_id('SignatureValue', dsns))
        self.append_key_info(signature)

    def append_signed_info(self, signature, queue):
        signed_info = etree.SubElement(signature, ns_id('SignedInfo', dsns))
        set_algorithm(signed_info, 'CanonicalizationMethod', C14N)
        set_algorithm(signed_info, 'SignatureMethod', self.keytype)
        queue.insert_references(signed_info)

    def append_key_info(self, signature):
        key_info = etree.SubElement(signature, ns_id('KeyInfo', dsns))
        sec_token_ref = etree.SubElement(key_info,
                ns_id('SecurityTokenReference', wssens))
        etree.SubElement(sec_token_ref, ns_id('Reference', wssens), {
            'URI': '#%s' % CERTREF,
            'ValueType': X509PROFILE,
        })
        x509_data = etree.SubElement(sec_token_ref, ns_id('X509Data', dsns))
        x509_issuer_serial = etree.SubElement(x509_data,
                ns_id('X509IssuerSerial', dsns))
        x509_issuer_name = etree.SubElement(x509_issuer_serial,
                ns_id('X509IssuerName', dsns))
        issuer = ', '.join(
                '='.join(c) for c in self.cert.get_issuer().get_components())
        try:
            issuer = unicode(issuer, 'utf-8')
        except UnicodeDecodeError:
            try:
                issuer = unicode(issuer, 'latin1')
            except UnicodeDecodeError:
                raise ValueError(
                    "The certificate issuer has a name with "
                    "name illegal character encoding.")
        x509_issuer_name.text = issuer
        x509_serial_number = etree.SubElement(x509_issuer_serial,
                ns_id('X509SerialNumber', dsns))
        x509_serial_number.text = str(self.cert.get_serial_number())

    def get_signature(self, envelope):
        with LibXML2ParsedDocument(envelope) as doc:
            root = doc.getRootElement()
            xmlsec.addIDs(doc, root, ['Id'])
            signNode = xmlsec.findNode(root, xmlsec.NodeSignature, xmlsec.DSigNs)
            with XmlSecSignatureContext(self) as dsig_ctx:
                if dsig_ctx.sign(signNode) < 0:
                    raise RuntimeError('signature failed')
                return doc.serialize()

    def __del__(self):
        deinit_xmlsec()


class SignQueue(object):

    def __init__(self):
        self.queue = []

    def push_and_mark(self, element):
        unique_id = get_unique_id()
        element.set(WSU_ID, unique_id)
        self.queue.append(unique_id)

    def insert_references(self, signed_info):
        for element_id in self.queue:
            reference = etree.SubElement(signed_info, DS_REFERENCE,
                    {'URI': '#{0}'.format(element_id)})
            transforms = etree.SubElement(reference, DS_TRANSFORMS)
            set_algorithm(transforms, 'Transform', C14N)
            set_algorithm(reference, 'DigestMethod', XMLDSIG_SHA1)
            etree.SubElement(reference, DS_DIGEST_VALUE)


def get_unique_id():
    return 'id-{0}'.format(uuid4())


def set_algorithm(parent, name, value):
    etree.SubElement(parent, ns_id(name, dsns), {'Algorithm': value})


def ensure_security_header(env, queue):
    try:
        header = HEADER_XPATH(env)[0]
    except IndexError:
        header = etree.Element(ns_id('Header', envns), nsmap=env.nsmap)
        env.insert(0, header)
    security = SECURITY_XPATH(header)
    if security:
        for timestamp in TIMESTAMP_XPATH(security[0]):
            queue.push_and_mark(timestamp)
        return security[0]
    else:
        d = {}
        #!!! With Axis 1.x this does not work
        #d[ns_id('mustUnderstand', envns)] = '1'
        security = etree.SubElement(header, ns_id('Security', wssens), d, NSMAP)
        return security
