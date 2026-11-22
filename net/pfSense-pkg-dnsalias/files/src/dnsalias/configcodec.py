"""Inactive local adapter for the qualified native configuration converter.

Borrow an already-qualified source audit and exact package helper digest. No
default live paths, configuration reads/writes, cache changes or scheduling.
The fixed helper bounds input/output expansion and PHP memory; this adapter
also validates its complete response. Its subprocess timeout is a soft elapsed
budget, not a hard kernel/filesystem latency guarantee. Never use in DNS or UI
request handling. Successful results are private configuration, not log data.
"""
import base64
import hashlib
import json
import math
import subprocess
import sys
import time

from .checkpoint import identity
from .ipc import strict_pairs,finite_float,invalid_number
from .sourceaudit import SourceAudit

XML_SOURCE_SHA256='9f0a71e0419e0587af645e94e6c15eef851bdd7185b6df419a67b7acb5a06966'
MAX_XML=8*1024*1024
MAX_REQUEST=16*1024*1024
MAX_RESPONSE=32*1024*1024


class ConfigConversionError(ValueError):pass


class NativeConfigCodec:
    def __init__(self,audit,*,helper_sha256,budget_seconds=2):
        identity(helper_sha256)
        if not sys.platform.startswith('freebsd') or not isinstance(audit,SourceAudit) or audit.state!='qualified':
            raise ValueError('qualified native conversion source audit required')
        if type(budget_seconds) not in (int,float) or not math.isfinite(budget_seconds) or not .01<=budget_seconds<=2:
            raise ValueError('bounded native conversion budget required')
        files={row[0].name:row[0] for row in audit.files}
        if (set(files)!={'config_codec','native_xml_parser'} or files['native_xml_parser'].path!='/etc/inc/xmlparse.inc'
            or not files['config_codec'].path.endswith('/native/configcodec.php')
            or files['config_codec'].max_bytes>65536 or files['native_xml_parser'].max_bytes>100000
            or audit.hashes.get('config_codec')!=helper_sha256 or audit.hashes.get('native_xml_parser')!=XML_SOURCE_SHA256):
            raise ValueError('exact inspected converter and native parser required')
        self.audit=audit;self.helper=files['config_codec'].path;self.budget=budget_seconds
        self.state='ready';self.expected={'config_codec':helper_sha256,'native_xml_parser':XML_SOURCE_SHA256}

    def _remaining(self,deadline):
        value=deadline-time.monotonic()
        if value<=0:raise ConfigConversionError('native conversion deadline')
        return value

    def _sources(self,deadline):
        result=self.audit.audit(budget_seconds=min(1,self._remaining(deadline)))
        if result['sources']!=self.expected:raise ConfigConversionError('native conversion source changed')

    def _convert(self,request):
        if self.state!='ready':raise ConfigConversionError('native conversion session ended; requalify sources')
        deadline=time.monotonic()+self.budget
        try:
            raw=json.dumps({'format':'dnsalias-native-xml-1',**request},separators=(',',':'),allow_nan=False).encode()
            if len(raw)>MAX_REQUEST:raise ConfigConversionError('native conversion request cap')
            self._sources(deadline)
            # Fixed executable and verified helper only. The qualified PHP
            # program has no command execution and bounds input, native XML,
            # tree size and memory. Captured output is never included in errors.
            result=subprocess.run(['/usr/local/bin/php',self.helper],input=raw,capture_output=True,
                timeout=self._remaining(deadline),close_fds=True,env={'PATH':'/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin','LC_ALL':'C'})
            self._sources(deadline)
            if result.returncode or result.stderr or not 0<len(result.stdout)<=MAX_RESPONSE:
                raise ConfigConversionError('native conversion rejected')
            value=json.loads(result.stdout,object_pairs_hook=strict_pairs,parse_float=finite_float,parse_constant=invalid_number)
            if (type(value) is not dict or set(value)!={'format','operation','configuration','rendered_xml_base64',
                'rendered_xml_sha256','source_xml_sha256','native_roundtrip_verified'}
                or value['format']!='dnsalias-native-xml-1' or value['operation']!=request['operation']
                or value['native_roundtrip_verified'] is not True or type(value['configuration']) is not dict):
                raise ConfigConversionError('native conversion response schema')
            encoded=value['rendered_xml_base64']
            if type(encoded) is not str or len(encoded)>((MAX_XML+2)//3)*4:
                raise ConfigConversionError('native conversion output cap')
            rendered=base64.b64decode(encoded,validate=True)
            if (not 0<len(rendered)<=MAX_XML or base64.b64encode(rendered).decode()!=encoded
                or hashlib.sha256(rendered).hexdigest()!=value['rendered_xml_sha256']):
                raise ConfigConversionError('native conversion output integrity')
            if request['operation']=='render':
                if value['configuration']!=request['configuration'] or value['source_xml_sha256'] is not None:
                    raise ConfigConversionError('native rendering changed configuration')
            else:
                original=base64.b64decode(request['xml_base64'],validate=True)
                if value['source_xml_sha256']!=hashlib.sha256(original).hexdigest():
                    raise ConfigConversionError('native parsing input mismatch')
            self._remaining(deadline)
            return {'configuration':value['configuration'],'xml':rendered,'xml_sha256':value['rendered_xml_sha256'],
                'source_xml_sha256':value['source_xml_sha256'],'native_roundtrip_verified':True}
        except Exception as exc:
            self.state='failed'
            # No subprocess stderr/stdout, parser text, config fields or full
            # exception details escape this private conversion boundary.
            raise ConfigConversionError('native configuration conversion failed; inspect locally before requalification') from None

    def decode(self,xml):
        if type(xml) is not bytes or not 0<len(xml)<=MAX_XML:raise ValueError('bounded native XML bytes required')
        return self._convert({'operation':'parse','xml_base64':base64.b64encode(xml).decode()})

    def encode(self,configuration):
        if type(configuration) is not dict or not configuration:raise ValueError('nonempty native configuration tree required')
        return self._convert({'operation':'render','configuration':configuration})

    def close(self):
        # The caller retains the borrowed audit and its descriptor ownership.
        self.state='closed'
