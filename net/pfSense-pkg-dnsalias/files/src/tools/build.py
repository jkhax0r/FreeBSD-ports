"""Build deterministic runtime code; distribute documentation separately.

Keeping README outside the runtime also permits the optional native extractor
to fit older160-member upgrade parsers. No live evidence is included.
"""
import hashlib
import argparse
import json
from pathlib import Path
import sys
import re
import zipfile

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('output')
parser.add_argument('--native-codec',type=Path,help='Explicit locally built FreeBSD amd64 CPython3.11 codec; no build or download is performed')
parser.add_argument('--native-extractor',type=Path,help='Explicit locally built FreeBSD amd64 CPython3.11 small-reply extractor')
parser.add_argument('--native-confirmation',type=Path,help='Explicit optional FreeBSD amd64 CPython3.11 confirmation component; does not activate reuse')
parser.add_argument('--native-generation',type=Path,help='Explicit optional FreeBSD amd64 CPython3.11 generation/socket checker')
parser.add_argument('--native-key',type=Path,help='Explicit optional FreeBSD amd64 CPython3.11 cached-answer key; no activation')
args=parser.parse_args()
output=Path(args.output).resolve()
paths=sorted(list((root/"dnsalias").glob("*.py"))+list((root/"web").glob("*.php"))+list((root/"native").glob("*.php"))+[root/"manage.py"])
files={p.relative_to(root).as_posix():p.read_bytes() for p in paths}
for kind,basename,binary in (('wire','replywire',args.native_codec),('extract','replyextract',args.native_extractor),
                             ('confirmation','confirmation',args.native_confirmation),('generation','generation',args.native_generation),
                             ('key','confirmationkey',args.native_key)):
    if binary is None:continue
    sys.path.insert(0,str(root))
    from dnsalias.nativewire import ABI,extension,qualified_elf
    name,state,owner,abi,protocol,methods=extension(kind)
    raw=binary.read_bytes()
    if not qualified_elf(raw):raise ValueError('qualified native ELF required')
    source=(root/'native'/(basename+'.c')).read_bytes()
    files['native/'+basename+'.c']=source
    files['native/'+basename+'.cpython-311.so']=raw
    files['native/'+basename+'.json']=(json.dumps({'format':owner,'module':name,'abi':ABI,'protocol':1,
        'binary_sha256':hashlib.sha256(raw).hexdigest(),'source_sha256':hashlib.sha256(source).hexdigest()},sort_keys=True,indent=2)+'\n').encode()
version=re.search(r'__version__ = "([^"]+)"',(root/"dnsalias/__init__.py").read_text())[1]
manifest={"format":1,"version":version,"mode":"observation_only","counter_ram_protocol":1,
          "files":{n:hashlib.sha256(b).hexdigest() for n,b in files.items()}}
files["MANIFEST.json"]=(json.dumps(manifest,sort_keys=True,indent=2)+"\n").encode()
output.parent.mkdir(parents=True,exist_ok=True)
with zipfile.ZipFile(output,"w",compression=zipfile.ZIP_DEFLATED) as z:
    for name,data in sorted(files.items()):
        info=zipfile.ZipInfo(name,date_time=(2026,1,1,0,0,0))
        info.compress_type=zipfile.ZIP_DEFLATED
        info.external_attr=0o100600<<16
        z.writestr(info,data)
print(json.dumps({"path":str(output),"sha256":hashlib.sha256(output.read_bytes()).hexdigest(),"files":len(files)}))
