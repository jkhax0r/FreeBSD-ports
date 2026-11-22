/* Optional bounded cached-answer identity, FreeBSD/amd64 CPython 3.11.
 * Mirrors confirmationkey.py for exact wire scalars and containers. Keeps the
 * same canonical JSON and SHA256 representation, including unknown headers.
 * No receipt lookup, authentication, PF, clocks, filesystem or IPC operations.
 * The caller still normalizes/qualifies replies and verifies current receipts.
 */
#include <Python.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

#if !defined(__FreeBSD__) || !defined(__x86_64__) || PY_MAJOR_VERSION != 3 || PY_MINOR_VERSION != 11
#error "Qualified target is FreeBSD amd64 CPython 3.11"
#endif

enum { VERSION,CALLBACK,QTYPE,QCLASS,RCODE,BLOCK,BYPASS,DROPPED,PROFILE,
       GENERATION,QNAME,UTC,MONO,BASIS,STARTED,FLAGS,COUNT,TTL,RECORDS,HEADERS };
static const char *headers[HEADERS]={"extractor_version","callback","qtype","qclass","rcode",
    "policy_block_registry_match","policy_bypass_client","transport_dropped_before","profile_id",
    "resolver_generation","qname","time","monotonic","callback_start_time",
    "generation_started_monotonic","reply_flags","answer_rrsets","reply_ttl","records"};
enum { NAME,TYPE,CLASS,ID,RRFLAGS,RRTTL,RAWTTL,HEX,FIELDS };
static const char *fields[FIELDS]={"name","type","class","rrset_id","rrset_flags","rrset_ttl","raw_ttl","rdata_hex"};
static const char *observations[]={"client","client_port","time","monotonic","callback_start_time","request_id"};

enum { CACHE_SLOTS=128, CACHE_BYTES=4096 };
typedef struct {
    unsigned char *bytes;
    Py_ssize_t size;
    uint64_t hash;
    PyObject *digest;
} Entry;
typedef struct {
    PyObject *headers[HEADERS],*fields[FIELDS],*observations[6];
    PyObject *encode,*sha256,*digest,*maxint,*minint;
    Entry cache[CACHE_SLOTS];
    unsigned int next,entries;
    size_t bytes;
    uint64_t hits,misses,bypassed;
} State;

typedef struct { unsigned char bytes[CACHE_BYTES];size_t used; } Signature;
static int append(Signature *out,const void *value,size_t size) {
    if (size>CACHE_BYTES-out->used) return 0;
    memcpy(out->bytes+out->used,value,size);out->used+=size;return 1;
}
static int byte(Signature *out,unsigned char value) { return append(out,&value,1); }
/* Exact built-in scalar encoding for an internal cache only. Type tags and
 * float bits distinguish 1,1.0,True and +/-0.0. String representation may miss
 * an equivalent string with different storage width, but cannot match a
 * different value. No object references or caller-owned buffers are retained.
 * Native byte order is local to this process; the public digest is unchanged.
 */
static int signature_scalar(Signature *out,PyObject *value) {
    if (value==Py_None) return byte(out,'n');
    if (PyBool_Check(value)) return byte(out,value==Py_True?'t':'f');
    if (PyUnicode_CheckExact(value)) {
        int kind=PyUnicode_KIND(value);
        size_t size=(size_t)PyUnicode_GET_LENGTH(value)*(size_t)kind;
        uint32_t length=(uint32_t)size;
        return byte(out,'s') && byte(out,(unsigned char)kind) && append(out,&length,sizeof(length))
            && append(out,PyUnicode_DATA(value),size);
    }
    if (PyFloat_CheckExact(value)) {
        double n=PyFloat_AS_DOUBLE(value);
        return byte(out,'d') && append(out,&n,sizeof(n));
    }
    if (PyLong_CheckExact(value)) {
        int negative=Py_SIZE((PyLongObject *)value)<0;
        PyObject *magnitude=negative?PyNumber_Negative(value):Py_NewRef(value);
        if (!magnitude) return -1;
        uint64_t n=PyLong_AsUnsignedLongLong(magnitude);Py_DECREF(magnitude);
        if (PyErr_Occurred()) return -1;
        return byte(out,negative?'-':'+') && append(out,&n,sizeof(n));
    }
    return 0;
}
static int signature(State *s,PyObject *value,Signature *out) {
    Py_ssize_t position=0;PyObject *key,*item;out->used=0;
    while (PyDict_Next(value,&position,&key,&item)) {
        int result=signature_scalar(out,key);if (result!=1) return result;
        if (PyUnicode_Compare(key,s->headers[RECORDS])==0) {
            uint32_t count=(uint32_t)PyList_GET_SIZE(item);
            if (!byte(out,'l') || !append(out,&count,sizeof(count))) return 0;
            for (Py_ssize_t i=0;i<PyList_GET_SIZE(item);i++) {
                PyObject *row=PyList_GET_ITEM(item,i);
                for (int j=0;j<FIELDS;j++) {
                    result=signature_scalar(out,PyDict_GetItemWithError(row,s->fields[j]));
                    if (result!=1) return result;
                }
            }
        } else {
            result=signature_scalar(out,item);if (result!=1) return result;
        }
    }
    return 1;
}
static uint64_t signature_hash(const Signature *key) {
    uint64_t hash=UINT64_C(14695981039346656037);
    for (size_t i=0;i<key->used;i++) { hash^=key->bytes[i];hash*=UINT64_C(1099511628211); }
    return hash;
}
static PyObject *cached(State *s,const Signature *key,uint64_t hash) {
    for (unsigned int i=0;i<s->entries;i++) {
        Entry *e=&s->cache[i];
        if (e->hash==hash && e->size==(Py_ssize_t)key->used && !memcmp(e->bytes,key->bytes,key->used)) {
            s->hits++;return Py_NewRef(e->digest);
        }
    }
    s->misses++;return NULL;
}
static void remember(State *s,const Signature *key,uint64_t hash,PyObject *digest) {
    if (!PyBytes_CheckExact(digest) || PyBytes_GET_SIZE(digest)!=32) return;
    unsigned char *copy=PyMem_Malloc(key->used);
    if (!copy) return; /* Optional cache allocation never changes the result. */
    memcpy(copy,key->bytes,key->used);
    Entry *e=&s->cache[s->next];s->bytes-=(size_t)e->size;
    PyMem_Free(e->bytes);Py_XDECREF(e->digest);
    e->bytes=copy;e->size=(Py_ssize_t)key->used;e->hash=hash;e->digest=Py_NewRef(digest);
    s->bytes+=key->used;s->next=(s->next+1)%CACHE_SLOTS;
    if (s->entries<CACHE_SLOTS)s->entries++;
}

static int string_size(PyObject *v,Py_ssize_t low,Py_ssize_t high) {
    return v && PyUnicode_CheckExact(v) && PyUnicode_GET_LENGTH(v)>=low && PyUnicode_GET_LENGTH(v)<=high;
}
static int text(PyObject *v,const char *expected) {
    return v && PyUnicode_CheckExact(v) && PyUnicode_CompareWithASCIIString(v,expected)==0;
}
static int bounded_int(PyObject *v,long long low,long long high,long long *out) {
    if (!v || !PyLong_CheckExact(v)) return 0;
    long long n=PyLong_AsLongLong(v);
    if (PyErr_Occurred()) { PyErr_Clear();return 0; }
    if (n<low || n>high) return 0;
    if (out) *out=n;
    return 1;
}
static int uint64_value(PyObject *v,uint64_t *out) {
    if (!v || !PyLong_CheckExact(v)) return 0;
    unsigned long long n=PyLong_AsUnsignedLongLong(v);
    if (PyErr_Occurred()) { PyErr_Clear();return 0; }
    if (out) *out=(uint64_t)n;
    return 1;
}
static int clock_value(PyObject *v,double *out) {
    if (!v || !(PyLong_CheckExact(v) || PyFloat_CheckExact(v))) return 0;
    double n=PyFloat_AsDouble(v);
    if (PyErr_Occurred()) { PyErr_Clear();return 0; }
    if (!isfinite(n) || n<0 || n>=1e15) return 0;
    *out=n;return 1;
}
static int remaining(uint64_t ttl,double now) {
    double n=(double)ttl-now;
    return n>0 && n<=604800;
}
static int hex_identity(PyObject *v,Py_ssize_t size) {
    if (!string_size(v,size,size)) return 0;
    for (Py_ssize_t i=0;i<size;i++) {
        Py_UCS4 c=PyUnicode_READ_CHAR(v,i);
        if (!((c>='a' && c<='f') || (c>='0' && c<='9'))) return 0;
    }
    return 1;
}
static int scalar(State *s,PyObject *v) {
    if (v==Py_None || PyBool_Check(v)) return 1;
    if (PyUnicode_CheckExact(v)) return PyUnicode_GET_LENGTH(v)<=512;
    if (PyLong_CheckExact(v)) {
        return PyObject_RichCompareBool(v,s->minint,Py_GT)==1 && PyObject_RichCompareBool(v,s->maxint,Py_LT)==1;
    }
    if (PyFloat_CheckExact(v)) return isfinite(PyFloat_AS_DOUBLE(v)) && fabs(PyFloat_AS_DOUBLE(v))<18446744073709551616.0;
    return 0;
}

static PyObject *compute_key(PyObject *module,PyObject *event,int reuse) {
    State *s=PyModule_GetState(module);
    if (!PyDict_CheckExact(event) || PyDict_Size(event)<1 || PyDict_Size(event)>64) Py_RETURN_NONE;
    PyObject *h[HEADERS];
    for (int i=0;i<HEADERS;i++) {
        h[i]=PyDict_GetItemWithError(event,s->headers[i]);
        if (!h[i]) { if (PyErr_Occurred()) return NULL; Py_RETURN_NONE; }
    }
    long long qtype,flags;
    if (!text(h[VERSION],"unbound-1.26.1-scalars-v1") || !text(h[CALLBACK],"cache")
        || !bounded_int(h[QTYPE],1,28,&qtype) || (qtype!=1 && qtype!=28)
        || !bounded_int(h[QCLASS],1,1,NULL) || !bounded_int(h[RCODE],0,0,NULL)
        || h[BLOCK]!=Py_False || !PyBool_Check(h[BYPASS]) || !bounded_int(h[DROPPED],0,0,NULL)
        || !hex_identity(h[PROFILE],64) || !hex_identity(h[GENERATION],32)
        || !string_size(h[QNAME],1,254)) Py_RETURN_NONE;
    double now,mono,basis,started;
    if (!clock_value(h[UTC],&now) || !clock_value(h[MONO],&mono) || !clock_value(h[BASIS],&basis)
        || !clock_value(h[STARTED],&started) || started>mono || now-basis<0 || now-basis>=5) Py_RETURN_NONE;
    uint64_t ttl;
    if (!bounded_int(h[FLAGS],0,65535,&flags) || !(flags&0x8000) || (flags&15)
        || !bounded_int(h[COUNT],1,64,NULL) || !uint64_value(h[TTL],&ttl) || !remaining(ttl,now)
        || !PyList_CheckExact(h[RECORDS]) || PyList_GET_SIZE(h[RECORDS])<1 || PyList_GET_SIZE(h[RECORDS])>64) Py_RETURN_NONE;
    for (Py_ssize_t i=0;i<PyList_GET_SIZE(h[RECORDS]);i++) {
        PyObject *row=PyList_GET_ITEM(h[RECORDS],i),*r[FIELDS];
        if (!PyDict_CheckExact(row) || PyDict_Size(row)!=FIELDS) Py_RETURN_NONE;
        for (int j=0;j<FIELDS;j++) {
            r[j]=PyDict_GetItemWithError(row,s->fields[j]);
            if (!r[j]) { if (PyErr_Occurred()) return NULL; Py_RETURN_NONE; }
        }
        /* A wire-decoded record always has exact built-in string keys. */
        Py_ssize_t position=0;PyObject *key,*value;
        while (PyDict_Next(row,&position,&key,&value)) if (!PyUnicode_CheckExact(key)) Py_RETURN_NONE;
        if (!string_size(r[NAME],1,254) || !(text(r[TYPE],"A") || text(r[TYPE],"AAAA") || text(r[TYPE],"CNAME"))
            || !text(r[CLASS],"IN") || !bounded_int(r[RRFLAGS],0,0,NULL)
            || !uint64_value(r[ID],NULL) || !uint64_value(r[RRTTL],NULL) || !uint64_value(r[RAWTTL],&ttl)
            || !remaining(ttl,now) || !string_size(r[HEX],1,510)) Py_RETURN_NONE;
    }
    PyObject *value=PyDict_New();
    if (!value) return NULL;
    Py_ssize_t position=0;PyObject *key,*item;
    while (PyDict_Next(event,&position,&key,&item)) {
        if (!string_size(key,0,64)) goto unsupported;
        int observed=0;
        for (int i=0;i<6;i++) if (PyUnicode_Compare(key,s->observations[i])==0) { observed=1;break; }
        if (observed) continue;
        if (PyUnicode_Compare(key,s->headers[RECORDS])!=0 && !scalar(s,item)) goto unsupported;
        if (PyDict_SetItem(value,key,item)<0) { Py_DECREF(value);return NULL; }
    }
    /* All original validation, including current remaining TTLs, ran above.
     * This cache avoids only serialization/hash computation for an exact
     * immutable value snapshot. It never qualifies a receipt or a PF mapping.
     */
    Signature sig;int cacheable=reuse?signature(s,value,&sig):0;uint64_t hash_value=0;
    if (cacheable<0) { Py_DECREF(value);return NULL; }
    if (cacheable) {
        hash_value=signature_hash(&sig);PyObject *hit=cached(s,&sig,hash_value);
        if (hit) { Py_DECREF(value);return hit; }
    } else if (reuse) s->bypassed++;
    PyObject *encoded=PyObject_CallOneArg(s->encode,value);Py_DECREF(value);
    if (!encoded) return NULL;
    PyObject *raw=PyUnicode_AsUTF8String(encoded);Py_DECREF(encoded);
    if (!raw) return NULL;
    if (PyBytes_GET_SIZE(raw)>16384) { Py_DECREF(raw);Py_RETURN_NONE; }
    PyObject *hash=PyObject_CallOneArg(s->sha256,raw);Py_DECREF(raw);
    if (!hash) return NULL;
    PyObject *result=PyObject_CallMethodNoArgs(hash,s->digest);Py_DECREF(hash);
    if (result && cacheable) remember(s,&sig,hash_value,result);
    return result;
unsupported:
    Py_DECREF(value);
    if (PyErr_Occurred()) return NULL;
    Py_RETURN_NONE;
}

static int traverse(PyObject *module,visitproc visit,void *arg) {
    State *s=PyModule_GetState(module);
    if (!s) return 0;
    for (int i=0;i<HEADERS;i++) Py_VISIT(s->headers[i]);
    for (int i=0;i<FIELDS;i++) Py_VISIT(s->fields[i]);
    for (int i=0;i<6;i++) Py_VISIT(s->observations[i]);
    Py_VISIT(s->encode);Py_VISIT(s->sha256);Py_VISIT(s->digest);Py_VISIT(s->maxint);Py_VISIT(s->minint);
    for (unsigned int i=0;i<s->entries;i++) Py_VISIT(s->cache[i].digest);
    return 0;
}
static int clear(PyObject *module) {
    State *s=PyModule_GetState(module);
    if (!s) return 0;
    for (int i=0;i<HEADERS;i++) Py_CLEAR(s->headers[i]);
    for (int i=0;i<FIELDS;i++) Py_CLEAR(s->fields[i]);
    for (int i=0;i<6;i++) Py_CLEAR(s->observations[i]);
    Py_CLEAR(s->encode);Py_CLEAR(s->sha256);Py_CLEAR(s->digest);Py_CLEAR(s->maxint);Py_CLEAR(s->minint);
    for (unsigned int i=0;i<s->entries;i++) {
        Py_CLEAR(s->cache[i].digest);PyMem_Free(s->cache[i].bytes);s->cache[i].bytes=NULL;s->cache[i].size=0;
    }
    s->entries=0;s->next=0;s->bytes=0;
    return 0;
}
static PyObject *cache_info(PyObject *module,PyObject *unused) {
    (void)unused;State *s=PyModule_GetState(module);
    return Py_BuildValue("{s:K,s:K,s:K,s:I,s:n,s:i,s:i}","hits",(unsigned long long)s->hits,
        "misses",(unsigned long long)s->misses,"bypassed",(unsigned long long)s->bypassed,
        "entries",s->entries,"bytes",(Py_ssize_t)s->bytes,"capacity",CACHE_SLOTS,"signature_limit",CACHE_BYTES);
}
static PyObject *answer_key(PyObject *module,PyObject *event) { return compute_key(module,event,1); }
static PyObject *uncached_key(PyObject *module,PyObject *event) { return compute_key(module,event,0); }
static PyMethodDef methods[]={{"key",answer_key,METH_O,"Exact cached-answer identity or None; no trust or policy decision."},
    {"uncached_key",uncached_key,METH_O,"Equivalent digest without serialization reuse; diagnostic comparison only."},
    {"cache_info",cache_info,METH_NOARGS,"Bounded serialization cache counters; no answer contents."},{NULL,NULL,0,NULL}};
static void release(void *module) { clear((PyObject *)module); }
static struct PyModuleDef definition={PyModuleDef_HEAD_INIT,"_dnsalias_confirmationkey",NULL,sizeof(State),methods,NULL,traverse,clear,release};
PyMODINIT_FUNC PyInit__dnsalias_confirmationkey(void) {
    PyObject *module=PyModule_Create(&definition);
    if (!module) return NULL;
    State *s=PyModule_GetState(module);
    PyObject *json=NULL,*hashlib=NULL,*encoder_type=NULL,*encoder=NULL,*args=NULL,*kwargs=NULL,*separators=NULL;
    for (int i=0;i<HEADERS;i++) if (!(s->headers[i]=PyUnicode_InternFromString(headers[i]))) goto error;
    for (int i=0;i<FIELDS;i++) if (!(s->fields[i]=PyUnicode_InternFromString(fields[i]))) goto error;
    for (int i=0;i<6;i++) if (!(s->observations[i]=PyUnicode_InternFromString(observations[i]))) goto error;
    s->digest=PyUnicode_InternFromString("digest");
    s->maxint=PyLong_FromString("18446744073709551616",NULL,10);s->minint=PyLong_FromString("-18446744073709551616",NULL,10);
    if (!s->digest || !s->maxint || !s->minint) goto error;
    json=PyImport_ImportModule("json");hashlib=PyImport_ImportModule("hashlib");
    if (!json || !hashlib) goto error;
    encoder_type=PyObject_GetAttrString(json,"JSONEncoder");s->sha256=PyObject_GetAttrString(hashlib,"sha256");
    args=PyTuple_New(0);kwargs=PyDict_New();separators=Py_BuildValue("(ss)",",",":");
    if (!encoder_type || !s->sha256 || !args || !kwargs || !separators) goto error;
    if (PyDict_SetItemString(kwargs,"sort_keys",Py_True)<0 || PyDict_SetItemString(kwargs,"allow_nan",Py_False)<0
        || PyDict_SetItemString(kwargs,"separators",separators)<0) goto error;
    encoder=PyObject_Call(encoder_type,args,kwargs);
    if (!encoder || !(s->encode=PyObject_GetAttrString(encoder,"encode"))) goto error;
    if (PyModule_AddIntConstant(module,"KEY_PROTOCOL",1)<0
        || PyModule_AddStringConstant(module,"KEY_ABI","cpython-311-freebsd-amd64")<0) goto error;
    Py_DECREF(json);Py_DECREF(hashlib);Py_DECREF(encoder_type);Py_DECREF(encoder);Py_DECREF(args);Py_DECREF(kwargs);Py_DECREF(separators);
    return module;
error:
    Py_XDECREF(json);Py_XDECREF(hashlib);Py_XDECREF(encoder_type);Py_XDECREF(encoder);Py_XDECREF(args);Py_XDECREF(kwargs);Py_XDECREF(separators);
    Py_DECREF(module);return NULL;
}
