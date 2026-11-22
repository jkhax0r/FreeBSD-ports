/* Inactive Unbound scalar-extraction experiment. Public Python attribute API
 * only: no SWIG layout assumptions, retained callback objects, I/O or PF writes.
 * Small exact-scalar replies only; None requests the existing Python fallback.
 * Admission, TTL normalization, authentication and add-before-reply are unchanged.
 */
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <math.h>
#include <string.h>

#define KEYS(X) \
 X(callback) X(time) X(monotonic) X(resolver_generation) X(generation_started_monotonic) \
 X(profile_id) X(callback_start_time) X(policy_block_registry_match) X(policy_bypass_client) \
 X(qname) X(qtype) X(qclass) X(rcode) X(client) X(client_port) X(reply_ttl) X(reply_flags) \
 X(reply_security) X(resolver_now) X(module_finished) X(return_rcode) X(has_return_message) \
 X(same_return_reply) X(answer_rrsets) X(authority_rrsets) X(additional_rrsets) X(records) \
 X(ttl_basis) X(extractor_version) X(qname_str) X(addr) X(port) X(ttl) X(flags) X(security) \
 X(qinfo) X(return_msg) X(env) X(now) X(ext_state) X(rep) X(this) X(an_numrrsets) \
 X(ns_numrrsets) X(ar_numrrsets) X(rrsets) X(rk) X(type_str) X(entry) X(data) X(count) \
 X(dname_str) X(rrset_class_str) X(id) X(rr_data) X(rr_ttl) X(name) X(type) X(class) \
 X(rrset_id) X(rrset_flags) X(rrset_ttl) X(raw_ttl) X(rdata_hex)
#define ENUM(name) K_##name,
enum { KEYS(ENUM) K_COUNT };
#undef ENUM
#define NAME(name) #name,
static const char *key_names[] = { KEYS(NAME) };
#undef NAME
typedef struct { PyObject *keys[K_COUNT], *basis, *version; } State;
/* At most 64 RRsets, 12 records and a fixed header: bounded references. */
typedef struct { State *state; PyObject *owned[1024]; unsigned count; } Pool;
static PyObject *hold(Pool *p, PyObject *v) {
    if (!v) return NULL;
    if (p->count == 1024) {
        Py_DECREF(v); PyErr_SetString(PyExc_ValueError, "extraction reference bound"); return NULL;
    }
    p->owned[p->count++] = v; return v;
}
static void release(Pool *p) { while (p->count) Py_DECREF(p->owned[--p->count]); }
static PyObject *attr(Pool *p, PyObject *obj, int key) {
    return hold(p, PyObject_GetAttr(obj, p->state->keys[key]));
}
static PyObject *item(Pool *p, PyObject *obj, Py_ssize_t n) {
    PyObject *index=PyLong_FromSsize_t(n); if (!index) return NULL;
    PyObject *v=PyObject_GetItem(obj,index); Py_DECREF(index); return hold(p,v);
}
static int put(Pool *p, PyObject *dict, int key, PyObject *value) {
    return value && PyDict_SetItem(dict,p->state->keys[key],value)==0;
}
static int invalid(const char *message) { PyErr_SetString(PyExc_ValueError,message); return 0; }
static int integer(PyObject *o, uint64_t maximum) {
    if (!o) return 0;
    if (!PyLong_CheckExact(o)) return invalid("invalid scalar integer");
    unsigned long long n=PyLong_AsUnsignedLongLong(o);
    if (PyErr_Occurred()) { PyErr_Clear(); return invalid("invalid scalar integer"); }
    return n<=maximum || invalid("invalid scalar integer");
}
static int text_value(PyObject *o, Py_ssize_t limit) {
    if (!o) return 0;
    return (PyUnicode_CheckExact(o) && PyUnicode_GET_LENGTH(o)>=1 && PyUnicode_GET_LENGTH(o)<=limit)
        || invalid("invalid scalar text");
}
static int clock_value(PyObject *o, double *value) {
    if (!o) return 0;
    if (!PyLong_CheckExact(o) && !PyFloat_CheckExact(o)) return invalid("invalid scalar clock");
    *value=PyFloat_AsDouble(o); if (PyErr_Occurred()) return 0;
    return (isfinite(*value) && *value>=0) || invalid("invalid scalar clock");
}
static int hex_text(PyObject *o, Py_ssize_t length) {
    if (!PyUnicode_CheckExact(o) || PyUnicode_GET_LENGTH(o)!=length) return 0;
    for (Py_ssize_t i=0;i<length;i++) {
        Py_UCS4 c=PyUnicode_READ_CHAR(o,i);
        if (!((c>='a' && c<='f') || (c>='0' && c<='9'))) return 0;
    }
    return 1;
}
static int equal_ascii(PyObject *o,const char *s) { return PyUnicode_CompareWithASCIIString(o,s)==0; }
static PyObject *hex_bytes(Pool *p,const unsigned char *raw,Py_ssize_t n) {
    static const char digits[]="0123456789abcdef";
    char out[510]; for (Py_ssize_t i=0;i<n;i++) { out[2*i]=digits[raw[i]>>4];out[2*i+1]=digits[raw[i]&15]; }
    return hold(p,PyUnicode_FromStringAndSize(out,n*2));
}

static PyObject *extract_small(PyObject *module,PyObject *args,PyObject *kwargs) {
    PyObject *kind,*qinfo,*qstate,*rep,*rcode,*peer=Py_None,*callback_start=Py_None;
    PyObject *module_id=NULL,*finished=NULL,*utc=NULL,*mono=NULL,*generation=NULL,*started=NULL,*profile=NULL,*unbound=NULL;
    PyObject *blocked=Py_False,*bypassed=Py_False;
    static char *names[]={"kind","qinfo","qstate","rep","rcode","peer","callback_start_time",
        "module_id","finished_state","observed_utc","observed_monotonic","resolver_generation",
        "generation_started_monotonic","profile_id","unbound_version","policy_block_registry_match","policy_bypass_client",NULL};
    if (!PyArg_ParseTupleAndKeywords(args,kwargs,"OOOOO|$OOOOOOOOOOOO:extract_small",names,
        &kind,&qinfo,&qstate,&rep,&rcode,&peer,&callback_start,&module_id,&finished,&utc,&mono,&generation,&started,&profile,&unbound,&blocked,&bypassed)) return NULL;
    if (!module_id || !finished || !utc || !mono || !generation || !started || !profile || !unbound) {
        PyErr_SetString(PyExc_TypeError,"explicit extraction context required");return NULL;
    }
    Pool pool={.state=PyModule_GetState(module),.count=0}; Pool *p=&pool;
    PyObject *result=NULL,*event=NULL,*records=NULL,*v,*q,*returned=Py_None,*obj,*other,*left,*right;
    double utc_value,mono_value,started_value,unused;
#define GET(target,object,key) do { target=attr(p,object,K_##key); if (!target) goto error; } while (0)
#define PUT(dict,key,value) do { if (!put(p,dict,K_##key,value)) goto error; } while (0)
#define INT(object,key,maximum) do { GET(v,object,key); if (!integer(v,maximum)) goto error; } while (0)
#define ATTR_INT(dict,dest,object,source,maximum) do { INT(object,source,maximum); PUT(dict,dest,v); } while (0)
#define ATTR_TEXT(dict,dest,object,source,maximum) do { GET(v,object,source); if (!text_value(v,maximum)) goto error; PUT(dict,dest,v); } while (0)
    if (!PyUnicode_CheckExact(unbound) || !PyUnicode_CheckExact(kind)) goto fallback;
    if (!equal_ascii(unbound,"1.26.1")) { invalid("unqualified Unbound version");goto error; }
    if (!hex_text(profile,64)) { invalid("explicit profile required");goto error; }
    if (!hex_text(generation,32)) { invalid("explicit epoch required");goto error; }
    if (!equal_ascii(kind,"resolved") && !equal_ascii(kind,"cache") && !equal_ascii(kind,"local") && !equal_ascii(kind,"servfail")) { invalid("unknown callback");goto error; }
    if (!PyBool_Check(blocked) || !PyBool_Check(bypassed)) { invalid("explicit optional policy evidence required");goto error; }
    if (!integer(module_id,63) || !integer(finished,255) || !clock_value(utc,&utc_value)
        || !clock_value(mono,&mono_value) || !clock_value(started,&started_value)) goto error;
    /* Preserve Python's exact comparison for potentially very large integers. */
    int later=PyObject_RichCompareBool(started,mono,Py_GT);if (later<0) goto error;
    if (later) { invalid("generation starts after observation");goto error; }
    q=qinfo;if (q==Py_None) GET(q,qstate,qinfo);
    if (qstate!=Py_None) GET(returned,qstate,return_msg);
    event=hold(p,PyDict_New()); records=hold(p,PyList_New(0)); if (!event || !records) goto error;
    PUT(event,callback,kind); PUT(event,time,utc); PUT(event,monotonic,mono);
    PUT(event,resolver_generation,generation); PUT(event,generation_started_monotonic,started); PUT(event,profile_id,profile);
    if (callback_start!=Py_None && !clock_value(callback_start,&unused)) goto error;
    PUT(event,callback_start_time,callback_start); PUT(event,policy_block_registry_match,blocked);PUT(event,policy_bypass_client,bypassed);
    ATTR_TEXT(event,qname,q,qname_str,254); ATTR_INT(event,qtype,q,qtype,65535); ATTR_INT(event,qclass,q,qclass,65535);
    if (!integer(rcode,65535)) goto error;PUT(event,rcode,rcode);
    if (peer==Py_None) { PUT(event,client,Py_None);PUT(event,client_port,Py_None); }
    else { ATTR_TEXT(event,client,peer,addr,45);ATTR_INT(event,client_port,peer,port,65535); }
    if (rep==Py_None) { PUT(event,reply_ttl,Py_None);PUT(event,reply_flags,Py_None);PUT(event,reply_security,Py_None); }
    else { ATTR_INT(event,reply_ttl,rep,ttl,INT64_MAX);ATTR_INT(event,reply_flags,rep,flags,65535);ATTR_INT(event,reply_security,rep,security,255); }
    if (qstate==Py_None) { PUT(event,resolver_now,Py_None);PUT(event,module_finished,Py_None);PUT(event,return_rcode,Py_None);PUT(event,has_return_message,Py_None); }
    else {
        GET(obj,qstate,env);GET(v,obj,now);if (!clock_value(v,&unused)) goto error;PUT(event,resolver_now,v);
        GET(obj,qstate,ext_state);v=item(p,obj,(Py_ssize_t)PyLong_AsLong(module_id));if (!v) goto error;
        other=hold(p,PyObject_RichCompare(v,finished,Py_EQ));if (!other) goto error;if (!PyBool_Check(other)) goto fallback;
        PUT(event,module_finished,other);ATTR_INT(event,return_rcode,qstate,return_rcode,65535);
        PUT(event,has_return_message,returned!=Py_None?Py_True:Py_False);
    }
    if (rep!=Py_None && returned!=Py_None) {
        GET(v,rep,this);left=hold(p,PyNumber_Long(v));if (!left) goto error;
        GET(obj,returned,rep);GET(v,obj,this);right=hold(p,PyNumber_Long(v));if (!right) goto error;
        other=hold(p,PyObject_RichCompare(left,right,Py_EQ));if (!other) goto error;PUT(event,same_return_reply,other);
    } else PUT(event,same_return_reply,Py_None);
    unsigned answer_count=0;
    if (rep==Py_None) {
        v=hold(p,PyLong_FromLong(0));PUT(event,answer_rrsets,v);PUT(event,authority_rrsets,v);PUT(event,additional_rrsets,v);
    } else {
        INT(rep,an_numrrsets,64);answer_count=(unsigned)PyLong_AsLong(v);PUT(event,answer_rrsets,v);
        ATTR_INT(event,authority_rrsets,rep,ns_numrrsets,65535);ATTR_INT(event,additional_rrsets,rep,ar_numrrsets,65535);
    }
    PUT(event,records,records);PUT(event,ttl_basis,p->state->basis);PUT(event,extractor_version,p->state->version);
    if (answer_count) {
        PyObject *rrsets;GET(rrsets,rep,rrsets);
        for (unsigned i=0;i<answer_count;i++) {
            PyObject *rr=item(p,rrsets,i),*key,*type,*data,*owner,*rrclass,*identity,*flags,*ttl,*raw_records,*ttls;
            if (!rr) goto error;GET(key,rr,rk);GET(type,key,type_str);
            if (!PyUnicode_CheckExact(type)) goto fallback;
            if (!equal_ascii(type,"A") && !equal_ascii(type,"AAAA") && !equal_ascii(type,"CNAME")) continue;
            GET(obj,rr,entry);GET(data,obj,data);INT(data,count,128);unsigned count=(unsigned)PyLong_AsLong(v);
            if (count+PyList_GET_SIZE(records)>12) goto fallback;
            GET(owner,key,dname_str);if (!text_value(owner,254)) goto error;
            GET(rrclass,key,rrset_class_str);if (!text_value(rrclass,16)) goto error;
            GET(identity,rr,id);GET(flags,key,flags);GET(ttl,data,ttl);
            if (!integer(identity,UINT64_MAX) || !integer(flags,UINT32_MAX) || !integer(ttl,INT64_MAX)) goto error;
            if (!count) continue;
            GET(raw_records,data,rr_data);GET(ttls,data,rr_ttl);
            for (unsigned j=0;j<count;j++) {
                PyObject *raw=item(p,raw_records,j);if (!raw) goto error;
                if (!PyBytes_CheckExact(raw)) goto fallback;
                Py_ssize_t length=PyBytes_GET_SIZE(raw);
                if (length<2 || length>257) { invalid("RDATA length bound");goto error; }
                const unsigned char *bytes=(const unsigned char *)PyBytes_AS_STRING(raw);
                if ((((unsigned)bytes[0]<<8)|bytes[1])!=length-2) { invalid("RDATA prefix mismatch");goto error; }
                PyObject *record=hold(p,PyDict_New());if (!record) goto error;
                PUT(record,name,owner);PUT(record,type,type);PUT(record,class,rrclass);PUT(record,rrset_id,identity);
                PUT(record,rrset_flags,flags);PUT(record,rrset_ttl,ttl);
                v=item(p,ttls,j);if (!integer(v,INT64_MAX)) goto error;PUT(record,raw_ttl,v);
                PUT(record,rdata_hex,hex_bytes(p,bytes+2,length-2));if (PyList_Append(records,record)<0) goto error;
            }
        }
    }
    /* Same proven small-scalar JSON size bound as replyextract.py. */
    result=Py_NewRef(event);goto done;
fallback:
    result=Py_NewRef(Py_None);goto done;
error:
    if (!PyErr_Occurred()) PyErr_SetString(PyExc_RuntimeError,"native extraction failed");
done:
    release(p);return result;
#undef GET
#undef PUT
#undef INT
#undef ATTR_INT
#undef ATTR_TEXT
}
static int traverse(PyObject *module,visitproc visit,void *arg) {
    State *s=PyModule_GetState(module);for (int i=0;i<K_COUNT;i++) Py_VISIT(s->keys[i]);Py_VISIT(s->basis);Py_VISIT(s->version);return 0;
}
static int clear(PyObject *module) {
    State *s=PyModule_GetState(module);for (int i=0;i<K_COUNT;i++) Py_CLEAR(s->keys[i]);Py_CLEAR(s->basis);Py_CLEAR(s->version);return 0;
}
static void free_module(void *module) { clear((PyObject *)module); }
static PyMethodDef methods[]={{"extract_small",(PyCFunction)(void (*)(void))extract_small,METH_VARARGS|METH_KEYWORDS,"Bounded scalar extraction, or None for Python fallback."},{NULL,NULL,0,NULL}};
static struct PyModuleDef definition={PyModuleDef_HEAD_INIT,"_dnsalias_replyextract",NULL,sizeof(State),methods,NULL,traverse,clear,free_module};
PyMODINIT_FUNC PyInit__dnsalias_replyextract(void) {
#if !defined(__FreeBSD__) || !defined(__amd64__) || PY_MAJOR_VERSION != 3 || PY_MINOR_VERSION != 11
    PyErr_SetString(PyExc_ImportError,"private qualified FreeBSD amd64 Python3.11 only");return NULL;
#endif
    PyObject *module=PyModule_Create(&definition);if (!module) return NULL;State *s=PyModule_GetState(module);
    for (int i=0;i<K_COUNT;i++) { s->keys[i]=PyUnicode_InternFromString(key_names[i]);if (!s->keys[i]) goto error; }
    s->basis=PyUnicode_FromString("unverified");s->version=PyUnicode_FromString("unbound-1.26.1-scalars-v1");
    if (!s->basis || !s->version) goto error;
    if (PyModule_AddStringConstant(module,"EXTRACT_ABI","cpython-311-freebsd-amd64")<0
        || PyModule_AddIntConstant(module,"EXTRACT_PROTOCOL",1)<0) goto error;
    return module;
error:
    Py_DECREF(module);return NULL;
}
