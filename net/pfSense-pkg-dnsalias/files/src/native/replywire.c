/* Optional small-reply transport codec; activation belongs to the package.
 * Serialization confers no authority: native peer, profile, TTL, name and PF
 * validation still belong to the existing receiver. No files or system calls.
 * CPython 3.11 holds the GIL throughout these entry points.
 */
#include <Python.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

#if !defined(__FreeBSD__) || !defined(__x86_64__) || PY_MAJOR_VERSION != 3 || PY_MINOR_VERSION != 11
#error "Qualified codec target is FreeBSD amd64 CPython 3.11"
#endif
#ifndef DNSALIAS_WIRE_MODULE_NAME
#define DNSALIAS_WIRE_MODULE_NAME "_dnsalias_replywire"
#define DNSALIAS_WIRE_INIT PyInit__dnsalias_replywire
#endif

#define LIMIT 60000
#define RECORD_LIMIT 12
static const unsigned char magic[8] = {'D','A','R','W',1,0,0,0};
static const unsigned char ack_magic[8] = {'D','A','A','K',1,0,0,0};
static const char *status_names[] = {"applied","ignored","helper_error"};
static const char *header_names[] = {
    "callback", "time", "monotonic", "resolver_generation",
    "generation_started_monotonic", "profile_id", "callback_start_time",
    "policy_block_registry_match", "policy_bypass_client", "qname", "qtype",
    "qclass", "rcode", "client", "client_port", "reply_ttl", "reply_flags",
    "reply_security", "resolver_now", "module_finished", "return_rcode",
    "has_return_message", "same_return_reply", "answer_rrsets",
    "authority_rrsets", "additional_rrsets", "ttl_basis", "extractor_version",
    "transport_dropped_before", "request_id"
};
static const char *record_names[] = {
    "name", "type", "class", "rrset_id", "rrset_flags", "rrset_ttl",
    "raw_ttl", "rdata_hex"
};
#define HEADERS ((int)(sizeof(header_names)/sizeof(header_names[0])))
#define FIELDS ((int)(sizeof(record_names)/sizeof(record_names[0])))

typedef struct {
    PyObject *headers[HEADERS];
    PyObject *fields[FIELDS];
    PyObject *records_key;
    PyObject *status_key;
    PyObject *statuses[3];
    unsigned char scratch[LIMIT];
} ModuleState;

static int reserve(size_t pos, size_t count) { return count <= LIMIT && pos <= LIMIT-count; }
static int exact_string_keys(PyObject *dict) {
    Py_ssize_t pos=0; PyObject *key,*value;
    while (PyDict_Next(dict,&pos,&key,&value)) if (!PyUnicode_CheckExact(key)) return 0;
    return 1;
}
static void put64(unsigned char *p, uint64_t v) {
    for (int i=0; i<8; i++) p[i] = (unsigned char)(v >> (8*i));
}
static uint64_t get64(const unsigned char *p) {
    uint64_t v=0;
    for (int i=0; i<8; i++) v |= ((uint64_t)p[i]) << (8*i);
    return v;
}

/* Exact built-in scalars only. Unsupported input returns a fallback signal;
 * this codec never coerces objects or silently drops fields. */
static int scalar_write(unsigned char *out, size_t *pos, PyObject *value) {
    if (!reserve(*pos,1)) return 0;
    if (value == Py_None) { out[(*pos)++]=0; return 1; }
    if (value == Py_False) { out[(*pos)++]=1; return 1; }
    if (value == Py_True) { out[(*pos)++]=2; return 1; }
    if (PyLong_CheckExact(value)) {
        uint64_t bits;
        unsigned char tag=3;
        unsigned long long u=PyLong_AsUnsignedLongLong(value);
        if (PyErr_Occurred()) {
            PyErr_Clear();
            long long s=PyLong_AsLongLong(value);
            if (PyErr_Occurred()) { PyErr_Clear(); return 0; }
            bits=(uint64_t)s; tag=4;
        } else bits=(uint64_t)u;
        if (!reserve(*pos,9)) return 0;
        out[(*pos)++]=tag; put64(out+*pos,bits); *pos+=8; return 1;
    }
    if (PyFloat_CheckExact(value)) {
        double d=PyFloat_AS_DOUBLE(value); uint64_t bits;
        if (!isfinite(d) || !reserve(*pos,9)) return 0;
        memcpy(&bits,&d,8); out[(*pos)++]=5; put64(out+*pos,bits); *pos+=8; return 1;
    }
    if (PyUnicode_CheckExact(value)) {
        Py_ssize_t size;
        const char *text=PyUnicode_AsUTF8AndSize(value,&size);
        if (!text) { PyErr_Clear(); return 0; }
        if (size<0 || size>4096 || !reserve(*pos,(size_t)size+3)) return 0;
        out[(*pos)++]=6; out[(*pos)++]=(unsigned char)size; out[(*pos)++]=(unsigned char)(size>>8);
        memcpy(out+*pos,text,(size_t)size); *pos+=(size_t)size; return 1;
    }
    return 0;
}

static PyObject *pack(PyObject *module, PyObject *event) {
    ModuleState *s=PyModule_GetState(module);
    if (!PyDict_CheckExact(event) || PyDict_Size(event)!=HEADERS+1 || !exact_string_keys(event)) Py_RETURN_NONE;
    PyObject *records=PyDict_GetItemWithError(event,s->records_key);
    if (!records || !PyList_CheckExact(records)) { PyErr_Clear(); Py_RETURN_NONE; }
    Py_ssize_t count=PyList_GET_SIZE(records);
    if (count<0 || count>RECORD_LIMIT) Py_RETURN_NONE;
    size_t pos=sizeof(magic); memcpy(s->scratch,magic,sizeof(magic));
    s->scratch[pos++]=(unsigned char)count;
    for (int i=0; i<HEADERS; i++) {
        PyObject *value=PyDict_GetItemWithError(event,s->headers[i]);
        if (!value || !scalar_write(s->scratch,&pos,value)) { PyErr_Clear(); Py_RETURN_NONE; }
    }
    for (Py_ssize_t n=0; n<count; n++) {
        PyObject *row=PyList_GET_ITEM(records,n);
        if (!PyDict_CheckExact(row) || PyDict_Size(row)!=FIELDS || !exact_string_keys(row)) Py_RETURN_NONE;
        for (int i=0; i<FIELDS; i++) {
            PyObject *value=PyDict_GetItemWithError(row,s->fields[i]);
            if (!value || !scalar_write(s->scratch,&pos,value)) { PyErr_Clear(); Py_RETURN_NONE; }
        }
    }
    return PyBytes_FromStringAndSize((const char *)s->scratch,(Py_ssize_t)pos);
}

static PyObject *invalid(void) {
    PyErr_SetString(PyExc_ValueError,"invalid bounded reply wire record"); return NULL;
}
static PyObject *scalar_read(const unsigned char *raw, size_t size, size_t *pos) {
    if (*pos>=size) return invalid();
    unsigned char tag=raw[(*pos)++];
    if (tag==0) Py_RETURN_NONE;
    if (tag==1) Py_RETURN_FALSE;
    if (tag==2) Py_RETURN_TRUE;
    if (tag>=3 && tag<=5) {
        if (size-*pos<8) return invalid();
        uint64_t bits=get64(raw+*pos); *pos+=8;
        if (tag==3) return PyLong_FromUnsignedLongLong(bits);
        if (tag==4) return PyLong_FromLongLong((int64_t)bits);
        double d; memcpy(&d,&bits,8);
        if (!isfinite(d)) return invalid();
        return PyFloat_FromDouble(d);
    }
    if (tag==6) {
        if (size-*pos<2) return invalid();
        size_t length=(size_t)raw[*pos] | ((size_t)raw[*pos+1]<<8); *pos+=2;
        if (length>4096 || length>size-*pos) return invalid();
        PyObject *value=PyUnicode_DecodeUTF8((const char *)raw+*pos,(Py_ssize_t)length,"strict");
        *pos+=length; return value;
    }
    return invalid();
}
static int read_fields(PyObject *dict, PyObject **keys, int count,
                       const unsigned char *raw, size_t size, size_t *pos) {
    for (int i=0; i<count; i++) {
        PyObject *value=scalar_read(raw,size,pos);
        if (!value) return 0;
        int result=PyDict_SetItem(dict,keys[i],value); Py_DECREF(value);
        if (result<0) return 0;
    }
    return 1;
}
static PyObject *unpack(PyObject *module, PyObject *input) {
    ModuleState *s=PyModule_GetState(module);
    if (!PyBytes_CheckExact(input)) {
        PyErr_SetString(PyExc_TypeError,"exact bounded bytes required"); return NULL;
    }
    Py_ssize_t length=PyBytes_GET_SIZE(input);
    const unsigned char *raw=(const unsigned char *)PyBytes_AS_STRING(input);
    if (length<9 || length>LIMIT || memcmp(raw,magic,sizeof(magic))) return invalid();
    size_t pos=8,size=(size_t)length; unsigned int count=raw[pos++];
    if (count>RECORD_LIMIT) return invalid();
    PyObject *event=PyDict_New(), *records=NULL;
    if (!event || !read_fields(event,s->headers,HEADERS,raw,size,&pos)) goto error;
    records=PyList_New(count);
    if (!records) goto error;
    for (unsigned int n=0; n<count; n++) {
        PyObject *row=PyDict_New();
        if (!row || !read_fields(row,s->fields,FIELDS,raw,size,&pos)) { Py_XDECREF(row); goto error; }
        PyList_SET_ITEM(records,n,row);
    }
    if (pos!=size) { invalid(); goto error; }
    if (PyDict_SetItem(event,s->records_key,records)<0) goto error;
    Py_DECREF(records); return event;
error:
    Py_XDECREF(records); Py_XDECREF(event); return NULL;
}
static int hex_digit(unsigned char c) {
    if (c>='0' && c<='9') return c-'0';
    if (c>='a' && c<='f') return c-'a'+10;
    return -1;
}
static PyObject *pack_ack(PyObject *module, PyObject *ack) {
    ModuleState *s=PyModule_GetState(module);
    if (!PyDict_CheckExact(ack) || PyDict_Size(ack)!=2 || !exact_string_keys(ack)) Py_RETURN_NONE;
    PyObject *token=PyDict_GetItemWithError(ack,s->headers[HEADERS-1]);
    PyObject *status=PyDict_GetItemWithError(ack,s->status_key);
    if (!token || !status || !PyUnicode_CheckExact(token) || !PyUnicode_CheckExact(status)) { PyErr_Clear(); Py_RETURN_NONE; }
    Py_ssize_t length;
    const char *text=PyUnicode_AsUTF8AndSize(token,&length);
    if (!text) { PyErr_Clear(); Py_RETURN_NONE; }
    if (length!=32) Py_RETURN_NONE;
    unsigned char output[25];memcpy(output,ack_magic,8);
    for (int i=0;i<16;i++) {
        int a=hex_digit((unsigned char)text[i*2]),b=hex_digit((unsigned char)text[i*2+1]);
        if (a<0 || b<0) Py_RETURN_NONE;
        output[8+i]=(unsigned char)((a<<4)|b);
    }
    for (int i=0;i<3;i++) {
        int equal=PyUnicode_Compare(status,s->statuses[i]);
        if (equal==0) { output[24]=(unsigned char)(i+1);return PyBytes_FromStringAndSize((const char *)output,25); }
        if (PyErr_Occurred()) return NULL;
    }
    Py_RETURN_NONE;
}
static PyObject *unpack_ack(PyObject *module, PyObject *input) {
    ModuleState *s=PyModule_GetState(module);
    if (!PyBytes_CheckExact(input)) { PyErr_SetString(PyExc_TypeError,"exact acknowledgment bytes required");return NULL; }
    const unsigned char *raw=(const unsigned char *)PyBytes_AS_STRING(input);
    if (PyBytes_GET_SIZE(input)!=25 || memcmp(raw,ack_magic,8) || raw[24]<1 || raw[24]>3) return invalid();
    static const char hex[]="0123456789abcdef";
    char text[32];
    for (int i=0;i<16;i++) { text[i*2]=hex[raw[8+i]>>4];text[i*2+1]=hex[raw[8+i]&15]; }
    PyObject *out=PyDict_New(),*token=PyUnicode_FromStringAndSize(text,32);
    if (!out || !token) { Py_XDECREF(out);Py_XDECREF(token);return NULL; }
    if (PyDict_SetItem(out,s->headers[HEADERS-1],token)<0 || PyDict_SetItem(out,s->status_key,s->statuses[raw[24]-1])<0) {
        Py_DECREF(out);Py_DECREF(token);return NULL;
    }
    Py_DECREF(token);return out;
}
static int module_traverse(PyObject *module, visitproc visit, void *arg) {
    ModuleState *s=PyModule_GetState(module);
    for (int i=0;i<HEADERS;i++) Py_VISIT(s->headers[i]);
    for (int i=0;i<FIELDS;i++) Py_VISIT(s->fields[i]);
    Py_VISIT(s->records_key);Py_VISIT(s->status_key);
    for (int i=0;i<3;i++) Py_VISIT(s->statuses[i]);
    return 0;
}
static int module_clear(PyObject *module) {
    ModuleState *s=PyModule_GetState(module);
    for (int i=0;i<HEADERS;i++) Py_CLEAR(s->headers[i]);
    for (int i=0;i<FIELDS;i++) Py_CLEAR(s->fields[i]);
    Py_CLEAR(s->records_key);Py_CLEAR(s->status_key);
    for (int i=0;i<3;i++) Py_CLEAR(s->statuses[i]);
    return 0;
}
static PyMethodDef methods[] = {
    {"pack",pack,METH_O,"Return exact small-reply bytes, or None for the existing codec."},
    {"unpack",unpack,METH_O,"Decode a bounded small reply without granting trust."},
    {"pack_ack",pack_ack,METH_O,"Encode only an exact supported acknowledgment, or None."},
    {"unpack_ack",unpack_ack,METH_O,"Decode an acknowledgment; peer/token verification remains mandatory."},
    {NULL,NULL,0,NULL}
};
static struct PyModuleDef definition = {
    PyModuleDef_HEAD_INIT,DNSALIAS_WIRE_MODULE_NAME,NULL,sizeof(ModuleState),methods,
    NULL,module_traverse,module_clear,NULL
};
PyMODINIT_FUNC DNSALIAS_WIRE_INIT(void) {
    PyObject *module=PyModule_Create(&definition);
    if (!module) return NULL;
    ModuleState *s=PyModule_GetState(module);
    for (int i=0;i<HEADERS;i++) if (!(s->headers[i]=PyUnicode_InternFromString(header_names[i]))) goto error;
    for (int i=0;i<FIELDS;i++) if (!(s->fields[i]=PyUnicode_InternFromString(record_names[i]))) goto error;
    s->records_key=PyUnicode_InternFromString("records");
    if (!s->records_key) goto error;
    s->status_key=PyUnicode_InternFromString("status");
    if (!s->status_key) goto error;
    for (int i=0;i<3;i++) if (!(s->statuses[i]=PyUnicode_InternFromString(status_names[i]))) goto error;
    if (PyModule_AddIntConstant(module,"WIRE_PROTOCOL",1)<0
        || PyModule_AddStringConstant(module,"WIRE_ABI","cpython-311-freebsd-amd64")<0) goto error;
    return module;
error:
    Py_DECREF(module); return NULL;
}
