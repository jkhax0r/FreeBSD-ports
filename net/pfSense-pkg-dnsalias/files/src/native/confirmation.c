/* Optional FreeBSD/amd64 CPython 3.11 confirmation-page component.
 * No DNS, PF, hooks, file creation/removal, descriptor transfer or recovery.
 * Caller must own file creation/enrollment and verify process/source lifetimes.
 * A hit here is NOT permission to bypass the deployed helper.
 *
 * All shared words are lock-free sequentially-consistent atomics. Slot and
 * authority sequence checks reject overlap, partial publication and ABA.
 * Readers map PROT_READ only. A separately enrolled root revoker may fence the
 * page permanently but cannot publish. Only its creating process may publish.
 */
#include <Python.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/capsicum.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdatomic.h>
#include <errno.h>
#include <math.h>
#include <string.h>
#include <time.h>

#if !defined(__FreeBSD__) || !defined(__x86_64__) || PY_MAJOR_VERSION != 3 || PY_MINOR_VERSION != 11
#error "This inactive ABI is qualified only for FreeBSD amd64 CPython 3.11"
#endif
_Static_assert(ATOMIC_LONG_LOCK_FREE==2 && sizeof(uint64_t)==8,"lock-free 64-bit atomics required");
#ifndef DNSALIAS_CONFIRMATION_NAME
#define DNSALIAS_CONFIRMATION_NAME "_dnsalias_confirmation"
#define DNSALIAS_CONFIRMATION_INIT PyInit__dnsalias_confirmation
#endif

typedef _Atomic(uint64_t) Word;
#define SLOT_COUNT 1024
#define SLOT_WAYS 4
#define PAGE_ABI 3
#define SCOPE_WORDS 16384
#define SCOPE_BITS (SCOPE_WORDS*64)
typedef struct { Word sequence,key[4],deadline,expires,epoch; } Slot;
typedef struct { Word magic,abi,token[4],writer_pid,epoch,fenced,scope_sequence,scope_ready,padding[5]; } Header;
typedef struct { _Alignas(64) Header header; Slot slots[SLOT_COUNT]; Word scope[SCOPE_WORDS]; } Page;
_Static_assert(sizeof(Slot)==64 && sizeof(Header)==128 && sizeof(Page)==196736,"fixed page layout required");
enum { ROLE_WRITER=1,ROLE_READER=2,ROLE_REVOKER=3 };
#define MAGIC UINT64_C(0x4441434f4e463031)
#define BUILDING UINT64_C(0x4441434f4e46494e)
#define LIMIT UINT64_C(0x7ffffffffffffffe)
#define CAPSULE "dnsalias.confirmation.lab.3"
typedef struct {
    Page *page;
    int fd,role,bad;
    pid_t creator,writer;
    uint64_t token[4],last_epoch;
} Mapping;

static uint64_t load(Word *value) { return atomic_load_explicit(value,memory_order_seq_cst); }
static void store(Word *value,uint64_t next) { atomic_store_explicit(value,next,memory_order_seq_cst); }
static uint64_t bits(double value) { uint64_t out;memcpy(&out,&value,8);return out; }
static double number(uint64_t value) { double out;memcpy(&out,&value,8);return out; }
static int clocks(double *mono,double *utc) {
    struct timespec a,b;
    if (clock_gettime(CLOCK_MONOTONIC,&a) || clock_gettime(CLOCK_REALTIME,&b)) {
        PyErr_SetFromErrno(PyExc_OSError);return 0;
    }
    *mono=(double)a.tv_sec+(double)a.tv_nsec/1e9;
    *utc=(double)b.tv_sec+(double)b.tv_nsec/1e9;
    return 1;
}
static int digest(PyObject *obj,uint64_t output[4]) {
    if (!PyBytes_CheckExact(obj) || PyBytes_GET_SIZE(obj)!=32) {
        PyErr_SetString(PyExc_ValueError,"exact 32-byte digest required");return 0;
    }
    memcpy(output,PyBytes_AS_STRING(obj),32);
    if (!(output[0]|output[1]|output[2]|output[3])) {
        PyErr_SetString(PyExc_ValueError,"zero digest is reserved");return 0;
    }
    return 1;
}
static int integer(PyObject *obj,int *out) {
    if (!PyLong_CheckExact(obj)) { PyErr_SetString(PyExc_ValueError,"exact nonnegative integer required");return 0; }
    long value=PyLong_AsLong(obj);
    if (PyErr_Occurred()) return 0;
    if (value<0 || value>INT_MAX) { PyErr_SetString(PyExc_ValueError,"bounded integer required");return 0; }
    *out=(int)value;return 1;
}
static int finite_clock(PyObject *obj,double *out) {
    if (!PyFloat_CheckExact(obj) && !PyLong_CheckExact(obj)) {
        PyErr_SetString(PyExc_ValueError,"explicit numeric expiry required");return 0;
    }
    *out=PyFloat_AsDouble(obj);
    if (PyErr_Occurred()) return 0;
    if (!isfinite(*out) || *out<0) { PyErr_SetString(PyExc_ValueError,"finite nonnegative expiry required");return 0; }
    return 1;
}
static int immutable(Mapping *map) {
    if (!map->page || map->bad) return 0;
    Header *h=&map->page->header;
    int valid=load(&h->magic)==MAGIC && load(&h->abi)==PAGE_ABI && load(&h->writer_pid)==(uint64_t)map->writer;
    for (int i=0;i<4;i++) valid=valid && load(&h->token[i])==map->token[i];
    if (!valid) map->bad=1;
    return valid;
}
static int unfenced(Mapping *map) {
    if (!immutable(map)) return 0;
    if (load(&map->page->header.fenced)) { map->bad=1;return 0; }
    return 1;
}
static uint64_t epoch(Mapping *map) {
    if (!unfenced(map)) return 0;
    uint64_t current=load(&map->page->header.epoch);
    if (current>LIMIT || current<map->last_epoch) { map->bad=1;return 0; }
    map->last_epoch=current;
    return current && !(current&1) ? current : 0;
}
static Mapping *mapping(PyObject *obj,int role) {
    Mapping *map=PyCapsule_GetPointer(obj,CAPSULE);
    if (!map) return NULL;
    if (!map->page || map->creator!=getpid() || (role && map->role!=role)) {
        PyErr_SetString(PyExc_ValueError,"live same-process mapping with correct capability required");return NULL;
    }
    if (map->role!=ROLE_READER && geteuid()!=0) {
        PyErr_SetString(PyExc_PermissionError,"root publisher/revoker required");return NULL;
    }
    return map;
}
static void release(Mapping *map) {
    if (map->page) {
        if (map->role==ROLE_WRITER && map->creator==getpid()) store(&map->page->header.fenced,1);
        munmap(map->page,sizeof(Page));map->page=NULL;
    }
    if (map->fd>=0) { close(map->fd);map->fd=-1; }
}
static void destroy(PyObject *obj) {
    Mapping *map=PyCapsule_GetPointer(obj,CAPSULE);
    if (map) { release(map);PyMem_Free(map); }
    else PyErr_Clear();
}
static PyObject *attach(PyObject *args,int role) {
    PyObject *fd_obj,*token_obj,*pid_obj=NULL;int fd,writer=0;
    if (role==ROLE_WRITER) {
        if (!PyArg_ParseTuple(args,"OO",&fd_obj,&token_obj)) return NULL;
        writer=getpid();
    } else if (!PyArg_ParseTuple(args,"OOO",&fd_obj,&token_obj,&pid_obj)) return NULL;
    uint64_t token[4];
    if (!integer(fd_obj,&fd) || !digest(token_obj,token) || (pid_obj && !integer(pid_obj,&writer))) return NULL;
    if (writer<=0) { PyErr_SetString(PyExc_ValueError,"exact enrolled writer PID required");return NULL; }
    if (role!=ROLE_READER && geteuid()!=0) { PyErr_SetString(PyExc_PermissionError,"root capability required");return NULL; }
    struct stat info;int flags=fcntl(fd,F_GETFL);
    if (flags<0 || fstat(fd,&info)) return PyErr_SetFromErrno(PyExc_OSError);
    if (!S_ISREG(info.st_mode) || info.st_uid!=0 || info.st_gid!=0 || info.st_nlink!=1
        || (info.st_mode&07777)!=0444 || info.st_size!=(off_t)sizeof(Page)
        || (flags&O_ACCMODE)!=(role==ROLE_READER?O_RDONLY:O_RDWR)) {
        PyErr_SetString(PyExc_ValueError,"root-owned single-link fixed-size mode0444 file and exact access mode required");return NULL;
    }
    if (role==ROLE_WRITER) {
        unsigned char blank[sizeof(Page)];ssize_t size=pread(fd,blank,sizeof(blank),0);
        if (size!=(ssize_t)sizeof(blank)) { PyErr_SetString(PyExc_ValueError,"complete fresh zero file required");return NULL; }
        for (size_t i=0;i<sizeof(blank);i++) if (blank[i]) {
            PyErr_SetString(PyExc_ValueError,"existing confirmation page cannot be adopted");return NULL;
        }
    }
    Mapping *map=PyMem_Calloc(1,sizeof(*map));
    if (!map) return PyErr_NoMemory();
    map->fd=-1;map->role=role;map->creator=getpid();map->writer=writer;memcpy(map->token,token,32);
    map->fd=fcntl(fd,F_DUPFD_CLOEXEC,0);
    if (map->fd<0) { PyMem_Free(map);return PyErr_SetFromErrno(PyExc_OSError); }
    void *address=mmap(NULL,sizeof(Page),PROT_READ|(role==ROLE_READER?0:PROT_WRITE),MAP_SHARED,map->fd,0);
    if (address==MAP_FAILED) { close(map->fd);PyMem_Free(map);return PyErr_SetFromErrno(PyExc_OSError); }
    map->page=address;
    if (role==ROLE_WRITER) {
        uint64_t expected=0;
        if (!atomic_compare_exchange_strong_explicit(&map->page->header.magic,&expected,BUILDING,memory_order_seq_cst,memory_order_seq_cst)) {
            /* A failed claimant must not fence the owner's page. */
            map->role=ROLE_READER;release(map);PyMem_Free(map);
            PyErr_SetString(PyExc_ValueError,"page was already claimed");return NULL;
        }
        Header *h=&map->page->header;
        store(&h->abi,PAGE_ABI);store(&h->writer_pid,(uint64_t)writer);
        for (int i=0;i<4;i++) store(&h->token[i],token[i]);
        store(&h->magic,MAGIC);
    } else if (!immutable(map)) {
        release(map);PyMem_Free(map);PyErr_SetString(PyExc_ValueError,"foreign or incomplete page identity");return NULL;
    }
    PyObject *capsule=PyCapsule_New(map,CAPSULE,destroy);
    if (!capsule) { release(map);PyMem_Free(map); }
    return capsule;
}
static PyObject *create_writer(PyObject *self,PyObject *args) { (void)self;return attach(args,ROLE_WRITER); }
static PyObject *open_reader(PyObject *self,PyObject *args) { (void)self;return attach(args,ROLE_READER); }
static PyObject *open_revoker(PyObject *self,PyObject *args) { (void)self;return attach(args,ROLE_REVOKER); }
static PyObject *page_revoke(PyObject *self,PyObject *obj) {
    (void)self;Mapping *map=mapping(obj,ROLE_WRITER);if (!map) return NULL;
    if (!unfenced(map)) { PyErr_SetString(PyExc_ValueError,"publisher is fenced or changed");return NULL; }
    uint64_t old=load(&map->page->header.epoch);
    if ((old&1) || old>=LIMIT) { PyErr_SetString(PyExc_ValueError,"stable unexhausted epoch required");return NULL; }
    store(&map->page->header.epoch,old+1);map->last_epoch=old+1;
    return PyLong_FromUnsignedLongLong(old+1);
}
static PyObject *commit(PyObject *self,PyObject *obj) {
    (void)self;Mapping *map=mapping(obj,ROLE_WRITER);if (!map) return NULL;
    if (!unfenced(map)) { PyErr_SetString(PyExc_ValueError,"publisher is fenced or changed");return NULL; }
    uint64_t old=load(&map->page->header.epoch);
    if (!(old&1) || old>=LIMIT) { PyErr_SetString(PyExc_ValueError,"prior revocation and unexhausted epoch required");return NULL; }
    store(&map->page->header.epoch,old+1);map->last_epoch=old+1;
    if (!unfenced(map)) { PyErr_SetString(PyExc_ValueError,"fenced during publication");return NULL; }
    return PyLong_FromUnsignedLongLong(old+1);
}
static PyObject *fence(PyObject *self,PyObject *obj) {
    (void)self;Mapping *map=mapping(obj,ROLE_REVOKER);if (!map) return NULL;
    if (!immutable(map)) { PyErr_SetString(PyExc_ValueError,"revoker page changed");return NULL; }
    uint64_t old=atomic_exchange_explicit(&map->page->header.fenced,1,memory_order_seq_cst);
    return PyBool_FromLong(!old);
}
static PyObject *publish(PyObject *self,PyObject *args) {
    (void)self;PyObject *obj,*key_obj,*mono_obj,*utc_obj;
    if (!PyArg_ParseTuple(args,"OOOO",&obj,&key_obj,&mono_obj,&utc_obj)) return NULL;
    Mapping *map=mapping(obj,ROLE_WRITER);if (!map) return NULL;
    uint64_t key[4];double deadline,expires,mono,utc;
    if (!digest(key_obj,key) || !finite_clock(mono_obj,&deadline) || !finite_clock(utc_obj,&expires) || !clocks(&mono,&utc)) return NULL;
    if (deadline<=mono || expires<=utc || deadline-mono>604800 || expires-utc>604800) {
        PyErr_SetString(PyExc_ValueError,"live bounded TTL horizons required");return NULL;
    }
    uint64_t generation=epoch(map);
    if (!generation) { PyErr_SetString(PyExc_ValueError,"stable unfenced epoch required");return NULL; }
    /* Four bounded candidates prevent two unrelated digests from repeatedly
     * evicting each other. Never probe beyond this group or grow the page. */
    size_t base=(key[0]&(SLOT_COUNT-1))&~(size_t)(SLOT_WAYS-1);
    Slot *slot=NULL,*available=NULL,*oldest=NULL;double earliest=INFINITY;
    for (size_t way=0;way<SLOT_WAYS;way++) {
        Slot *candidate=&map->page->slots[base+way];uint64_t sequence=load(&candidate->sequence);
        if ((sequence&1) || sequence>=LIMIT) { PyErr_SetString(PyExc_ValueError,"slot incomplete or exhausted");return NULL; }
        uint64_t found[4];for (int i=0;i<4;i++) found[i]=load(&candidate->key[i]);
        if (sequence && !memcmp(key,found,32)) slot=candidate;
        double end=number(load(&candidate->deadline)),wall=number(load(&candidate->expires));
        if (!isfinite(end) || !isfinite(wall)) { PyErr_SetString(PyExc_ValueError,"slot expiry changed");return NULL; }
        if (!available && (!sequence || load(&candidate->epoch)!=generation || end<=mono || wall<=utc)) available=candidate;
        if (end<earliest) { earliest=end;oldest=candidate; }
    }
    if (!slot) slot=available?available:oldest;
    if (!slot) { PyErr_SetString(PyExc_ValueError,"no qualified bounded slot");return NULL; }
    uint64_t serial=load(&slot->sequence);
    if ((serial&1) || serial>=LIMIT) { PyErr_SetString(PyExc_ValueError,"slot incomplete or exhausted");return NULL; }
    store(&slot->sequence,serial+1);
    for (int i=0;i<4;i++) store(&slot->key[i],key[i]);
    store(&slot->deadline,bits(deadline));store(&slot->expires,bits(expires));store(&slot->epoch,generation);
    store(&slot->sequence,serial+2);
    if (epoch(map)!=generation) { PyErr_SetString(PyExc_ValueError,"revoked during slot publication");return NULL; }
    Py_RETURN_NONE;
}
static PyObject *lookup(PyObject *self,PyObject *args) {
    (void)self;PyObject *obj,*key_obj;
    if (!PyArg_ParseTuple(args,"OO",&obj,&key_obj)) return NULL;
    Mapping *map=mapping(obj,ROLE_READER);if (!map) return NULL;
    uint64_t key[4];if (!digest(key_obj,key)) return NULL;
    uint64_t generation=epoch(map);if (!generation) Py_RETURN_NONE;
    size_t base=(key[0]&(SLOT_COUNT-1))&~(size_t)(SLOT_WAYS-1);
    for (size_t way=0;way<SLOT_WAYS;way++) {
        Slot *slot=&map->page->slots[base+way];uint64_t serial=load(&slot->sequence);
        if (!serial || (serial&1) || serial>LIMIT) continue;
        uint64_t found[4];for (int i=0;i<4;i++) found[i]=load(&slot->key[i]);
        double deadline=number(load(&slot->deadline)),expires=number(load(&slot->expires));
        uint64_t stamp=load(&slot->epoch);double mono,utc;
        if (memcmp(key,found,32) || stamp!=generation) continue;
        if (!clocks(&mono,&utc)) return NULL;
        if (!isfinite(deadline) || !isfinite(expires) || deadline<=mono || expires<=utc
            || deadline-mono>604800 || expires-utc>604800) Py_RETURN_NONE;
        if (load(&slot->sequence)!=serial || epoch(map)!=generation) Py_RETURN_NONE;
        return Py_BuildValue("Kdd",(unsigned long long)generation,deadline,expires);
    }
    Py_RETURN_NONE;
}
/* Monotone conservative interest filter. Only the enrolled writer adds names.
 * Four SHA-256 lanes select bits. Collisions cause extra ACK waits, never a
 * false claim of absence. Bits are not cleared during this page's lifetime.
 * A sequence brackets additions so a reader cannot use a partial update.
 * Scope keys distinguish exact owners from wildcard suffixes in Python. */
static int scope_maybe(Page *page,const uint64_t key[4]) {
    for (int i=0;i<4;i++) {
        uint64_t bit=key[i]&(SCOPE_BITS-1);
        if (!(load(&page->scope[bit/64])&(UINT64_C(1)<<(bit%64)))) return 0;
    }
    return 1;
}
static PyObject *scope_add(PyObject *self,PyObject *args) {
    (void)self;PyObject *obj,*keys;
    if (!PyArg_ParseTuple(args,"OO",&obj,&keys)) return NULL;
    Mapping *map=mapping(obj,ROLE_WRITER);if (!map) return NULL;
    if (!unfenced(map)) { PyErr_SetString(PyExc_ValueError,"scope publisher is fenced");return NULL; }
    if (!PyTuple_CheckExact(keys) || PyTuple_GET_SIZE(keys)>4096) {
        PyErr_SetString(PyExc_ValueError,"bounded tuple of interest digests required");return NULL;
    }
    int changed=0;
    for (Py_ssize_t n=0;n<PyTuple_GET_SIZE(keys);n++) {
        uint64_t key[4];if (!digest(PyTuple_GET_ITEM(keys,n),key)) return NULL;
        if (!scope_maybe(map->page,key)) changed=1;
    }
    if (!changed) Py_RETURN_NONE;
    Word *sequence=&map->page->header.scope_sequence;uint64_t serial=load(sequence);
    if ((serial&1) || serial>=LIMIT) { PyErr_SetString(PyExc_ValueError,"scope sequence exhausted");return NULL; }
    store(sequence,serial+1);
    for (Py_ssize_t n=0;n<PyTuple_GET_SIZE(keys);n++) {
        uint64_t key[4];memcpy(key,PyBytes_AS_STRING(PyTuple_GET_ITEM(keys,n)),32);
        for (int i=0;i<4;i++) {
            uint64_t bit=key[i]&(SCOPE_BITS-1);
            atomic_fetch_or_explicit(&map->page->scope[bit/64],UINT64_C(1)<<(bit%64),memory_order_seq_cst);
        }
    }
    store(sequence,serial+2);
    if (!unfenced(map)) { PyErr_SetString(PyExc_ValueError,"scope fenced during update");return NULL; }
    Py_RETURN_NONE;
}
static PyObject *scope_ready(PyObject *self,PyObject *args) {
    (void)self;PyObject *obj,*ready;
    if (!PyArg_ParseTuple(args,"OO",&obj,&ready)) return NULL;
    Mapping *map=mapping(obj,ROLE_WRITER);if (!map) return NULL;
    if (!PyBool_Check(ready) || !unfenced(map)) {
        PyErr_SetString(PyExc_ValueError,"explicit scope readiness and live publisher required");return NULL;
    }
    Word *sequence=&map->page->header.scope_sequence;uint64_t serial=load(sequence);
    if ((serial&1) || serial>=LIMIT) { PyErr_SetString(PyExc_ValueError,"scope sequence exhausted");return NULL; }
    store(sequence,serial+1);store(&map->page->header.scope_ready,ready==Py_True);
    store(sequence,serial+2);Py_RETURN_NONE;
}
static PyObject *scope_absent(PyObject *self,PyObject *args) {
    (void)self;PyObject *obj,*keys;
    if (!PyArg_ParseTuple(args,"OO",&obj,&keys)) return NULL;
    Mapping *map=mapping(obj,ROLE_READER);if (!map) return NULL;
    if (!PyTuple_CheckExact(keys) || PyTuple_GET_SIZE(keys)<1 || PyTuple_GET_SIZE(keys)>512) {
        PyErr_SetString(PyExc_ValueError,"bounded nonempty tuple of candidate digests required");return NULL;
    }
    uint64_t generation=epoch(map),serial=load(&map->page->header.scope_sequence);
    if (!generation || !serial || (serial&1) || serial>LIMIT || !load(&map->page->header.scope_ready)) Py_RETURN_NONE;
    for (Py_ssize_t n=0;n<PyTuple_GET_SIZE(keys);n++) {
        uint64_t key[4];if (!digest(PyTuple_GET_ITEM(keys,n),key)) return NULL;
        if (scope_maybe(map->page,key)) Py_RETURN_NONE;
    }
    if (epoch(map)!=generation || load(&map->page->header.scope_sequence)!=serial
        || !load(&map->page->header.scope_ready)) Py_RETURN_NONE;
    return Py_BuildValue("KK",(unsigned long long)generation,(unsigned long long)serial);
}
static PyObject *current_epoch(PyObject *self,PyObject *obj) {
    (void)self;Mapping *map=mapping(obj,0);if (!map) return NULL;
    uint64_t value=epoch(map);if (!value) Py_RETURN_NONE;
    return PyLong_FromUnsignedLongLong(value);
}
static PyObject *close_mapping(PyObject *self,PyObject *obj) {
    (void)self;Mapping *map=PyCapsule_GetPointer(obj,CAPSULE);if (!map) return NULL;
    if (map->creator!=getpid()) { PyErr_SetString(PyExc_ValueError,"inherited mapping cannot be controlled");return NULL; }
    release(map);Py_RETURN_NONE;
}
/* Startup-only watch capabilities. Keep all read/write/lookup/mmap/fchdir
 * authority out of the resolver even when watching an ancestor outside its
 * chroot. Rights belong to the duplicate descriptor; the owner's original
 * audit descriptor must remain unaffected. No queue or transfer is created. */
static int watch_fd(PyObject *obj,int *fd) {
    if (!PyLong_CheckExact(obj)) {
        PyErr_SetString(PyExc_TypeError,"exact file descriptor required");return 0;
    }
    long value=PyLong_AsLong(obj);
    if (value==-1 && PyErr_Occurred()) return 0;
    if (value<0 || value>INT_MAX) {
        PyErr_SetString(PyExc_ValueError,"valid file descriptor required");return 0;
    }
    *fd=(int)value;return 1;
}
static int watch_rights(int fd) {
    cap_rights_t wanted,actual;
    cap_rights_init(&wanted,CAP_EVENT,CAP_FSTAT);
    if (cap_rights_get(fd,&actual)) return -1;
    return memcmp(&wanted,&actual,sizeof(wanted))==0;
}
static PyObject *watch_restrict(PyObject *self,PyObject *obj) {
    (void)self;int source;
    if (!watch_fd(obj,&source)) return NULL;
    if (geteuid()!=0) { PyErr_SetString(PyExc_ValueError,"root watch owner required");return NULL; }
    struct stat st;int flags=fcntl(source,F_GETFL);
    if (flags<0 || fstat(source,&st)) return PyErr_SetFromErrno(PyExc_OSError);
    if ((flags&O_ACCMODE)!=O_RDONLY || !(S_ISREG(st.st_mode)||S_ISDIR(st.st_mode))) {
        PyErr_SetString(PyExc_ValueError,"read-only regular file or directory required");return NULL;
    }
    int fd=fcntl(source,F_DUPFD_CLOEXEC,0);
    if (fd<0) return PyErr_SetFromErrno(PyExc_OSError);
    cap_rights_t wanted;cap_rights_init(&wanted,CAP_EVENT,CAP_FSTAT);
    if (cap_rights_limit(fd,&wanted)) {
        int error=errno;close(fd);errno=error;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    int qualified=watch_rights(fd);
    if (qualified!=1) {
        int error=qualified<0?errno:EINVAL;close(fd);errno=error;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    return PyLong_FromLong(fd);
}
static PyObject *watch_check(PyObject *self,PyObject *obj) {
    (void)self;int fd;if (!watch_fd(obj,&fd)) return NULL;
    int result=watch_rights(fd);
    if (result<0) return PyErr_SetFromErrno(PyExc_OSError);
    return PyBool_FromLong(result);
}
static PyMethodDef methods[]={
    {"create_writer",create_writer,METH_VARARGS,"Claim a caller-owned fresh zero page; root only."},
    {"open_reader",open_reader,METH_VARARGS,"Read-only mapping bound to token and writer PID."},
    {"open_revoker",open_revoker,METH_VARARGS,"Root-only permanent-fence capability."},
    {"revoke",page_revoke,METH_O,"Revoke before changes; old receipts immediately become unusable."},
    {"commit",commit,METH_O,"Publish a new stable epoch after synchronization."},
    {"fence",fence,METH_O,"Permanently disable reuse before independent cleanup."},
    {"publish",publish,METH_VARARGS,"Publish one digest and its two existing TTL horizons."},
    {"lookup",lookup,METH_VARARGS,"Return a coherent live receipt or None; no authority by itself."},
    {"scope_add",scope_add,METH_VARARGS,"Add conservative interests before dependency or policy changes."},
    {"scope_ready",scope_ready,METH_VARARGS,"Mark a completely seeded conservative scope."},
    {"scope_absent",scope_absent,METH_VARARGS,"Prove all supplied names absent from the stable interest filter."},
    {"epoch",current_epoch,METH_O,"Read the stable epoch or None."},
    {"close",close_mapping,METH_O,"Release owned mapping/fd; writer closure fences the page."},
    {"watch_restrict",watch_restrict,METH_O,"Root-only duplicate restricted to vnode events and fstat."},
    {"watch_check",watch_check,METH_O,"Require exactly vnode-event and fstat capabilities."},
    {NULL,NULL,0,NULL}};
static struct PyModuleDef module={PyModuleDef_HEAD_INIT,DNSALIAS_CONFIRMATION_NAME,NULL,-1,methods,NULL,NULL,NULL,NULL};
PyMODINIT_FUNC DNSALIAS_CONFIRMATION_INIT(void) {
    PyObject *result=PyModule_Create(&module);if (!result) return NULL;
    if (PyModule_AddStringConstant(result,"CONFIRMATION_ABI","cpython-311-freebsd-amd64")<0
        || PyModule_AddIntConstant(result,"CONFIRMATION_PROTOCOL",1)<0
        || PyModule_AddIntConstant(result,"WATCH_FD_ABI",1)<0
        || PyModule_AddIntConstant(result,"PAGE_SIZE",sizeof(Page))<0 || PyModule_AddIntConstant(result,"SLOTS",SLOT_COUNT)<0
        || PyModule_AddIntConstant(result,"WAYS",SLOT_WAYS)<0 || PyModule_AddIntConstant(result,"PAGE_ABI",PAGE_ABI)<0) {
        Py_DECREF(result);return NULL;
    }
    return result;
}
