/* Optional combined-generation metadata checks. Fresh fstat/lstat/
 * fstatat calls for both pinned generation directories and the reply socket.
 * No caching, path adoption, unlink, write, permission change or FD ownership.
 */
#include <Python.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

static int u32(PyObject *object, uint32_t *out) {
    if (!PyLong_CheckExact(object)) return 0;
    unsigned long long n=PyLong_AsUnsignedLongLong(object);
    if (PyErr_Occurred()) { PyErr_Clear(); return 0; }
    if (n>UINT32_MAX) return 0;
    *out=(uint32_t)n; return 1;
}
static int identity(PyObject *object, uint64_t out[2]) {
    if (!PyTuple_CheckExact(object) || PyTuple_GET_SIZE(object)!=2) return 0;
    for (int i=0; i<2; i++) {
        PyObject *item=PyTuple_GET_ITEM(object,i);
        if (!PyLong_CheckExact(item)) return 0;
        int overflow=0;
        long long signed_value=PyLong_AsLongLongAndOverflow(item,&overflow);
        if (PyErr_Occurred()) { PyErr_Clear(); return 0; }
        if (overflow<0) return 0;
        if (!overflow) out[i]=(uint64_t)signed_value;
        else {
            out[i]=PyLong_AsUnsignedLongLong(item);
            if (PyErr_Occurred()) { PyErr_Clear(); return 0; }
        }
    }
    return 1;
}
static int directory_ok(const struct stat *s,uint32_t uid,uint32_t gid,
    uint32_t mode,const uint64_t id[2]) {
    return S_ISDIR(s->st_mode) && s->st_uid==uid && s->st_gid==gid
        && (s->st_mode&07777)==mode && (uint64_t)s->st_dev==id[0]
        && (uint64_t)s->st_ino==id[1];
}
static int generation_identity(PyObject *object,uint64_t out[2],uint32_t uid,uint32_t gid) {
    if (!PyTuple_CheckExact(object) || PyTuple_GET_SIZE(object)!=5) return 0;
    PyObject *pair=PyTuple_GetSlice(object,0,2);
    if (!pair) return 0;
    int valid=identity(pair,out);Py_DECREF(pair);
    uint32_t owner,group,mode;
    return valid && u32(PyTuple_GET_ITEM(object,2),&owner)
        && u32(PyTuple_GET_ITEM(object,3),&group) && u32(PyTuple_GET_ITEM(object,4),&mode)
        && owner==uid && group==gid && mode==0700;
}
static PyObject *generation_check(PyObject *self,PyObject *args) {
    (void)self;
    int parent_fd,generation_fd,endpoint_fd;
    PyObject *parent_path,*generation_path,*parent_id,*generation_id,*endpoint_id,*socket_id,*uid_o,*gid_o;
    if (!PyArg_ParseTuple(args,"iUiUiOOOOOO:check",&parent_fd,&parent_path,&generation_fd,&generation_path,
            &endpoint_fd,&uid_o,&gid_o,&parent_id,&generation_id,&endpoint_id,&socket_id)) return NULL;
    uint32_t uid,gid;uint64_t pi[2],gi[2],ei[2],si[2];Py_ssize_t pn,gn;
    const char *pp=PyUnicode_AsUTF8AndSize(parent_path,&pn),*gp=PyUnicode_AsUTF8AndSize(generation_path,&gn);
    if (!pp || !gp) return NULL;
    if (parent_fd<0 || generation_fd<0 || endpoint_fd<0 || pn<1 || pn>68 || gn!=pn+35 || gn>103
        || pp[0]!='/' || memchr(pp,0,(size_t)pn) || memchr(gp,0,(size_t)gn)
        || memcmp(gp,pp,(size_t)pn) || memcmp(gp+pn,"/g-",3)
        || !u32(uid_o,&uid) || !u32(gid_o,&gid) || !generation_identity(parent_id,pi,uid,gid)
        || !generation_identity(generation_id,gi,uid,gid) || !identity(endpoint_id,ei)
        || !identity(socket_id,si) || memcmp(gi,ei,sizeof(gi))) {
        PyErr_SetString(PyExc_ValueError,"complete captured generation and endpoint identities required");return NULL;
    }
    for (Py_ssize_t i=pn+3;i<gn;i++) if (!((gp[i]>='0' && gp[i]<='9') || (gp[i]>='a' && gp[i]<='f'))) {
        PyErr_SetString(PyExc_ValueError,"exact generation directory required");return NULL;
    }
    struct stat po,pnamed,go,eo,gnamed,sk;int valid=0;
    /* The generation's two FDs remain checked independently. Their common
     * pathname needs one fresh lstat rather than two; all owner/mode/inode
     * and socket checks are retained. No cached validity or slower schedule. */
    Py_BEGIN_ALLOW_THREADS
    if (!fstat(parent_fd,&po) && !fstatat(AT_FDCWD,pp,&pnamed,AT_SYMLINK_NOFOLLOW)
        && directory_ok(&po,uid,gid,0700,pi) && directory_ok(&pnamed,uid,gid,0700,pi)
        && !fstat(generation_fd,&go) && !fstat(endpoint_fd,&eo)
        && !fstatat(AT_FDCWD,gp,&gnamed,AT_SYMLINK_NOFOLLOW)
        && directory_ok(&go,uid,gid,0700,gi) && directory_ok(&eo,uid,gid,0700,gi)
        && directory_ok(&gnamed,uid,gid,0700,gi)
        && !fstatat(endpoint_fd,"replies.sock",&sk,AT_SYMLINK_NOFOLLOW)) {
        valid=S_ISSOCK(sk.st_mode) && sk.st_uid==uid && sk.st_gid==gid && (sk.st_mode&07777)==0600
            && sk.st_nlink==1 && (uint64_t)sk.st_dev==si[0] && (uint64_t)sk.st_ino==si[1];
    }
    Py_END_ALLOW_THREADS
    return PyBool_FromLong(valid);
}
static PyMethodDef generation_methods[]={
    {"check",generation_check,METH_VARARGS,"Fresh checks of the captured generation and reply endpoint."},
    {NULL,NULL,0,NULL}
};
static struct PyModuleDef generation_module={PyModuleDef_HEAD_INIT,"_dnsalias_generation",NULL,-1,generation_methods};
PyMODINIT_FUNC PyInit__dnsalias_generation(void) {
    PyObject *module=PyModule_Create(&generation_module);
    if (!module) return NULL;
    if (PyModule_AddStringConstant(module,"GENERATION_ABI","cpython-311-freebsd-amd64")<0
        || PyModule_AddIntConstant(module,"GENERATION_PROTOCOL",1)<0) {
        Py_DECREF(module);return NULL;
    }
    return module;
}
