#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "aes256.h"
#include "ige256.h"
#include "ctr256.h"
#include "cbc256.h"

#define DESCRIPTION "Fast and Portable Cryptography Extension Library for Pyrogram"

// AES-256-IGE mode
static PyObject *ige(PyObject *self, PyObject *args, uint8_t encrypt) {
    Py_buffer data, key, iv;
    uint8_t *buf;
    PyObject *out;

    if (!PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv))
        return NULL;

    if (data.len == 0 || data.len % 16 != 0 || key.len != 32 || iv.len != 32) {
        PyErr_SetString(PyExc_ValueError, "Invalid data, key, or IV size");
        return NULL;
    }

    // Allocate memory for output buffer
    buf = (uint8_t *)malloc(data.len);
    if (!buf) {
        PyErr_SetString(PyExc_MemoryError, "Memory allocation failed");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
        ige256(data.buf, buf, data.len, key.buf, iv.buf, encrypt);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&iv);

    out = Py_BuildValue("y#", buf, data.len);
    free(buf);

    return out;
}

static PyObject *ige256_encrypt(PyObject *self, PyObject *args) {
    return ige(self, args, 1);
}

static PyObject *ige256_decrypt(PyObject *self, PyObject *args) {
    return ige(self, args, 0);
}

// AES-256-CTR mode
static PyObject *ctr256_encrypt(PyObject *self, PyObject *args) {
    Py_buffer data, key, iv, state;
    uint8_t *buf;
    PyObject *out;

    if (!PyArg_ParseTuple(args, "y*y*y*y*", &data, &key, &iv, &state))
        return NULL;

    if (data.len == 0 || key.len != 32 || iv.len != 16 || state.len != 1 || *(uint8_t *)state.buf > 15) {
        PyErr_SetString(PyExc_ValueError, "Invalid data, key, IV, or state");
        return NULL;
    }

    // Allocate memory for output buffer
    buf = (uint8_t *)malloc(data.len);
    if (!buf) {
        PyErr_SetString(PyExc_MemoryError, "Memory allocation failed");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
        ctr256(data.buf, buf, data.len, key.buf, iv.buf, state.buf);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&iv);
    PyBuffer_Release(&state);

    out = Py_BuildValue("y#", buf, data.len);
    free(buf);

    return out;
}

// AES-256-CBC mode
static PyObject *cbc(PyObject *self, PyObject *args, uint8_t encrypt) {
    Py_buffer data, key, iv;
    uint8_t *buf;
    PyObject *out;

    if (!PyArg_ParseTuple(args, "y*y*y*", &data, &key, &iv))
        return NULL;

    if (data.len == 0 || data.len % 16 != 0 || key.len != 32 || iv.len != 16) {
        PyErr_SetString(PyExc_ValueError, "Invalid data, key, or IV size");
        return NULL;
    }

    // Allocate memory for output buffer
    buf = (uint8_t *)malloc(data.len);
    if (!buf) {
        PyErr_SetString(PyExc_MemoryError, "Memory allocation failed");
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
        cbc256(data.buf, buf, data.len, key.buf, iv.buf, encrypt);
    Py_END_ALLOW_THREADS

    PyBuffer_Release(&data);
    PyBuffer_Release(&key);
    PyBuffer_Release(&iv);

    out = Py_BuildValue("y#", buf, data.len);
    free(buf);

    return out;
}

static PyObject *cbc256_encrypt(PyObject *self, PyObject *args) {
    return cbc(self, args, 1);
}

static PyObject *cbc256_decrypt(PyObject *self, PyObject *args) {
    return cbc(self, args, 0);
}

// Documentation strings
PyDoc_STRVAR(ige256_encrypt_docs, "ige256_encrypt(data, key, iv)\nAES-256-IGE Encryption");
PyDoc_STRVAR(ige256_decrypt_docs, "ige256_decrypt(data, key, iv)\nAES-256-IGE Decryption");
PyDoc_STRVAR(ctr256_encrypt_docs, "ctr256_encrypt(data, key, iv, state)\nAES-256-CTR Encryption");
PyDoc_STRVAR(ctr256_decrypt_docs, "ctr256_decrypt(data, key, iv, state)\nAES-256-CTR Decryption");
PyDoc_STRVAR(cbc256_encrypt_docs, "cbc256_encrypt(data, key, iv)\nAES-256-CBC Encryption");
PyDoc_STRVAR(cbc256_decrypt_docs, "cbc256_decrypt(data, key, iv)\nAES-256-CBC Decryption");

// Method definitions
static PyMethodDef methods[] = {
    {"ige256_encrypt", (PyCFunction)ige256_encrypt, METH_VARARGS, ige256_encrypt_docs},
    {"ige256_decrypt", (PyCFunction)ige256_decrypt, METH_VARARGS, ige256_decrypt_docs},
    {"ctr256_encrypt", (PyCFunction)ctr256_encrypt, METH_VARARGS, ctr256_encrypt_docs},
    {"cbc256_encrypt", (PyCFunction)cbc256_encrypt, METH_VARARGS, cbc256_encrypt_docs},
    {"cbc256_decrypt", (PyCFunction)cbc256_decrypt, METH_VARARGS, cbc256_decrypt_docs},
    {NULL, NULL, 0, NULL}
};

// Module definition
static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT,
    "TgCrypto",
    DESCRIPTION,
    -1,
    methods
};

// Module initialization function
PyMODINIT_FUNC PyInit_tgcrypto(void) {
    return PyModule_Create(&module);
}
