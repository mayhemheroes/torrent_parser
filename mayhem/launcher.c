/*
 * launcher.c -- a REAL libFuzzer target ELF that drives the Python harness.
 *
 * Mayhem requires the target `cmd:` to be an ELF (it rejects shell/script
 * wrappers), the gate checks each target binary for DWARF < 4 debug info, and
 * Mayhem's cloud coverage tracer only credits edges recorded by the SanCov
 * instrumentation compiled into the MAIN executable. A Python harness driven
 * by Atheris' own bundled libFuzzer therefore records 0 edges cloud-side.
 *
 * So this binary IS the libFuzzer target: it is linked with -fsanitize=fuzzer
 * against a private static CPython that build.sh compiles with
 * -fsanitize=fuzzer-no-link (inline 8-bit counters + PC table in this very
 * ELF). LLVMFuzzerInitialize boots the embedded interpreter and imports the
 * harness module; LLVMFuzzerTestOneInput hands each input to the module's
 * TestOneInput(bytes). Interpreter + harness execution paths show up as
 * ordinary native edges, exactly like any C libFuzzer target.
 *
 * The harness module directory/name are baked in via -DHARNESS_DIR/-DHARNESS_MOD.
 * An uncaught Python exception is a finding: print it and abort().
 */
#include <Python.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifndef HARNESS_DIR
#define HARNESS_DIR "/mayhem/mayhem"
#endif
#ifndef HARNESS_MOD
#define HARNESS_MOD "differential_fuzz"
#endif
#ifndef PYHOME
#define PYHOME "/opt/toolchains/python/cpython"
#endif

static PyObject *test_one_input;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    (void)argc;
    (void)argv;

    PyConfig config;
    PyConfig_InitPythonConfig(&config);
    config.parse_argv = 0;
    config.install_signal_handlers = 0;

    /* Pin the interpreter to the private CPython prefix; without this the
     * embedded runtime can resolve the SYSTEM stdlib, whose extension modules
     * don't match this build. */
    PyStatus status = PyConfig_SetBytesString(&config, &config.home, PYHOME);
    if (PyStatus_Exception(status)) {
        PyConfig_Clear(&config);
        Py_ExitStatusException(status);
    }

    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        Py_ExitStatusException(status);
    }

    if (PyRun_SimpleString(
            "import sys\n"
            "sys.path.insert(0, \"" HARNESS_DIR "\")\n") != 0) {
        fprintf(stderr, "launcher: failed to extend sys.path\n");
        abort();
    }

    PyObject *mod = PyImport_ImportModule(HARNESS_MOD);
    if (!mod) {
        PyErr_Print();
        fprintf(stderr, "launcher: cannot import harness module " HARNESS_MOD "\n");
        abort();
    }
    test_one_input = PyObject_GetAttrString(mod, "TestOneInput");
    Py_DECREF(mod);
    if (!test_one_input || !PyCallable_Check(test_one_input)) {
        fprintf(stderr, "launcher: " HARNESS_MOD ".TestOneInput missing\n");
        abort();
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    PyObject *buf = PyBytes_FromStringAndSize((const char *)data, (Py_ssize_t)size);
    if (!buf) {
        PyErr_Print();
        abort();
    }
    PyObject *res = PyObject_CallFunctionObjArgs(test_one_input, buf, NULL);
    Py_DECREF(buf);
    if (!res) {
        /* Uncaught Python exception == finding. */
        PyErr_Print();
        abort();
    }
    Py_DECREF(res);
    return 0;
}
