/*
 * launcher.c -- an ELF target that runs the Atheris (Python) fuzz harness.
 *
 * Mayhem requires the target `cmd:` to be an ELF (it rejects shell/script
 * wrappers) and our gate checks each target binary for DWARF < 4 debug info.
 * An Atheris harness is a Python script, so we compile this launcher (with
 * $DEBUG_FLAGS, i.e. -gdwarf-3) as a CPython-EMBEDDING binary: it statically
 * links libpython and runs the harness in-process via Py_RunMain.
 *
 * In-process embedding, NOT exec of the interpreter: Mayhem's cloud coverage
 * tracer measures the main executable of the cmd process. An exec-style
 * wrapper (or a dynamically-linked embedder, where the interpreter lives in
 * libpython.so) records 0 edges cloud-side even though libFuzzer runs fine;
 * with libpython statically linked into THIS binary the interpreter's edges
 * are attributed to the target and the run reports real coverage.
 *
 * The harness path is baked in at compile time via -DHARNESS=... so the
 * binary is self-contained.
 */
#include <Python.h>

#include <stdio.h>
#include <stdlib.h>

#ifndef HARNESS
#define HARNESS "/mayhem/mayhem/differential_fuzz.py"
#endif

int main(int argc, char **argv) {
    PyConfig config;
    PyConfig_InitPythonConfig(&config);

    /* argv for the interpreter: HARNESS <forwarded libFuzzer args...> */
    char **a = (char **)calloc((size_t)argc + 1, sizeof(char *));
    if (!a) {
        perror("calloc");
        return 1;
    }
    int n = 0;
    a[n++] = (char *)HARNESS;
    for (int i = 1; i < argc; i++) {
        a[n++] = argv[i];
    }

    /* Do NOT let Python parse libFuzzer flags (-runs=..., corpus dirs) as
     * interpreter options; hand them through verbatim in sys.argv. */
    config.parse_argv = 0;
    PyStatus status = PyConfig_SetBytesArgv(&config, n, a);
    if (PyStatus_Exception(status)) {
        PyConfig_Clear(&config);
        Py_ExitStatusException(status);
    }
    status = PyConfig_SetBytesString(&config, &config.run_filename, HARNESS);
    if (PyStatus_Exception(status)) {
        PyConfig_Clear(&config);
        Py_ExitStatusException(status);
    }

    status = Py_InitializeFromConfig(&config);
    PyConfig_Clear(&config);
    if (PyStatus_Exception(status)) {
        Py_ExitStatusException(status);
    }

    return Py_RunMain();
}
