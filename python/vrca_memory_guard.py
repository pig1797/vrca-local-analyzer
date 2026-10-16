# -*- coding: utf-8 -*-
"""Windows kernel-enforced memory guard for VRCA worker processes."""

import ctypes
import os


_MEMORY_JOB = None


def apply_windows_memory_limit(limit_mb=None):
    """Cap the current process before UnityPy reads an AssetBundle.

    The cap is enforced by a Windows Job Object, rather than a polling loop.
    It therefore remains effective even if a native parser allocates memory in
    a sudden burst.  The handle is intentionally retained for process lifetime.
    """
    global _MEMORY_JOB
    if os.name != "nt" or _MEMORY_JOB is not None:
        return

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class BasicLimit(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", ctypes.c_ulong),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_ulong),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_ulong),
            ("SchedulingClass", ctypes.c_ulong),
        ]

    class ExtendedLimit(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimit),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.restype = ctypes.c_void_p
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    kernel32.SetInformationJobObject.argtypes = [
        ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_ulong
    ]
    kernel32.AssignProcessToJobObject.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    kernel32.CloseHandle.argtypes = [ctypes.c_void_p]

    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise RuntimeError("unable to create the VRCA memory-limit job")

    if limit_mb is None:
        limit_mb = int(os.environ.get("VRCA_UNLOCK_MEMORY_MB", "2048"))
    limit_mb = min(max(int(limit_mb), 256), 2048)
    info = ExtendedLimit()
    # Cap both each process and the whole inherited process tree.  The job-wide
    # cap matters for tools such as AssetRipper that may create helper children.
    # JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY |
    # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    info.BasicLimitInformation.LimitFlags = 0x00000100 | 0x00000200 | 0x00002000
    info.ProcessMemoryLimit = limit_mb * 1024 * 1024
    info.JobMemoryLimit = limit_mb * 1024 * 1024
    if not kernel32.SetInformationJobObject(
        job, 9, ctypes.byref(info), ctypes.sizeof(info)
    ):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        raise RuntimeError("unable to configure the VRCA memory limit: %d" % error)
    if not kernel32.AssignProcessToJobObject(job, kernel32.GetCurrentProcess()):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        raise RuntimeError("unable to enforce the VRCA memory limit: %d" % error)
    _MEMORY_JOB = job
