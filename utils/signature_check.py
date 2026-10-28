"""
CyberGuardian Authenticode Signature Verification
=================================================

Verifies Windows Authenticode signatures using the Win32 API through ctypes.

This replaces the previous implementation which interpolated file paths into a
PowerShell command string (a command-injection vector) and spawned two
processes per scanned binary.

Public API:
    verify_file(path) -> SignatureInfo

``SignatureInfo.status`` is one of: "Valid", "Unsigned", "Invalid", "Expired",
"UntrustedRoot", "Unavailable".  ``SignatureInfo.signer`` is the certificate
subject's simple display name when it can be resolved.
"""

from __future__ import annotations

import ctypes
import os
import sys
import threading
from ctypes import wintypes
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

IS_WINDOWS = sys.platform == "win32"

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x00001000
WTD_DISABLE_MD2_MD4 = 0x00002000
WTD_SAFER_FLAG = 0x00000100

CERT_QUERY_OBJECT_FILE = 1
CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x00000400
CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED = 0x00000008
CERT_QUERY_FORMAT_FLAG_BINARY = 0x00000002
CMSG_SIGNER_CERT_INFO_PARAM = 7
CERT_FIND_SUBJECT_CERT = 0x000B0000
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
X509_ASN_ENCODING = 0x00000001
PKCS_7_ASN_ENCODING = 0x00010000
MAX_PATH_CHARS = 260
WTD_CHOICE_CATALOG = 2
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
FILE_SHARE_ALL = 0x00000007
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x00000080

# WinVerifyTrust return values of interest
TRUST_E_NOSIGNATURE = 0x800B0100
TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003
TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
TRUST_E_EXPLICIT_DISTRUST = 0x800B0111
CERT_E_UNTRUSTEDROOT = 0x800B0109
CERT_E_CHAINING = 0x800B010A
CERT_E_EXPIRED = 0x800B0101
CERT_E_REVOKED = 0x800B010C
CERT_E_UNTRUSTEDTESTROOT = 0x800B010D
CERT_E_WRONG_USAGE = 0x800B0110
CRYPT_E_SECURITY_SETTINGS = 0x80092026

_STATUS_MAP = {
    0x00000000: "Valid",
    TRUST_E_NOSIGNATURE: "Unsigned",
    TRUST_E_SUBJECT_FORM_UNKNOWN: "Unsigned",
    TRUST_E_PROVIDER_UNKNOWN: "Unavailable",
    TRUST_E_EXPLICIT_DISTRUST: "Invalid",
    CERT_E_UNTRUSTEDROOT: "UntrustedRoot",
    CERT_E_UNTRUSTEDTESTROOT: "UntrustedRoot",
    CERT_E_CHAINING: "Invalid",
    CERT_E_EXPIRED: "Expired",
    CERT_E_REVOKED: "Invalid",
    CERT_E_WRONG_USAGE: "Invalid",
    CRYPT_E_SECURITY_SETTINGS: "Invalid",
}

CACHE_LIMIT = 4096


@dataclass(frozen=True)
class SignatureInfo:
    """Result of an Authenticode verification."""

    path: str
    status: str
    signer: str = ""

    @property
    def is_valid(self) -> bool:
        return self.status == "Valid"

    @property
    def is_signed(self) -> bool:
        return self.status in {
            "Valid",
            "Invalid",
            "Expired",
            "UntrustedRoot",
        }


# ---------------------------------------------------------------------------
# ctypes structures
# ---------------------------------------------------------------------------


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", wintypes.DWORD),
        ("Data2", wintypes.WORD),
        ("Data3", wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


class WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pcwszFilePath", wintypes.LPCWSTR),
        ("hFile", wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(GUID)),
    ]


class WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wintypes.DWORD),
        ("fdwRevocationChecks", wintypes.DWORD),
        ("dwUnionChoice", wintypes.DWORD),
        ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
        ("dwStateAction", wintypes.DWORD),
        ("hWVTStateData", wintypes.HANDLE),
        ("pwszURLReference", wintypes.LPWSTR),
        ("dwProvFlags", wintypes.DWORD),
        ("dwUIContext", wintypes.DWORD),
    ]


class WINTRUST_CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("dwCatalogVersion", wintypes.DWORD),
        ("pcwszCatalogFilePath", wintypes.LPCWSTR),
        ("pcwszMemberTag", wintypes.LPCWSTR),
        ("pcwszMemberFilePath", wintypes.LPCWSTR),
        ("hMemberFile", wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", wintypes.DWORD),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", wintypes.HANDLE),
    ]


class CATALOG_INFO(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wintypes.DWORD),
        ("wszCatalogFile", wintypes.WCHAR * MAX_PATH_CHARS),
    ]


# WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
ACTION_GENERIC_VERIFY_V2 = GUID(
    0x00AAC56B, 0xCD44, 0x11D0, (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

_lock = threading.Lock()
_cache: Dict[Tuple[str, float, int], SignatureInfo] = {}


def _dll_crypt32():
    """Load crypt32 with correct prototypes (pointer restypes are essential)."""
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    crypt32.CryptQueryObject.restype = wintypes.BOOL
    crypt32.CryptQueryObject.argtypes = [
        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.HANDLE), ctypes.POINTER(wintypes.HANDLE),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    crypt32.CryptMsgGetParam.restype = wintypes.BOOL
    crypt32.CryptMsgGetParam.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
    ]
    crypt32.CertFindCertificateInStore.restype = ctypes.c_void_p
    crypt32.CertFindCertificateInStore.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p,
    ]
    crypt32.CertGetNameStringW.restype = wintypes.DWORD
    crypt32.CertGetNameStringW.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        ctypes.c_void_p, wintypes.DWORD,
    ]
    crypt32.CertFreeCertificateContext.argtypes = [ctypes.c_void_p]
    crypt32.CertCloseStore.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    crypt32.CryptMsgClose.argtypes = [wintypes.HANDLE]
    return crypt32


def _query_signer(
    path: str, content_flag: int = CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED
) -> str:
    """Return the signer's simple display name using CryptQueryObject."""
    try:
        crypt32 = _dll_crypt32()

        encoding = wintypes.DWORD()
        content = wintypes.DWORD()
        fmt = wintypes.DWORD()
        store = wintypes.HANDLE()
        msg = wintypes.HANDLE()
        context = ctypes.c_void_p()

        ok = crypt32.CryptQueryObject(
            wintypes.DWORD(CERT_QUERY_OBJECT_FILE),
            ctypes.c_wchar_p(path),
            wintypes.DWORD(content_flag),
            wintypes.DWORD(CERT_QUERY_FORMAT_FLAG_BINARY),
            wintypes.DWORD(0),
            ctypes.byref(encoding),
            ctypes.byref(content),
            ctypes.byref(fmt),
            ctypes.byref(store),
            ctypes.byref(msg),
            ctypes.byref(context),
        )
        if not ok:
            return ""

        try:
            size = wintypes.DWORD()
            if not crypt32.CryptMsgGetParam(
                msg, wintypes.DWORD(CMSG_SIGNER_CERT_INFO_PARAM), wintypes.DWORD(0),
                None, ctypes.byref(size),
            ):
                return ""
            if not size.value:
                return ""
            buffer = (ctypes.c_ubyte * size.value)()
            if not crypt32.CryptMsgGetParam(
                msg, wintypes.DWORD(CMSG_SIGNER_CERT_INFO_PARAM), wintypes.DWORD(0),
                ctypes.byref(buffer), ctypes.byref(size),
            ):
                return ""

            cert_ctx = crypt32.CertFindCertificateInStore(
                store,
                wintypes.DWORD(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING),
                wintypes.DWORD(0),
                wintypes.DWORD(CERT_FIND_SUBJECT_CERT),
                ctypes.byref(buffer),
                None,
            )
            if not cert_ctx:
                return ""
            try:
                length = crypt32.CertGetNameStringW(
                    cert_ctx,
                    wintypes.DWORD(CERT_NAME_SIMPLE_DISPLAY_TYPE),
                    wintypes.DWORD(0),
                    None,
                    None,
                    wintypes.DWORD(0),
                )
                if not length:
                    return ""
                name_buf = ctypes.create_unicode_buffer(length)
                crypt32.CertGetNameStringW(
                    cert_ctx,
                    wintypes.DWORD(CERT_NAME_SIMPLE_DISPLAY_TYPE),
                    wintypes.DWORD(0),
                    None,
                    name_buf,
                    wintypes.DWORD(length),
                )
                return name_buf.value.strip()
            finally:
                crypt32.CertFreeCertificateContext(cert_ctx)
        finally:
            if msg:
                crypt32.CryptMsgClose(msg)
            if store:
                crypt32.CertCloseStore(store, wintypes.DWORD(0))
    except Exception:
        return ""


def _verify_wintrust(path: str) -> int:
    """Run WinVerifyTrust and return the raw HRESULT."""
    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)

    file_info = WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = path
    file_info.hFile = None
    file_info.pgKnownSubject = None

    data = WINTRUST_DATA()
    data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
    data.dwUIChoice = WTD_UI_NONE
    data.fdwRevocationChecks = WTD_REVOKE_NONE
    data.dwUnionChoice = WTD_CHOICE_FILE
    data.pFile = ctypes.pointer(file_info)
    data.dwStateAction = WTD_STATEACTION_VERIFY
    data.dwProvFlags = (
        WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_DISABLE_MD2_MD4 | WTD_SAFER_FLAG
    )

    result = wintrust.WinVerifyTrust(
        wintypes.HWND(0), ctypes.byref(ACTION_GENERIC_VERIFY_V2), ctypes.byref(data)
    )

    # Always release the state data, even when verification failed.
    data.dwStateAction = WTD_STATEACTION_CLOSE
    try:
        wintrust.WinVerifyTrust(
            wintypes.HWND(0), ctypes.byref(ACTION_GENERIC_VERIFY_V2), ctypes.byref(data)
        )
    except Exception:
        pass

    return int(result) & 0xFFFFFFFF


def _verify_catalog(path: str) -> Tuple[int, str]:
    """Verify a catalog-signed file (typical for Windows system binaries).

    Returns ``(hresult, catalog_path)``.  ``TRUST_E_NOSIGNATURE`` means the file
    is not present in any installed catalog either.
    """
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]

    wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
    wintrust.CryptCATAdminAcquireContext.restype = wintypes.BOOL
    wintrust.CryptCATAdminAcquireContext.argtypes = [
        ctypes.POINTER(wintypes.HANDLE), ctypes.c_void_p, wintypes.DWORD,
    ]
    wintrust.CryptCATAdminCalcHashFromFileHandle2.restype = wintypes.BOOL
    wintrust.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
        wintypes.HANDLE, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
    ]
    wintrust.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p
    wintrust.CryptCATAdminEnumCatalogFromHash.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(ctypes.c_ubyte), wintypes.DWORD,
        wintypes.DWORD, ctypes.c_void_p,
    ]
    wintrust.CryptCATCatalogInfoFromContext.restype = wintypes.BOOL
    wintrust.CryptCATCatalogInfoFromContext.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(CATALOG_INFO), wintypes.DWORD,
    ]
    wintrust.CryptCATAdminReleaseCatalogContext.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
    ]
    wintrust.CryptCATAdminReleaseContext.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    wintrust.WinVerifyTrust.restype = ctypes.c_long

    handle = kernel32.CreateFileW(
        path, GENERIC_READ, FILE_SHARE_ALL, None, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, None,
    )
    if not handle or handle == INVALID_HANDLE_VALUE:
        return TRUST_E_NOSIGNATURE, ""

    cat_admin = wintypes.HANDLE()
    cat_info = ctypes.c_void_p()
    try:
        if not wintrust.CryptCATAdminAcquireContext(ctypes.byref(cat_admin), None, 0):
            return TRUST_E_NOSIGNATURE, ""

        hash_len = wintypes.DWORD(0)
        if not wintrust.CryptCATAdminCalcHashFromFileHandle2(
            cat_admin, handle, ctypes.byref(hash_len), None, 0
        ):
            return TRUST_E_NOSIGNATURE, ""
        if not hash_len.value:
            return TRUST_E_NOSIGNATURE, ""

        hash_buf = (ctypes.c_ubyte * hash_len.value)()
        if not wintrust.CryptCATAdminCalcHashFromFileHandle2(
            cat_admin, handle, ctypes.byref(hash_len), hash_buf, 0
        ):
            return TRUST_E_NOSIGNATURE, ""

        cat_info = wintrust.CryptCATAdminEnumCatalogFromHash(
            cat_admin, hash_buf, hash_len.value, 0, None
        )
        if not cat_info:
            return TRUST_E_NOSIGNATURE, ""

        info = CATALOG_INFO()
        info.cbStruct = ctypes.sizeof(CATALOG_INFO)
        if not wintrust.CryptCATCatalogInfoFromContext(cat_info, ctypes.byref(info), 0):
            return TRUST_E_NOSIGNATURE, ""

        catalog_path = info.wszCatalogFile
        member_tag = "".join(f"{b:02X}" for b in hash_buf[: hash_len.value])

        cat = WINTRUST_CATALOG_INFO()
        cat.cbStruct = ctypes.sizeof(WINTRUST_CATALOG_INFO)
        cat.dwCatalogVersion = 0
        cat.pcwszCatalogFilePath = catalog_path
        cat.pcwszMemberTag = member_tag
        cat.pcwszMemberFilePath = path
        cat.hMemberFile = handle
        cat.pbCalculatedFileHash = ctypes.cast(
            hash_buf, ctypes.POINTER(ctypes.c_ubyte)
        )
        cat.cbCalculatedFileHash = hash_len.value
        cat.pcCatalogContext = None
        cat.hCatAdmin = cat_admin

        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = WTD_CHOICE_CATALOG
        data.pFile = ctypes.cast(
            ctypes.pointer(cat), ctypes.POINTER(WINTRUST_FILE_INFO)
        )
        data.dwStateAction = WTD_STATEACTION_VERIFY
        data.dwProvFlags = WTD_DISABLE_MD2_MD4 | WTD_SAFER_FLAG

        code = int(
            wintrust.WinVerifyTrust(
                wintypes.HWND(0),
                ctypes.byref(ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(data),
            )
        ) & 0xFFFFFFFF

        data.dwStateAction = WTD_STATEACTION_CLOSE
        try:
            wintrust.WinVerifyTrust(
                wintypes.HWND(0),
                ctypes.byref(ACTION_GENERIC_VERIFY_V2),
                ctypes.byref(data),
            )
        except Exception:
            pass

        return code, catalog_path
    finally:
        if cat_info:
            wintrust.CryptCATAdminReleaseCatalogContext(cat_admin, cat_info, 0)
        if cat_admin:
            wintrust.CryptCATAdminReleaseContext(cat_admin, 0)
        kernel32.CloseHandle(handle)


def verify_file(path: str) -> SignatureInfo:
    """Verify the Authenticode signature of ``path`` (cached by mtime/size)."""
    path = os.fspath(path)
    if not path or not os.path.isfile(path):
        return SignatureInfo(path=path, status="Unavailable")

    if not IS_WINDOWS:
        return SignatureInfo(path=path, status="Unavailable")

    try:
        stat = os.stat(path)
    except OSError:
        return SignatureInfo(path=path, status="Unavailable")

    key = (os.path.normcase(os.path.abspath(path)), stat.st_mtime, stat.st_size)
    with _lock:
        cached = _cache.get(key)
    if cached is not None:
        return cached

    signer = ""
    try:
        code = _verify_wintrust(path)
        if code == TRUST_E_NOSIGNATURE:
            # Windows system binaries are frequently catalog-signed only.
            cat_code, catalog_path = _verify_catalog(path)
            if cat_code != TRUST_E_NOSIGNATURE:
                code = cat_code
                if code == 0 and catalog_path:
                    signer = _query_signer(
                        catalog_path, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED
                    )
        status = _STATUS_MAP.get(code, "Invalid")
    except Exception:
        status = "Unavailable"

    if status in {"Valid", "Expired", "UntrustedRoot"} and not signer:
        signer = _query_signer(path)

    info = SignatureInfo(path=path, status=status, signer=signer)

    with _lock:
        if len(_cache) >= CACHE_LIMIT:
            _cache.clear()
        _cache[key] = info
    return info


def clear_cache() -> None:
    """Clear the verification cache."""
    with _lock:
        _cache.clear()
