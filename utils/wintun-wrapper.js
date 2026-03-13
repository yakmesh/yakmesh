import koffi from 'koffi';
import { join } from 'path';

// Load wintun.dll
const dllPath = join(import.meta.dirname, 'wintun.dll');
const lib = koffi.load(dllPath);

// Windows Types
const DWORD = koffi.types.uint32;
const WORD = koffi.types.uint16;
const BYTE = koffi.types.uint8;
const WCHAR = koffi.types.char16; // WCHAR is usually 16-bit
const VOID = koffi.types.void;
const HANDLE = koffi.pointer('HANDLE', koffi.types.void);
const WINTUN_ADAPTER_HANDLE = koffi.pointer('WINTUN_ADAPTER_HANDLE', koffi.types.void);
const WINTUN_SESSION_HANDLE = koffi.pointer('WINTUN_SESSION_HANDLE', koffi.types.void);

const GUID = koffi.struct('GUID', {
    Data1: DWORD,
    Data2: WORD,
    Data3: WORD,
    Data4: koffi.array(BYTE, 8)
});

// Wintun API
// WINTUN_ADAPTER_HANDLE WintunCreateAdapter(const WCHAR *Name, const WCHAR *TunnelType, const GUID *RequestedGUID);
const WintunCreateAdapter = lib.func('WintunCreateAdapter', WINTUN_ADAPTER_HANDLE, ['const char16_t*', 'const char16_t*', koffi.pointer(GUID)]);

// WINTUN_SESSION_HANDLE WintunStartSession(WINTUN_ADAPTER_HANDLE Adapter, DWORD Capacity);
const WintunStartSession = lib.func('WintunStartSession', WINTUN_SESSION_HANDLE, [WINTUN_ADAPTER_HANDLE, DWORD]);

// void WintunCloseAdapter(WINTUN_ADAPTER_HANDLE Adapter);
const WintunCloseAdapter = lib.func('WintunCloseAdapter', VOID, [WINTUN_ADAPTER_HANDLE]);

// void WintunEndSession(WINTUN_SESSION_HANDLE Session);
const WintunEndSession = lib.func('WintunEndSession', VOID, [WINTUN_SESSION_HANDLE]);

// BYTE* WintunAllocateSendPacket(WINTUN_SESSION_HANDLE Session, DWORD PacketSize);
const WintunAllocateSendPacket = lib.func('WintunAllocateSendPacket', koffi.pointer(BYTE), [WINTUN_SESSION_HANDLE, DWORD]);

// void WintunSendPacket(WINTUN_SESSION_HANDLE Session, const BYTE *Packet);
const WintunSendPacket = lib.func('WintunSendPacket', VOID, [WINTUN_SESSION_HANDLE, koffi.pointer(BYTE)]);

// BYTE* WintunReceivePacket(WINTUN_SESSION_HANDLE Session, DWORD *PacketSize);
const WintunReceivePacket = lib.func('WintunReceivePacket', koffi.pointer(BYTE), [WINTUN_SESSION_HANDLE, koffi.out(koffi.pointer(DWORD))]);

// void WintunReleaseReceivePacket(WINTUN_SESSION_HANDLE Session, const BYTE *Packet);
const WintunReleaseReceivePacket = lib.func('WintunReleaseReceivePacket', VOID, [WINTUN_SESSION_HANDLE, koffi.pointer(BYTE)]);

// HANDLE WintunGetReadWaitEvent(WINTUN_SESSION_HANDLE Session);
const WintunGetReadWaitEvent = lib.func('WintunGetReadWaitEvent', HANDLE, [WINTUN_SESSION_HANDLE]);

// Kernel32 for WaitForSingleObject and Memcopy
const kernel32 = koffi.load('kernel32.dll');
const WaitForSingleObject = kernel32.func('uint32_t __stdcall WaitForSingleObject(void *hHandle, uint32_t dwMilliseconds)');
const RtlCopyMemory = kernel32.func('void __stdcall RtlCopyMemory(void *Destination, const void *Source, size_t Length)');

export {
    WintunCreateAdapter, WintunStartSession, WintunCloseAdapter, WintunEndSession,
    WintunAllocateSendPacket, WintunSendPacket, WintunReceivePacket, WintunReleaseReceivePacket,
    WintunGetReadWaitEvent, WaitForSingleObject, RtlCopyMemory, GUID, koffi
};
