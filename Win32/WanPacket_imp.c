/*
 * Import stub handler for WanPacket.dll.
 * Since WanPacket.cpp isn't compilable using MinGW (<netmon.h>
 * is missing in MinGW etc., etc.), I went the easy way of loading
 * WanPacket.dll at run-time.
 *
 * By G. Vanem <gvanem@yahoo.no> 2009.
 */

#include "./Win32/config.h"

/* Add this since we want the definition in Packet32.h.
 */
#define PCAP_DONT_INCLUDE_PCAP_BPF_H

#include <stdio.h>
#include <Packet32.h>
#include <WanPacket/WanPacket.h>
#include <pcap-int.h>
#include "pcap-trace.h"

#if defined(HAVE_CRTDBG_H) || defined(_MSC_VER) || defined(__MINGW64_VERSION_MAJOR)
  #include <crtdbg.h>
  #undef  HAVE_CRTDBG_H
  #define HAVE_CRTDBG_H
#endif

static HINSTANCE wp_mod = NULL;
static void load_wanpacket_dll (void);

#define LOAD_FUNC(f)  do {                                                            \
                        p_##f = (t_##f) GetProcAddress (wp_mod, "WanPacket" #f);      \
                        PCAP_TRACE (2, "Function WanPacket%s(): %*s0x%p\n",           \
                                    #f, 15-(int)strlen(#f), "", (const void*) p_##f); \
                      } while (0)

#if defined(__WATCOMC__)
  #if defined(__SW_3R)
    #error "Do not compile this with register calls"
  #endif
  /*
   * wcc386 doesn't like a 'cdecl' modifier here since none was
   * specified in  $(WinPcap_root)/PacketNtx/Dll/WanPacket/WanPacket.h.
   */
  #define WANPACKET_CALL
#elif defined(__GNUC__)
  #define WANPACKET_CALL __attribute__((__cdecl__))
#else
  #define WANPACKET_CALL __cdecl
#endif

#define THUNK(name, ret, proto, args)                           \
                       typedef ret (__cdecl *t_ ##name) proto;  \
                       static t_##name p_##name;                \
                                                                \
                       ret WANPACKET_CALL WanPacket##name proto \
                       {                                        \
                         load_wanpacket_dll();                  \
                         if (!p_##name)                         \
                            return (ret) 0;                     \
                         return (*p_##name) args;               \
                       }

THUNK (OpenAdapter,    WAN_ADAPTER *, (void),                                    () )
THUNK (SetBpfFilter,   BOOLEAN,       (WAN_ADAPTER *a, UCHAR *code, DWORD len),  (a,code,len))
THUNK (CloseAdapter,   BOOLEAN,       (WAN_ADAPTER *a),                          (a) )
THUNK (SetBufferSize,  BOOLEAN,       (WAN_ADAPTER *a, DWORD size),              (a,size) )
THUNK (ReceivePacket,  DWORD,         (WAN_ADAPTER *a, UCHAR *buf, DWORD size),  (a,buf,size) )
THUNK (SetMinToCopy,   BOOLEAN,       (WAN_ADAPTER *a, DWORD size),              (a,size) )
THUNK (GetStats,       BOOLEAN,       (WAN_ADAPTER *a, struct bpf_stat *st),     (a,st) )
THUNK (SetReadTimeout, BOOLEAN,       (WAN_ADAPTER *a, DWORD time_ms),           (a,time_ms) )
THUNK (SetMode,        BOOLEAN,       (WAN_ADAPTER *a, DWORD mode),              (a,mode) )
THUNK (GetReadEvent,   HANDLE,        (WAN_ADAPTER *a),                          (a) )
THUNK (TestAdapter,    BOOLEAN,       (void),                                    () )

static void load_wanpacket_dll (void)
{
  static BOOL done = FALSE;

  if (done)
     return;

  done = TRUE;

#if defined(HAVE_CRTDBG_H)
  /*
   * Try to disable the GUI in case some dependant .DLLs
   * of WanPacket.dll are missing.
   */
  _CrtSetReportMode (_CRT_ASSERT, 0);
#endif

  PCAP_TRACE (2, "load_wanpacket_dll\n");
  wp_mod = LoadLibrary ("WanPacket.dll");
  if (!wp_mod)
  {
    PCAP_TRACE (2, "Failed to load WanPacket.dll.\n");
    return;
  }
  PCAP_TRACE (2, "loaded okay.\n");

  LOAD_FUNC (SetBpfFilter);
  LOAD_FUNC (OpenAdapter);
  LOAD_FUNC (CloseAdapter);
  LOAD_FUNC (SetBufferSize);
  LOAD_FUNC (ReceivePacket);
  LOAD_FUNC (SetMinToCopy);
  LOAD_FUNC (GetStats);
  LOAD_FUNC (SetReadTimeout);
  LOAD_FUNC (SetMode);
  LOAD_FUNC (GetReadEvent);
  LOAD_FUNC (TestAdapter);
}
