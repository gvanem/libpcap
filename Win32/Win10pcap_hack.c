/*
 * Hacks for making Win10Pcap more compatible with my
 * existing Wpcap2.dll (built for the original WinPcap).
 *
 * By G. Vanem <gvanem@yahoo.no>  2015.
 */

#include <stdio.h>

#if defined(USE_WIN10PCAP)  /* Rest of file */

#include "./Win32/config.h"
#include "pcap-trace.h"

#include <assert.h>
#include <Packet_dll/Packet32.h>
#include <Packet_dll/SeTypes.h>
#include <Packet_dll/NdisDriverUser.h>
#include <Packet_dll/Packet32_Internal.h>

/*
 * Adapt the original function 'PacketFindAdInfo()' in:
 *  $(WINPCAP_ROOT)/PacketNtx/AdInfo.c
 *
 * to a function here. Use the 'SL_ADAPTER_INFO' list in:
 *   $(WIN10PCAP_ROOT)/Packet_dll/NdisDriverUser.c
 *
 * as a base.
 */
struct ADAPTER_INFO {  /* Same as SLADAPTER_INFO */
       wchar_t AdapterId[SL_ADAPTER_ID_LEN];  /* Adapter ID */
       UCHAR   MacAddress[6];                 /* MAC address */
       UCHAR   Padding1[2];
       UINT    MtuSize;                       /* MTU size */
       char    FriendlyName[256];             /* Display name */
       UINT    SupportsVLanHw;                /* Supports VLAN by HW */
       UCHAR   Reserved[256-sizeof(UINT)];    /* Reserved area */
     };

struct ADAPTER_INFO *PacketFindAdInfo (PCHAR AdapterName)
{
  SU              *su = OpenSuBasicAdapter();
  SE_LIST         *o;
  SU_ADAPTER_LIST *d;

  PCAP_TRACE (1, "%s(): AdapterName: '%s', su: %p\n", __FUNCTION__, AdapterName, su);

  assert (sizeof(SL_ADAPTER_INFO) == sizeof(struct ADAPTER_INFO));

  if (!su)
     return (NULL);

  o = SuGetAdapterList(su);
  d = FindAdapterByName (o, AdapterName);

  PCAP_TRACE (1, "o: %p, d: %p\n", o, d);

  return (struct ADAPTER_INFO*) (d ? &d->Info : NULL);
}
#endif /* USE_WIN10PCAP */
