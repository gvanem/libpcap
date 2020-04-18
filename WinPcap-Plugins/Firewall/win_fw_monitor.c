/*
 * A Windows Firewall event sniffer plugin for WinPcap.
 * Depends on the Windows Filtering Platform (WFP).
 *
 * Highly experimental at the moment (june 2018). But the idea
 * is to fake a OpenBSD "packet filter log" on Windows too.
 *
 * Ref: <net/pfvar.h>, <net/if_pflog.h> and their relevant man-pages.
 *
 * This is the main source-code for 'winpcap_firewall_plugin.dll'
 * which is loaded by the WinPcap plugin handler in pcap-plugin.c.
 *
 * By G. Vanem <gvanem@yahoo.no> 2018.
 */

#define PLUGIN_INSTANCE_TYPE  struct _PluginInstance
#define PCAP_PLUGIN_NAME      "PCAP-Firewall"
#define TRACE_PREFIX          "[Firewall] "

#define __FILE()              "WinPcap-plugin/Firewall/win_fw_monitor.c"

#include "./Win32/config.h"

#if defined(HAVE_FW_MONITOR)  /* Rest of file */

#include <windows.h>
#include <pcap-int.h>

struct _PluginInstance;    /* Forward */

#include "./WinPcap-Plugins/pcap-plugin-interface.h"

typedef struct _PluginInstance {
        char                *deviceName;
        PLUGIN_PACKET_HEADER packetHeader;
        UINT8                packet [1024*10];
        int                  readTimeoutMs;
        PLUGIN_STATS         stats;
      } PluginInstance;


PLUGIN_API size_t GetPluginApiVersion (void)
{
  PCAP_TRACE (2, "%s() called. ver: %d\n", __FUNCTION__, PLUGIN_API_VERSION);

  return PLUGIN_API_VERSION;
}

BOOL WINAPI DllMain (HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpvReserved)
{
  switch (dwReason)
  {
    case DLL_PROCESS_ATTACH:
         PCAP_TRACE (2, "%s (%p,DLL_PROCESS_ATTACH) called.\n",
                     __FUNCTION__, (const void*)hinstDLL);
         break;
    case DLL_PROCESS_DETACH:
         PCAP_TRACE (2, "%s (%p,DLL_PROCESS_DETACH) called.\n",
                     __FUNCTION__, (const void*)hinstDLL);
         break;
  }
  return (TRUE);
}
#endif   /* HAVE_FW_MONITOR */
