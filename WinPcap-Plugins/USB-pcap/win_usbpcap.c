/*
 * A Windows USBPcap plugin for WinPcap.
 *
 * Highly experimental at the moment (june 2014).
 *
 * This is the main source-code for 'winpcap_usb_plugin.dll'
 * which is loaded by the WinPcap plugin handler in pcap-plugin.c.
 *
 * By G. Vanem <gvanem@yahoo.no> 2013.
 */

#define COMPILING_PCAP_PLUGIN
#define PLUGIN_INSTANCE_TYPE   struct _PluginInstance
#define PCAP_PLUGIN_NAME       "USB-Pcap"
#define TRACE_PREFIX           "[USB-Pcap] "

#define __FILE()               "WinPcap-plugin/USB-pcap/win_usbpcap.c"

#include "./Win32/config.h"

struct _PluginInstance;    /* Forward */

#include <pcap.h>
#include <pcap-int.h>

#include "./WinPcap-Plugins/pcap-plugin-interface.h"

#define DLT_TO_FAKE       DLT_USBPCAP
#define DLT_TO_FAKE_STR  "DLT_USBPCAP"

typedef struct _PluginInstance {
        char                *deviceName;
        PLUGIN_PACKET_HEADER packetHeader;
        UINT8                packet[1024*10];
        int                  readTimeoutMs;
        PLUGIN_STATS         stats;
      } PluginInstance;

PLUGIN_API size_t GetPluginApiVersion (void)
{
  PCAP_TRACE (3, "%s() called. ver: %d\n", __FUNCTION__, PLUGIN_API_VERSION);

  return PLUGIN_API_VERSION;
}

PLUGIN_API BOOL GetPluginName (OUT char  *out,
                               IN  size_t nameSizeInBytes)
{
  const char *name = PCAP_PLUGIN_NAME;

  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);
  pcap_strlcpy (out, name, nameSizeInBytes);
  return (TRUE);
}

PLUGIN_API BOOL GetDeviceList (OUT PLUGIN_DEVICE_DESCRIPTION **devices,
                               OUT char                       *errorMsg,
                               IN  size_t                      errorMsgSizeInBytes)
{
  PLUGIN_DEVICE_DESCRIPTION *newDeviceDesc = calloc (sizeof(*newDeviceDesc), 1);

  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  if (!newDeviceDesc)
  {
    pcap_strlcpy (errorMsg, "Failed to allocate memory for the device description", errorMsgSizeInBytes);
    FreeDeviceList (*devices);
    return (FALSE);
  }
  snprintf (newDeviceDesc->name, sizeof(newDeviceDesc->name), "\\\\" PCAP_PLUGIN_NAME);
  snprintf (newDeviceDesc->description, sizeof(newDeviceDesc->description), "USB Capture Device");

  *devices = newDeviceDesc;

  return (TRUE);
}

PLUGIN_API void FreeDeviceList (IN OUT PLUGIN_DEVICE_DESCRIPTION *devices)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  while (devices)
  {
    PLUGIN_DEVICE_DESCRIPTION *tmpEntry = devices->next;

    free (devices);
    devices = tmpEntry;
  }
}

PLUGIN_API BOOL OpenInstance (IN  char                  *deviceName,
                              OUT PLUGIN_INSTANCE_TYPE **instanceHandle,
                              OUT char                  *errorMsg,
                              IN  size_t                 errorMsgSizeInBytes)
{
  PLUGIN_INSTANCE_TYPE *newInstance = calloc (sizeof(*newInstance)+strlen(deviceName)+1, 1);

  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  if (!newInstance)
  {
    strncpy (errorMsg, "Failed to allocate memory for the instance handle", errorMsgSizeInBytes);
    return (FALSE);
  }
  newInstance->deviceName = strcpy ((char*)(newInstance+1), deviceName);
  *instanceHandle = newInstance;
  return (TRUE);
}

PLUGIN_API void CloseInstance (IN PLUGIN_INSTANCE_TYPE *instanceHandle)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);
  free (instanceHandle);
}

PLUGIN_API int GetLinkType (IN PLUGIN_INSTANCE_TYPE *instanceHandle)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);
  UNUSED (instanceHandle);

  return (DLT_TO_FAKE);
}

PLUGIN_API BOOL GetSupportedDlts (IN     PLUGIN_INSTANCE_TYPE *instanceHandle,
                                  IN OUT UINT                 *dltList,
                                  IN     size_t                dltListSizeInBytes,
                                  OUT    size_t               *dltCount)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  UNUSED (instanceHandle);

  *dltCount = 1;

  if (dltListSizeInBytes < sizeof(UINT)*(*dltCount))
     return (FALSE);

  dltList[0] = DLT_TO_FAKE;
  return (TRUE);
}

PLUGIN_API BOOL SetDatalink (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                             IN  int                   dlt,
                             OUT char                 *errorMsg,
                             IN  size_t                errorMsgSizeInBytes)
{
  UNUSED (instanceHandle);

  if (dlt != DLT_TO_FAKE)
  {
    snprintf (errorMsg, errorMsgSizeInBytes, "Currently only %s is the supported link type.",
              DLT_TO_FAKE_STR);
    return (FALSE);
  }
  return (TRUE);
}

PLUGIN_API BOOL GetStats (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                          OUT PLUGIN_STATS         *stats,
                          OUT char                 *errorMsg,
                          IN  size_t                errorMsgSizeInBytes)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  UNUSED (errorMsg);
  UNUSED (errorMsgSizeInBytes);

  *stats = instanceHandle->stats;

  return (TRUE);
}

PLUGIN_API BOOL SetReadTimeout (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                                IN  int                   timeoutMs,
                                OUT char                 *errorMsg,
                                IN  size_t                errorMsgSizeInBytes)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  UNUSED (errorMsg);
  UNUSED (errorMsgSizeInBytes);

  instanceHandle->readTimeoutMs = timeoutMs;

  return (TRUE);
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
