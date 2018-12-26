/*
 * A Bluetooth API sniffer plugin for WinPcap.
 *
 * Highly experimental at the moment (june 2014).
 *
 * This is the main source-code for 'winpcap_btooth_plugin.dll'
 * which is loaded by the WinPcap plugin handler in pcap-plugin.c.
 *
 * By G. Vanem <gvanem@yahoo.no> 2013.
 */

#define INITGUID
#define COMPILING_PCAP_PLUGIN
#define PLUGIN_INSTANCE_TYPE  struct _PluginInstance
#define PCAP_PLUGIN_NAME      "PCAP-BlueTooth"
#define TRACE_PREFIX          "[Bluetooth] "

#define __FILE()              "WinPcap-plugin/BlueTooth/win_btooth.c"

#include "./Win32/config.h"

#if defined(HAVE_BLUETOOTH)  /* Rest of file */

#if !defined(_MSC_VER) && !defined(GCC_MAKE_DEPEND)
  #error For MSVC only
#endif

#include <windows.h>
#include <pcap-int.h>

#if !defined(NTDDI_VERSION) || (NTDDI_VERSION < NTDDI_WINXPSP2)
  #undef  NTDDI_VERSION
  #define NTDDI_VERSION NTDDI_WINXPSP2
#endif

#include <BluetoothAPIs.h>
#include <Setupapi.h>
#include <devguid.h>

#define DLT_TO_FAKE       DLT_BLUETOOTH_HCI_H4_WITH_PHDR
#define DLT_TO_FAKE_STR  "DLT_BLUETOOTH_HCI_H4_WITH_PHDR"

struct _PluginInstance;    /* Forward */

#include "./WinPcap-Plugins/pcap-plugin-interface.h"

static int init_win_bluetooth (void);
static int enum_netcards (void);

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

PLUGIN_API BOOL GetPluginName (OUT char  *out,
                               IN  size_t nameSizeInBytes)
{
  const char *name = PCAP_PLUGIN_NAME;

  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);
  pcap_strlcpy (out, name, nameSizeInBytes);
  return (TRUE);
}

PLUGIN_API VOID FreeDeviceList (IN OUT PLUGIN_DEVICE_DESCRIPTION *devices)
{
  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);

  while (devices)
  {
    PLUGIN_DEVICE_DESCRIPTION *next = devices->next;

    free (devices);
    devices = next;
  }
}

PLUGIN_API BOOL GetDeviceList (OUT PLUGIN_DEVICE_DESCRIPTION **devices,
                               OUT char                       *errorMsg,
                               IN  size_t                      errorMsgSizeInBytes)
{
  PLUGIN_DEVICE_DESCRIPTION *newDeviceDesc;

  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);

  if (!init_win_bluetooth() || !enum_netcards())
     return (FALSE);

  newDeviceDesc = calloc (sizeof(*newDeviceDesc), 1);
  if (!newDeviceDesc)
  {
    strncpy (errorMsg, "Failed to allocate memory for the device description", errorMsgSizeInBytes);
    FreeDeviceList (*devices);
    return (FALSE);
  }

  snprintf (newDeviceDesc->name, sizeof(newDeviceDesc->name), "\\\\" PCAP_PLUGIN_NAME);
  snprintf (newDeviceDesc->description, sizeof(newDeviceDesc->description), "BlueTooth Device");

  newDeviceDesc->next = *devices;
  *devices = newDeviceDesc;

  return (TRUE);
}

PLUGIN_API BOOL OpenInstance (IN  char                  *deviceName,
                              OUT PLUGIN_INSTANCE_TYPE **instanceHandle,
                              OUT char                  *errorMsg,
                              IN  size_t                 errorMsgSizeInBytes)
{
  PLUGIN_INSTANCE_TYPE *newInstance = calloc (sizeof(*newInstance)+strlen(deviceName)+1, 1);

  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);

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
  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);
  free (instanceHandle);
}

PLUGIN_API int GetLinkType (IN PLUGIN_INSTANCE_TYPE *instanceHandle)
{
  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);
  UNUSED (instanceHandle);

  return (DLT_TO_FAKE);
}

PLUGIN_API BOOL GetSupportedDlts (IN     PLUGIN_INSTANCE_TYPE *instanceHandle,
                                  IN OUT UINT                 *dltList,
                                  IN     size_t                dltListSizeInBytes,
                                  OUT    size_t               *dltCount)
{
  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);

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
                             IN   size_t               errorMsgSizeInBytes)
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
  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);

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
  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);

  UNUSED (errorMsg);
  UNUSED (errorMsgSizeInBytes);

  instanceHandle->readTimeoutMs = timeoutMs;

  return (TRUE);
}

PLUGIN_API BOOL GetNextPacket (IN  PLUGIN_INSTANCE_TYPE  *instanceHandle,
                               OUT PLUGIN_PACKET_HEADER **packetHeader,
                               OUT void                 **packet,
                               OUT char                  *errorMsg,
                               IN  size_t                 errorMsgSizeInBytes)
{
  FILETIME currentTime;
  UINT64   uTime;
  size_t   i = 0;

  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);

  UNUSED (errorMsg);
  UNUSED (errorMsgSizeInBytes);

  *packetHeader = NULL;
  *packet = NULL;

  instanceHandle->packetHeader.caplen = 128;
  instanceHandle->packetHeader.len = 128;
  instanceHandle->stats.received++;

  GetSystemTimeAsFileTime (&currentTime);

  uTime = ((UINT64)(currentTime.dwHighDateTime)) << 32;
  uTime += currentTime.dwLowDateTime;

  uTime /= 10;

  /* We now have the number of micro seconds since January 1, 1601.
   * We need the number of micro seconds since January 1, 1970.
   * Subtract the number of micro seconds between the two dates.
   */
  uTime -= 11644473600000000ULL;

  instanceHandle->packetHeader.ts.tv_sec  = (UINT32)(uTime / 1000000);
  instanceHandle->packetHeader.ts.tv_usec = (UINT32)(uTime % 1000000);

  for (i = 0; i < instanceHandle->packetHeader.caplen; ++i)
  {
    if (i == sizeof(struct timeval))
    {
      memcpy (&instanceHandle->packet[i], "BlueTooth", 9);
      i += 9;
    }
    else
    {
      instanceHandle->packet[i] = instanceHandle->packet[i-1] + 1;
    }
  }

  Sleep (100);
  *packetHeader = &instanceHandle->packetHeader;
  *packet = instanceHandle->packet;

  return (TRUE);
}

PLUGIN_API BOOL SetBufferSize (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                               IN  size_t                sizeInBytes,
                               OUT char                 *errorMsg,
                               IN  size_t                errorMsgSizeInBytes)
{
  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);

  UNUSED (instanceHandle);
  UNUSED (sizeInBytes);
  UNUSED (errorMsg);
  UNUSED (errorMsgSizeInBytes);

  return (TRUE);
}

PLUGIN_API BOOL SetMinToCopy (IN  PLUGIN_INSTANCE_TYPE *instanceHandle,
                              IN  size_t                sizeInBytes,
                              OUT char                 *errorMsg,
                              IN  size_t                errorMsgSizeInBytes)
{
  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);

  UNUSED (instanceHandle);
  UNUSED (sizeInBytes);
  UNUSED (errorMsg);
  UNUSED (errorMsgSizeInBytes);

  return (TRUE);
}

/*
 * Removes end-of-line termination from a string.
 */
char *strip_nl (char *s)
{
  char *p;

  if ((p = strrchr(s,'\n')) != NULL) *p = '\0';
  if ((p = strrchr(s,'\r')) != NULL) *p = '\0';
  return (s);
}

/*
 * Return err-number+string for 'err'. Use only with GetLastError().
 * Does not handle libc errno's. Remove trailing [\r\n.]
 */
char *win_strerror (unsigned long err)
{
  static char buf[512+20];
  char   err_buf[512], *p;

  if (!FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err,
                      LANG_NEUTRAL, err_buf, sizeof(err_buf)-1, NULL))
     strcpy (err_buf, "Unknown error");
  snprintf (buf, sizeof(buf), "%lu: %s", err, err_buf);
  strip_nl (buf);
  p = strrchr (buf, '.');
  if (p && p[1] == '\0')
     *p = '\0';
  return (buf);
}

static int init_win_bluetooth (void)
{
  BLUETOOTH_FIND_RADIO_PARAMS bt;
  HANDLE                      bt_hnd;
  HBLUETOOTH_RADIO_FIND       rc = NULL;

  bt.dwSize = sizeof(bt);

  rc = BluetoothFindFirstRadio (&bt, &bt_hnd);
  if (!rc)
       PCAP_TRACE (2, "BluetoothFindFirstRadio(): %s\n", win_strerror(GetLastError()));
  else BluetoothFindRadioClose (rc);
  return (rc ? 1 : 0);
}

static int enum_netcards (void)
{
#if (NTDDI_VERSION < NTDDI_VISTA)
  #pragma message ("Win-Vista (or later) SDK is required to compile this.")
#else

  static const GUID GUID_DEVCLASS_NET__ = { 0x4d36e972, 0xe325, 0x11ce,
                                            { 0xbf,0xc1,0x08,0x00,0x2b,0xe1,0x03,0x18 }
                                          };

  SP_DEVINFO_DATA DeviceInfoData;
  HDEVINFO        DeviceInfoSet;
  int             DeviceIndex, rc = 0;
  BOOL            rc1 = TRUE, rc2 = TRUE;

  DeviceInfoSet = SetupDiGetClassDevs (&GUID_DEVCLASS_NET__, NULL, NULL, DIGCF_PRESENT);
  memset (&DeviceInfoData, '\0', sizeof(DeviceInfoData));
  DeviceInfoData.cbSize = sizeof(DeviceInfoData);

  for (DeviceIndex = 0; rc1; DeviceIndex++)
  {
    DEVPROPKEY  DEVPKEY_Device_Class;
    DEVPROPTYPE PropType;
    GUID        DevGuid;
    DWORD       Size, Error;

    rc1 = SetupDiEnumDeviceInfo (DeviceInfoSet, DeviceIndex, &DeviceInfoData);
    if (!rc1)
       break;

   /*
    * From https://msdn.microsoft.com/en-us/library/windows/hardware/ff551963%28v=vs.85%29.aspx
    *   "SetupAPI supports only a Unicode version of SetupDiGetDeviceProperty."
    */
    rc2 = SetupDiGetDevicePropertyW (DeviceInfoSet,
                                     &DeviceInfoData,
                                     &DEVPKEY_Device_Class,
                                     &PropType,
                                     (BYTE*)&DevGuid,
                                     sizeof(GUID),
                                     &Size, 0);

    if (!rc2 || PropType != DEVPROP_TYPE_GUID)
    {
      Error = GetLastError();
      if (Error == ERROR_NOT_FOUND)
         PCAP_TRACE (2, "SetupDiGetDeviceProperty(): %s\n", win_strerror(GetLastError()));
    }
    else
      rc++;
  }

  if (DeviceInfoSet)
     SetupDiDestroyDeviceInfoList (DeviceInfoSet);
#endif

  return (rc);
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
#endif   /* HAVE_BLUETOOTH */
