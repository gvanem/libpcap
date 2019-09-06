/*
 * Copyright (c) 2011, Dustin Johnson (Dustin@Dustinj.us)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#define PLUGIN_INSTANCE_TYPE   PluginInstance
#define PCAP_PLUGIN_NAME       "ExamplePlugin"
#define TRACE_PREFIX           "[Example] "
#define NUM_DEVICES            2

#define __FILE()               "WinPcap-plugin/example/example_plugin.c"

#include "./Win32/config.h"

typedef struct _PluginInstance PluginInstance;

#include <pcap/dlt.h>
#include <pcap-int.h>

#include "./WinPcap-Plugins/pcap-plugin-interface.h"

typedef struct _PluginInstance {
    char                *deviceName;
    PLUGIN_PACKET_HEADER packetHeader;
    UINT8                packet[1024*10];
    int                  readTimeoutMs;
    PLUGIN_STATS         stats;
  } PluginInstance;


PLUGIN_API size_t GetPluginApiVersion (void)
{
  PCAP_TRACE (3, "%s() called, ver: %d.\n",  __FUNCTION__, PLUGIN_API_VERSION);
  return (PLUGIN_API_VERSION);
}

PLUGIN_API BOOL GetPluginName (OUT char  *out,
                               IN  size_t nameSizeInBytes)
{
  const char *name = PCAP_PLUGIN_NAME;

  PCAP_TRACE (3, "%s() called -> %s\n",  __FUNCTION__, name);
  pcap_strlcpy (out, name, nameSizeInBytes);
  return (TRUE);
}

PLUGIN_API void FreeDeviceList (IN OUT PLUGIN_DEVICE_DESCRIPTION *devices)
{
  PCAP_TRACE (3, "%s() called.\n",  __FUNCTION__);

  while (devices)
  {
    PLUGIN_DEVICE_DESCRIPTION *tmpEntry = devices->next;

    free (devices);
    devices = tmpEntry;
  }
}

PLUGIN_API BOOL GetDeviceList (OUT PLUGIN_DEVICE_DESCRIPTION **devices,
                               OUT char                       *errorMsg,
                               IN  size_t                      errorMsgSizeInBytes)
{
  unsigned i = 0;

  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  for (i = 1; i <= NUM_DEVICES; ++i)
  {
    PLUGIN_DEVICE_DESCRIPTION *newDeviceDesc = calloc (sizeof(*newDeviceDesc), 1);

    if (!newDeviceDesc)
    {
      pcap_strlcpy (errorMsg, "Failed to allocate memory for the device description", errorMsgSizeInBytes);
      FreeDeviceList (*devices);
      return (FALSE);
    }

    snprintf (newDeviceDesc->name, sizeof(newDeviceDesc->name), "\\\\" PCAP_PLUGIN_NAME "\\#%u", i);
    snprintf (newDeviceDesc->description, sizeof(newDeviceDesc->description), PCAP_PLUGIN_NAME " #%u", i);

    newDeviceDesc->next = *devices;
    *devices = newDeviceDesc;
  }
  return (TRUE);
}

PLUGIN_API BOOL OpenInstance (IN  char            *deviceName,
                              OUT PluginInstance **instanceHandle,
                              OUT char            *errorMsg,
                              IN  size_t           errorMsgSizeInBytes)
{
  PluginInstance *newInstance = calloc (sizeof(*newInstance), 1);

  PCAP_TRACE (3, "%s (\"%s\") called.\n", __FUNCTION__, deviceName);

  if (!newInstance)
  {
    pcap_strlcpy (errorMsg, "Failed to allocate memory for the instance handle", errorMsgSizeInBytes);
    return (FALSE);
  }
  newInstance->deviceName = strdup (deviceName);
  *instanceHandle = newInstance;
  return (TRUE);
}

PLUGIN_API void CloseInstance (IN PluginInstance *instanceHandle)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);
  free (instanceHandle->deviceName);
  free (instanceHandle);
}

PLUGIN_API int GetLinkType (IN PluginInstance *instanceHandle)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);
  UNUSED (instanceHandle);

  return (DLT_NULL);
}

PLUGIN_API BOOL GetSupportedDlts (IN     PluginInstance *instanceHandle,
                                  IN OUT UINT           *dltList,
                                  IN     size_t          dltListSizeInBytes,
                                  OUT    size_t         *dltCount)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  UNUSED (instanceHandle);

  *dltCount = 3;

  if (dltListSizeInBytes < sizeof(UINT)*(*dltCount))
     return (FALSE);

  dltList[0] = 0;   /* DLT_NULL   */
  dltList[1] = 1;   /* DLT_EN10MB */
  dltList[2] = 147; /* DLT_USER0  */

  return (TRUE);
}

PLUGIN_API BOOL SetDatalink (IN  PluginInstance *instanceHandle,
                             IN  int             dlt,
                             OUT char           *errorMsg,
                             IN  size_t          errorMsgSizeInBytes)
{
  UNUSED (instanceHandle);

  if (dlt != 0 && dlt != 1 && dlt != 147)
  {
    pcap_strlcpy (errorMsg, "Currently, DLT_NULL, DLT_EN10MB and DLT_USER0 are the only supported link types",
                  errorMsgSizeInBytes);
    return (FALSE);
  }
  return (TRUE);
}

PLUGIN_API BOOL GetStats (IN  PluginInstance *instanceHandle,
                          OUT PLUGIN_STATS   *stats,
                          OUT char           *errorMsg,
                          IN  size_t          errorMsgSizeInBytes)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  UNUSED (errorMsg);
  UNUSED (errorMsgSizeInBytes);

  *stats = instanceHandle->stats;

  return (TRUE);
}

PLUGIN_API BOOL SetReadTimeout (IN  PluginInstance *instanceHandle,
                                IN  int             timeoutMs,
                                OUT char           *errorMsg,
                                IN  size_t          errorMsgSizeInBytes)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  UNUSED (errorMsg);
  UNUSED (errorMsgSizeInBytes);

  instanceHandle->readTimeoutMs = timeoutMs;

  return (TRUE);
}

PLUGIN_API BOOL GetNextPacket (IN  PluginInstance        *instanceHandle,
                               OUT PLUGIN_PACKET_HEADER **packetHeader,
                               OUT void                 **packet,
                               OUT char                  *errorMsg,
                               IN  size_t                 errorMsgSizeInBytes)
{
  size_t i = 0;
  FILETIME currentTime;
  UINT64   uTime;

  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

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
  uTime -= 11644473600000000L;

  instanceHandle->packetHeader.ts.tv_sec  = (UINT32)(uTime / 1000000);
  instanceHandle->packetHeader.ts.tv_usec = (UINT32)(uTime % 1000000);

  for (i = 0; i < instanceHandle->packetHeader.caplen; ++i)
  {
    if (i == 8 /* sizeof(struct timeval) */)
    {
      memcpy (&instanceHandle->packet[i], "Example", 6);
      i += 6;
    }
    else
      instanceHandle->packet[i] = instanceHandle->packet[i-1] + 1;
  }

  Sleep (500);
  *packetHeader = &instanceHandle->packetHeader;
  *packet = instanceHandle->packet;

  return (TRUE);
}

PLUGIN_API BOOL SetBufferSize (IN  PluginInstance *instanceHandle,
                               IN  size_t          sizeInBytes,
                               OUT char           *errorMsg,
                               IN  size_t          errorMsgSizeInBytes)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  UNUSED (instanceHandle);
  UNUSED (sizeInBytes);
  UNUSED (errorMsg);
  UNUSED (errorMsgSizeInBytes);

  return (TRUE);
}

PLUGIN_API BOOL SetMinToCopy (IN  PluginInstance *instanceHandle,
                              IN  size_t          sizeInBytes,
                              OUT char           *errorMsg,
                              IN  size_t          errorMsgSizeInBytes)
{
  PCAP_TRACE (3, "%s() called.\n", __FUNCTION__);

  UNUSED (instanceHandle);
  UNUSED (sizeInBytes);
  UNUSED (errorMsg);
  UNUSED (errorMsgSizeInBytes);

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
