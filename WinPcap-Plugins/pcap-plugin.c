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

#define _TCHAR_H_    /* Avoid the <tchar.h> sillyness */
#define _INC_TCHAR

#undef  TRACE_PREFIX
#define TRACE_PREFIX  "[Plugin] "

#undef  __FILE
#define __FILE()      "WinPcap-plugin/pcap-plugin.c"

#include "./Win32/config.h"

#include <pcap.h>
#include <pcap-int.h>

#include <malloc.h>
#include <memory.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "./WinPcap-Plugins/pcap-plugin.h"
#include "./WinPcap-Plugins/pcap-plugin-interface.h"

#define DIM(array)     (int) (sizeof(array) / sizeof(array[0]))

#define USE_SET_DUMMY  1

/* \todo: Use a 'smartlist_t' below?
 */
#define MAX_PLUGINS 10
#define MAX_DEVICES 10

typedef struct _PLUGIN_INSTANCE {
        char                  PluginName [MAX_PATH];
        char                  PluginModuleName [MAX_PATH];
        char                  PluginFullName [MAX_PATH];
        HMODULE               Handle;
        pcap_if_t             device_list [MAX_DEVICES];   /* We don't use the '*addresses' or 'flags' yet */
        struct bpf_program   *fcode [MAX_DEVICES];

        t_GetPluginApiVersion GetPluginApiVersion;
        t_GetPluginName       GetPluginName;

        t_GetDeviceList       GetDeviceList;
        t_FreeDeviceList      FreeDeviceList;

        t_OpenInstance        OpenInstance;
        t_CloseInstance       CloseInstance;

        t_GetLinkType         GetLinkType;
        t_GetSupportedDlts    GetSupportedDlts;

        t_GetStats            GetStats;
        t_SetPacketFilter     SetPacketFilter;
        t_SetReadTimeout      SetReadTimeout;
        t_GetNextPacket       GetNextPacket;
        t_GetReadEvent        GetReadEvent;
        t_InjectPacket        InjectPacket;
        t_SetDirection        SetDirection;
        t_SetDatalink         SetDatalink;
        t_IsNonBlocking       IsNonBlocking;
        t_SetNonBlocking      SetNonBlocking;
        t_SetBufferSize       SetBufferSize;
        t_SetMode             SetMode;
        t_SetMinToCopy        SetMinToCopy;
      } PLUGIN_INSTANCE;

static PLUGIN_INSTANCE g_Plugins [MAX_PLUGINS];
static int             g_PluginCount  = 0;
static int             g_moduleCount  = 0;
static int             g_good_devices = 0;

static BOOL is_wow64_active (void);
static BOOL is_plugin_device (const char *device);
static void plugin_kill_instance (pcap_t *p, PLUGIN_INSTANCE *plugin);
static int  plugin_read (pcap_t *p, int cnt, pcap_handler callback, u_char *user);
static int  plugin_inject (pcap_t *p, const void *buf, size_t size);
static int  plugin_set_packet_filter (pcap_t *p, struct bpf_program *fp);
static int  plugin_setdirection (pcap_t *p, pcap_direction_t dir);
static int  plugin_set_datalink (pcap_t *p, int dlt);
static int  plugin_getnonblock (pcap_t *p);
static int  plugin_setnonblock (pcap_t *p, int non_block);
static int  plugin_setnonblock_nop (pcap_t *p, int non_block);
static int  plugin_stats (pcap_t *p, struct pcap_stat *ps);
static int  plugin_setbuff (pcap_t *p, int dim);
static int  plugin_setmode (pcap_t *p, int mode);
static int  plugin_setmintocopy (pcap_t *p, int size);
static void plugin_cleanup (pcap_t *p);
static BOOL plugin_find_device (const char *device, int *pluginIndex);

struct plugin_priv {
       void  *PluginInstanceHandle;
       int    PluginIndex;
     };

void plugin_exit (void)
{
  int i, j;

  PCAP_TRACE (2, "plugin_exit():\n");
  for (i = 0; i < g_PluginCount; i++)
  {
    PLUGIN_INSTANCE *plugin = g_Plugins + i;
    const pcap_if_t  *dev;

    PCAP_TRACE (2, "g_plugin[%d]: PluginName: %s\n", i, plugin->PluginName);
    plugin_kill_instance (NULL, plugin);  /* Plug the leakage in 'pcap_findalldevs()' */
  }
}

static int dummy_common (pcap_t *p, const char *op_code)
{
  PCAP_TRACE (2, "Alert!!\n"
              "       dummy_%s() unexpectedly called for device \"%s\"\n",
              op_code, p->opt.device);
  return (PCAP_ERROR);
}

#define DUMMY_FUNC(x)                            \
        static int __cdecl dummy_##x (pcap_t *p) \
        {                                        \
          return dummy_common (p, #x);           \
        }

DUMMY_FUNC (read_op)
DUMMY_FUNC (next_packet_op)
DUMMY_FUNC (inject_op)
DUMMY_FUNC (save_current_filter_op)
DUMMY_FUNC (setfilter_op)
DUMMY_FUNC (setdirection_op)
DUMMY_FUNC (set_datalink_op)
DUMMY_FUNC (getnonblock_op)
DUMMY_FUNC (setnonblock_op)
DUMMY_FUNC (stats_op)
DUMMY_FUNC (stats_ex_op)
DUMMY_FUNC (setbuff_op)
DUMMY_FUNC (setmode_op)
DUMMY_FUNC (setmintocopy_op)
DUMMY_FUNC (getevent_op)
DUMMY_FUNC (oid_get_request_op)
DUMMY_FUNC (oid_set_request_op)
DUMMY_FUNC (sendqueue_transmit_op)
DUMMY_FUNC (setuserbuffer_op)
DUMMY_FUNC (live_dump_op)
DUMMY_FUNC (live_dump_ended_op)
DUMMY_FUNC (get_airpcap_handle_op)
DUMMY_FUNC (cleanup_op)

#define SET_DUMMY(pcap, x)              pcap->x = (x##_t) dummy_##x
#define SET_FUNC(pcap, plugin_func, x)  do {                              \
                                          if (plugin_func)                \
                                               pcap->x##_op = plugin_##x; \
                                          else SET_DUMMY (pcap, x##_op);  \
                                        } while (0)

#if (USE_SET_DUMMY == 1)
/*
 * All the '*_op' functions pointers are defined in pcap-int.h in
 * 'struct pcap'. This function sets all of them to point to
 * 'dummy_xx()'. So in the case a plugin developer fails to add
 * some '*_op', we get an 'PCAP_ERROR' returned to the caller of
 * the pcap function or an 'abort()' above.
 */
static void plugin_initialize_ops_to_dummies (pcap_t *p)
{
  SET_DUMMY (p, read_op);
  SET_DUMMY (p, next_packet_op);
  SET_DUMMY (p, inject_op);
  SET_DUMMY (p, save_current_filter_op);
  SET_DUMMY (p, setfilter_op);
  SET_DUMMY (p, setdirection_op);
  SET_DUMMY (p, set_datalink_op);
  SET_DUMMY (p, getnonblock_op);
  SET_DUMMY (p, setnonblock_op);
  SET_DUMMY (p, stats_op);
  SET_DUMMY (p, stats_ex_op);
  SET_DUMMY (p, setbuff_op);
  SET_DUMMY (p, setmode_op);
  SET_DUMMY (p, setmintocopy_op);
  SET_DUMMY (p, getevent_op);
  SET_DUMMY (p, oid_get_request_op);
  SET_DUMMY (p, oid_set_request_op);
  SET_DUMMY (p, sendqueue_transmit_op);
  SET_DUMMY (p, setuserbuffer_op);
  SET_DUMMY (p, live_dump_op);
  SET_DUMMY (p, live_dump_ended_op);
  SET_DUMMY (p, get_airpcap_handle_op);
  SET_DUMMY (p, cleanup_op);
}
#endif

static void plugin_initialize_ops (pcap_t *p, PLUGIN_INSTANCE *plugin)
{
  p->cleanup_op   = plugin_cleanup;
  p->setfilter_op = plugin_set_packet_filter;

#if (USE_SET_DUMMY == 0)
  SET_FUNC (p, plugin->GetNextPacket,  read);
  SET_FUNC (p, plugin->InjectPacket,   inject);
  SET_FUNC (p, plugin->SetDirection,   setdirection);
  SET_FUNC (p, plugin->SetDatalink,    set_datalink);
  SET_FUNC (p, plugin->IsNonBlocking,  getnonblock);
  SET_FUNC (p, plugin->SetNonBlocking, setnonblock);
  SET_FUNC (p, plugin->GetStats,       stats);
  SET_FUNC (p, plugin->SetBufferSize,  setbuff);
  SET_FUNC (p, plugin->SetMode,        setmode);
  SET_FUNC (p, plugin->SetMinToCopy,   setmintocopy);

#else
  if (plugin->GetNextPacket)
     p->read_op = plugin_read;

  if (plugin->InjectPacket)
     p->inject_op = plugin_inject;

  if (plugin->SetDirection)
     p->setdirection_op = plugin_setdirection;

  if (plugin->SetDatalink)
     p->set_datalink_op = plugin_set_datalink;

  if (plugin->IsNonBlocking)
     p->getnonblock_op = plugin_getnonblock;

  if (plugin->SetNonBlocking)
       p->setnonblock_op = plugin_setnonblock;
  else p->setnonblock_op = plugin_setnonblock_nop;

  if (plugin->GetStats)
     p->stats_op = plugin_stats;

  if (plugin->SetBufferSize)
     p->setbuff_op = plugin_setbuff;

  if (plugin->SetMode)
     p->setmode_op = plugin_setmode;

  if (plugin->SetMinToCopy)
     p->setmintocopy_op = plugin_setmintocopy;
#endif /* USE_SET_DUMMY == 0 */
}

static inline PLUGIN_INSTANCE *plugin_get_instance (pcap_t *p, void **handle)
{
  const struct plugin_priv *priv;

  assert (p);
  assert (p->priv);
  priv = (const struct plugin_priv*) p->priv;

  if (handle)
     *handle = priv->PluginInstanceHandle;
  return (g_Plugins + priv->PluginIndex);
}

static pcap_if_t *plugin_search_device_list (PLUGIN_INSTANCE *plugin, const char *device)
{
  int i;

  for (i = 0; i < DIM(plugin->device_list); i++)
  {
    pcap_if_t *dev = plugin->device_list + i;

    if (dev->name && !strcmp(device,dev->name))
       return (dev);
  }
  return (NULL);
}

static void plugin_kill_instance (pcap_t *p, PLUGIN_INSTANCE *plugin)
{
  int i;

  if (p)
  {
    struct plugin_priv *priv;

    assert (p->priv);
    priv = (struct plugin_priv*) p->priv;
    priv->PluginInstanceHandle = NULL;
  }

  PCAP_TRACE (2, "plugin_kill_instance (\"%s\"):\n", plugin->PluginName);

  for (i = 0; i < DIM(plugin->device_list); i++)
  {
    pcap_if_t           *dev = plugin->device_list + i;
    char                *next = dev->name;
    struct bpf_program  *fcode = plugin->fcode[i];
    char   buf [10];

    PCAP_TRACE (2, "  [%d]: dev->name: %s, fcode: %p (%s bytes)\n",
                i, dev->name, (const void*)fcode,
                fcode ? itoa(fcode->bf_len,buf,10) : "<N/A>");

    if (plugin->fcode[i])
       pcap_freecode (plugin->fcode[i]);

    if (dev->name)
       free (dev->name);

    if (dev->description)
       free (dev->description);

    dev->name = dev->description = NULL;
    plugin->fcode[i] = NULL;
    if (!next)
       break;
  }
}

/*
 * Call the plugin's 'GetDeviceList()' method and create a 'device_list[]'
 * of the returned device names and the descriptions.
 *
 * I ass-u-me that the 'GetDeviceList()' never changes it's device names
 * at runtime since this function is called only once at startup.
 */
static void plugin_build_device_list (PLUGIN_INSTANCE *plugin)
{
  PLUGIN_DEVICE_DESCRIPTION *device, *devices = NULL;
  char   errbuf [PCAP_ERRBUF_SIZE];
  int    i;

  assert (plugin->device_list[0].name == NULL);
  assert (plugin->device_list[0].description == NULL);

  PCAP_TRACE (2, "plugin->GetDeviceList() returned:\n");

  errbuf[0] = '\0';
  if (!(*plugin->GetDeviceList)(&devices, errbuf, sizeof(errbuf)))
  {
    PCAP_TRACE (2, "<Nothing>: %s\n", errbuf);
    return;
  }

  for (i = 0, device = devices; device; device = device->next, i++)
  {
    pcap_if_t *dev = plugin->device_list + i;

    PCAP_TRACE (2, "  %d: \"%s\".\n", i, device->name);
    dev->name        = strdup (device->name);
    dev->description = strdup (device->description);
    g_good_devices++;

    if (i >= DIM(plugin->device_list))
       break;
  }
  (*plugin->FreeDeviceList) (devices);
}

#if defined(USE_PCAP_TRACE)
static void plugin_print_info (const PLUGIN_INSTANCE *plugin)
{
  int i, indent = sizeof(__FILE()) + 8;

  _pcap_trace_color (TRACE_COLOR_START);
  printf ("%s(%u): ", __FILE(), __LINE__);

  _pcap_trace_color (TRACE_COLOR_ARGS);
  printf ("Module: %s, name: %s\n"
          "%*sdevices(s): ",
          plugin->PluginModuleName, plugin->PluginName, indent, "");

  indent += sizeof("devices(s): ");

  _pcap_trace_color (FOREGROUND_INTENSITY | 5);  /* Bright magenta */

  for (i = 0; i < DIM(plugin->device_list); i++)
  {
    const pcap_if_t *dev = plugin->device_list + i;

    printf ("%*s %d: \"%s\" %s",
            i > 0 ? indent : 1, "", i, dev->name,
            (i == 0 && !dev->name) ? ": <No devices!!>\n" : "\n");
    if (!dev->name)
       break;
  }
  _pcap_trace_color (0);
}
#endif

static void plugin_load_one (const char *pluginModuleName, const char *pluginFullName)
{
  PLUGIN_INSTANCE *plugin = NULL;
  size_t           plugin_ver = 0;
  int              i, num_missing = 0;
  static volatile  LONG isCurrentlyLoading = FALSE;

  PCAP_TRACE (2, "plugin_load_one (\"%s\")\n", pluginFullName);

  /* Can't load more plugins than we have room for.
   */
  if (g_PluginCount >= DIM(g_Plugins))
     goto Exit;

  /* Make sure that there is only one thread in here at a time, poor man's wait lock
   */
  while (InterlockedCompareExchange(&isCurrentlyLoading, TRUE, FALSE) == TRUE)
  {
    Sleep (1);
  }

#if 0
  for (i = 0; i < g_PluginCount; i++)
  {
    plugin = g_Plugins + i;
    if (!strcmp(pluginModuleName, plugin->PluginModuleName))
       goto Exit;    /* Already loaded */
  }
#endif

  plugin = g_Plugins + g_PluginCount;
  memset (plugin, 0, sizeof(*plugin));

  /* The 'LoadLibrary()' will fail with 'GetLastError() ==  ERROR_BAD_EXE_FORMAT' (193)
   * if we're running a 32-bit WinPcap and found a 64-bit plugin. And vice-versa.
   */
  plugin->Handle = LoadLibrary (pluginFullName);
  if (!plugin->Handle)
  {
    DWORD err = GetLastError();

    if (err == ERROR_BAD_EXE_FORMAT)  /* Mixing 32/64-bit .DLLs and .EXEs */
         PCAP_TRACE (2, "  LoadLibrary(\"%s\") failed. ERROR_BAD_EXE_FORMAT.\n", pluginFullName);
    else PCAP_TRACE (2, "  LoadLibrary(\"%s\") failed. rc: %lu\n", pluginFullName, err);
    goto Exit;
  }

  pcap_strlcpy (plugin->PluginModuleName, pluginModuleName, sizeof(plugin->PluginModuleName));
  pcap_strlcpy (plugin->PluginFullName, pluginFullName, sizeof(plugin->PluginFullName));

#undef  SET_ADDR
#define SET_ADDR(required, func)                                               \
        do {                                                                   \
          plugin->func = (t_##func) GetProcAddress (plugin->Handle, #func);    \
          if (!plugin->func && required) {                                     \
            PCAP_TRACE (2, "  %s: function export '%s' is missing.\n",         \
                        pluginModuleName, #func);                              \
            num_missing++;                                                     \
          }                                                                    \
        } while (0)

  /* Core plugin functions
   */
  SET_ADDR (1, GetPluginApiVersion);
  SET_ADDR (1, GetPluginName);

  /* Required pcap function
   */
  SET_ADDR (1, GetDeviceList);
  SET_ADDR (1, FreeDeviceList);
  SET_ADDR (1, OpenInstance);
  SET_ADDR (1, CloseInstance);
  SET_ADDR (1, GetLinkType);

  /* Optional pcap function
   */
  SET_ADDR (0, GetSupportedDlts);
  SET_ADDR (0, GetStats);
  SET_ADDR (0, SetPacketFilter);
  SET_ADDR (0, SetReadTimeout);
  SET_ADDR (0, GetNextPacket);
  SET_ADDR (0, GetReadEvent);
  SET_ADDR (0, InjectPacket);
  SET_ADDR (0, SetDirection);
  SET_ADDR (0, SetDatalink);
  SET_ADDR (0, IsNonBlocking);
  SET_ADDR (0, SetNonBlocking);
  SET_ADDR (0, SetBufferSize);
  SET_ADDR (0, SetMode);
  SET_ADDR (0, SetMinToCopy);

#undef SET_ADDR

  if (num_missing > 0)
     goto Exit;

  PCAP_TRACE (2, "  %s has the needed functions exported.\n", pluginFullName);
  g_moduleCount++;

  if (!plugin->GetSupportedDlts ^ !plugin->SetDatalink)
  {
    /* Can't have the ability to retrieve the DLT list but not set the DLT and vice versa.
     */
    PCAP_TRACE (2, "  %s cannot set/get DLT.\n", pluginFullName);
    goto Exit;
  }

  plugin_ver = (*plugin->GetPluginApiVersion)();

  if (plugin_ver != PLUGIN_API_VERSION)
  {
    PCAP_TRACE (2, "  %s returned wrong version: %d (%d needed).\n",
                pluginModuleName, (int)plugin_ver, PLUGIN_API_VERSION);
    goto Exit;
  }

  if (!(*plugin->GetPluginName)(plugin->PluginName, sizeof(plugin->PluginName)))
  {
    PCAP_TRACE (2, "  %s failed to return it's name.\n", pluginFullName);
    goto Exit;
  }

  g_PluginCount++;

  plugin_build_device_list (plugin);

Exit:
  isCurrentlyLoading = FALSE;
}

static void plugin_load_all (const char *file_spec) /* \todo */
{
  char            win_dir[MAX_PATH];
  HANDLE          fileHandle;
  WIN32_FIND_DATA findFileData;
  char            pluginSearchSpec[MAX_PATH];
  const char     *sys_dir;
  static BOOL done = FALSE;

  if (done)
     return;

  PCAP_TRACE (2, "plugin_load_all().\n");

  pcap_wsockinit();
  done = TRUE;

  sys_dir = (is_wow64_active() ? "SysWOW64" : "System32");

  /* Get the location of the system directory and add on
   * the file pattern that we will use to look for plugins.
   */
  if (!GetWindowsDirectory(win_dir, sizeof(win_dir)))
  {
    /* Some error occurred while retrieving the system path */
    return;
  }

  if (!file_spec)
  {
    _snprintf (pluginSearchSpec, sizeof(pluginSearchSpec),
               "%s\\%s\\%s", win_dir, sys_dir, "winpcap_*.dll");
    file_spec = pluginSearchSpec;
  }

  PCAP_TRACE (2, "Looking for plugins: %s\n", file_spec);

  /* Find the first file
   */
  fileHandle = FindFirstFile (pluginSearchSpec, &findFileData);
  if (fileHandle == INVALID_HANDLE_VALUE)
  {
    /* Didn't find any plugins or, perhaps, some other error.
     */
    PCAP_TRACE (2, "FindFirstFile(\"%s\") failed; %lu\n",
                pluginSearchSpec, GetLastError());
    return;
  }

  do
  {
    /* Skip directories.
     */
    if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
    {
      char pluginFullName [MAX_PATH];

      _snprintf (pluginFullName, sizeof(pluginFullName), "%s\\%s\\%s",
                 win_dir, sys_dir, findFileData.cFileName);

      plugin_load_one (findFileData.cFileName, pluginFullName);
    }
  }
  while (FindNextFile(fileHandle, &findFileData));

  FindClose (fileHandle);

  PCAP_TRACE (2, "%s() finished:\n"
                 "%*sWe have %d modules and %d plugins with a total of %d devices.\n",
                 __FUNCTION__, sizeof(__FILE())+8, "",
                 g_moduleCount, g_PluginCount, g_good_devices);
}

int plugin_findalldevs (pcap_if_list_t *devlistp, char *errbuf)
{
  int i;

  PCAP_TRACE (2, "plugin_findalldevs().\n");

  plugin_load_all (NULL);

#if defined(USE_PCAP_TRACE)
  if (_pcap_trace_level() >= 2)
     for (i = 0; i < g_PluginCount; i++)
         plugin_print_info (g_Plugins + i);
#endif

  for (i = 0; i < g_PluginCount; i++)
  {
    PLUGIN_INSTANCE *plugin = g_Plugins + i;

    /* One plugin-DLL can handle several devices (or instances).
     * Loop over all of them to add a pcap-device for each.
     */
    for (i = 0; i < DIM(plugin->device_list); i++)
    {
      pcap_if_t *added, *dev = plugin->device_list + i;

      if (!dev->name)
         break;

      added = add_dev (devlistp, dev->name, 0, dev->description, errbuf);
      PCAP_TRACE (2, "add_dev (\"%s\") %s.\n", dev->name, added ? "okay" : "failed");
      if (!added)
         return (-1);
    }
  }
  return (0);
}

static int plugin_activate (pcap_t *p)
{
  struct plugin_priv *priv = p->priv;
  PLUGIN_INSTANCE    *plugin;
  void               *handle = NULL;

  PCAP_TRACE (2, "plugin_activate (\"%s\").\n", p->opt.device);

  if (!plugin_find_device(p->opt.device, &priv->PluginIndex))
  {
    pcap_strlcpy (p->errbuf, "Failed to find a plugin to service the device", PCAP_ERRBUF_SIZE);
    PCAP_TRACE (2, "%s.\n", p->errbuf);
    return (-1);
  }

  plugin = plugin_get_instance (p, NULL);

  /* This call and only this call will create the 'handle'.
   * If successful, set 'priv->PluginInstanceHandle = handle'.
   * Otherwise we might leak handles and memory.
   */
  if (!(*plugin->OpenInstance)(p->opt.device, &handle, p->errbuf, PCAP_ERRBUF_SIZE))
     return (-1);

  priv->PluginInstanceHandle = handle;

  PCAP_TRACE (2, "OpenInstance(): handle: %p.\n", handle);

  /* We need to guard 'plugin->SetReadTimeout' as it is an optional function
   */
  if (plugin->SetReadTimeout &&
      !(*plugin->SetReadTimeout)(handle, p->opt.timeout, p->errbuf, PCAP_ERRBUF_SIZE))
     return (-1);

  p->linktype = (*plugin->GetLinkType) (handle);

  if (!plugin->GetSupportedDlts)
  {
    p->dlt_list = malloc (sizeof(u_int));
    if (!p->dlt_list)
    {
      pcap_strlcpy (p->errbuf, "Failed to allocate memory for the device's DLT list", PCAP_ERRBUF_SIZE);
      return (-1);
    }
    p->dlt_list[0] = p->linktype;
    p->dlt_count = 1;
  }
  else
  {
    size_t dltCount = 0;
    size_t listSizeInBytes = sizeof(u_int);

    /* Get the list of supported DLTs from the plugin.
     * Start with an array of 2 and double the array size until the array is successfully returned.
     */
    p->dlt_list = NULL;

    do
    {
      if (p->dlt_list)
        free (p->dlt_list);

      listSizeInBytes *= 2;
      p->dlt_list = malloc (listSizeInBytes);
      if (!p->dlt_list)
      {
        pcap_strlcpy (p->errbuf, "Failed to allocate memory for the device's DLT list", PCAP_ERRBUF_SIZE);
        return (-1);
      }
    }
    while (!(*plugin->GetSupportedDlts)(handle, p->dlt_list, listSizeInBytes, &dltCount));

    p->dlt_count = (int)dltCount;
  }

  plugin_initialize_ops (p, plugin);

  if (p->snapshot <= 0 || p->snapshot > MAXIMUM_SNAPLEN)
     p->snapshot = MAXIMUM_SNAPLEN;

  return (0);
}

static BOOL is_plugin_device (const char *device)
{
  BOOL rc = plugin_find_device (device, NULL);

  PCAP_TRACE (2, "is_plugin_device (\"%s\"): is %sa plugin-device.\n",
              device, rc ? "" : "not ");
  return (rc);
}

HANDLE plugin_get_read_event (pcap_t *p)
{
  void               *handle;
  PLUGIN_INSTANCE    *plugin = plugin_get_instance (p, &handle);
  struct plugin_priv *priv   = p->priv;
  HANDLE              readEvent = NULL;

  PCAP_TRACE (2, "%s() called.\n", __FUNCTION__);

  if (!plugin->GetReadEvent)
  {
    pcap_strlcpy (p->errbuf, "This device does not support the retrieval of a read event",
                  PCAP_ERRBUF_SIZE);
    return (NULL);
  }

  if (!(*plugin->GetReadEvent)(handle, &readEvent, p->errbuf, PCAP_ERRBUF_SIZE))
     return (NULL);
  return (readEvent);
}

static int plugin_read (pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{
  void            *handle;
  PLUGIN_INSTANCE *plugin = plugin_get_instance (p, &handle);
  int              packetCount = 0;

  PCAP_TRACE (2, "%s (\"%s\") called.\n", __FUNCTION__, p->opt.device);

  if (p->break_loop)
  {
    p->break_loop = 0;
    return (-2);
  }

  do
  {
    PLUGIN_PACKET_HEADER *packetHeader;
    void                 *packet;

    if (p->break_loop)
    {
      if (packetCount == 0)
      {
        p->break_loop = 0;
        return (-2);
      }
      return (packetCount);
    }

    if (!(*plugin->GetNextPacket)(handle, &packetHeader, &packet, p->errbuf, PCAP_ERRBUF_SIZE))
       return (-1);

    if (packetHeader && packet)
    {
      struct pcap_pkthdr pcapHeader;

      pcapHeader.ts.tv_sec  = packetHeader->ts.tv_sec;
      pcapHeader.ts.tv_usec = packetHeader->ts.tv_usec;
      pcapHeader.caplen     = packetHeader->caplen;
      pcapHeader.len        = packetHeader->len;

      /* Check to see if this instance needs user mode filtering, if so then do it
       */
      if (/* p->opt.use_bpf == 0 && */ p->fcode.bf_insns)
      {
        u_int filterResult = bpf_filter (p->fcode.bf_insns, packet, pcapHeader.len, pcapHeader.caplen);

        if (filterResult == 0)
           continue;

        if (filterResult < pcapHeader.caplen)
           pcapHeader.caplen = filterResult;
      }

      (*callback) (user, &pcapHeader, packet);
      packetCount++;
    }
  } while (packetCount < cnt || cnt == -1);

  return (packetCount);
}

static int plugin_inject (pcap_t *p, const void *buf, size_t size)
{
  void            *handle;
  PLUGIN_INSTANCE *plugin = plugin_get_instance (p, &handle);

  PCAP_TRACE (2, "%s (\"%s\") called.\n", __FUNCTION__, p->opt.device);

  if (!plugin->InjectPacket ||
      !(*plugin->InjectPacket)(handle, buf, size, p->errbuf, PCAP_ERRBUF_SIZE))
     return (-1);
  return (0);
}

static int plugin_set_packet_filter (pcap_t *p, struct bpf_program *fp)
{
  void               *handle;
  PLUGIN_INSTANCE    *plugin = plugin_get_instance (p, &handle);
  struct plugin_priv *priv   = p->priv;

  PCAP_TRACE (2, "%s (\"%s\") called.\n", __FUNCTION__, p->opt.device);

  if (!fp)
  {
    pcap_strlcpy (p->errbuf, "No filter specified", PCAP_ERRBUF_SIZE);
    return (-1);
  }

  /* If the plugin provides the ability to set kernel filtering then use that.
   * Otherwise, install the filter as a user mode filter and the plugin framework
   * will handle the packet filtering.
   */
  if (plugin->SetPacketFilter)
  {
    if (!(*plugin->SetPacketFilter)(handle, fp->bf_insns,
                                    fp->bf_len * sizeof(*fp->bf_insns),
                                    p->errbuf, PCAP_ERRBUF_SIZE))
      return (-1);
  }
  else
  {
    /* Install a user level filter
     */
    if (install_bpf_program(p, fp) < 0)
    {
      snprintf (p->errbuf, sizeof(p->errbuf), "Unable to install the filter: %s",
                pcap_strerror(errno));
      return (-1);
    }

    /* Indicate that BPF filtering is to happen outside of the kernel.
     */
#if 0
    p->md.use_bpf = 0;
#endif

    plugin->fcode [priv->PluginIndex] = fp;  /* Free this in plugin_kill_instance() */
  }
  return (0);
}

static int plugin_setdirection (pcap_t *p, pcap_direction_t dir)
{
  void             *handle;
  PLUGIN_INSTANCE  *plugin = plugin_get_instance (p, &handle);
  PLUGIN_DIRECTION  localDir;

  PCAP_TRACE (2, "%s (\"%s\") called.\n", __FUNCTION__, p->opt.device);

  switch (dir)
  {
    case PCAP_D_INOUT:
         localDir = PLUGIN_DIRECTION_INOUT;
         break;
    case PCAP_D_IN:
         localDir = PLUGIN_DIRECTION_IN;
         break;
    case PCAP_D_OUT:
         localDir = PLUGIN_DIRECTION_OUT;
         break;
    default:
        pcap_strlcpy (p->errbuf, "Unknown pcap direction encountered", PCAP_ERRBUF_SIZE);
        return (-1);
  }

  if (!(*plugin->SetDirection)(handle, localDir, p->errbuf, PCAP_ERRBUF_SIZE))
     return (-1);

  return (0);
}

static int plugin_set_datalink (pcap_t *p, int dlt)
{
  void            *handle;
  PLUGIN_INSTANCE *plugin = plugin_get_instance (p, &handle);

  PCAP_TRACE (2, "%s (\"%s\") called.\n", __FUNCTION__, p->opt.device);

  if (!(*plugin->SetDatalink)(handle, dlt, p->errbuf, PCAP_ERRBUF_SIZE))
     return (-1);
  return (0);
}

static int plugin_getnonblock (pcap_t *p)
{
  void            *handle;
  PLUGIN_INSTANCE *plugin = plugin_get_instance (p, &handle);
  BOOL             blocking;

  PCAP_TRACE (2, "%s (\"%s\") called.\n", __FUNCTION__, p->opt.device);

  if (!(*plugin->IsNonBlocking)(handle, &blocking, p->errbuf, PCAP_ERRBUF_SIZE))
     return (-1);
  return (blocking);
}

static int plugin_setnonblock (pcap_t *p, int non_block)
{
  void            *handle;
  PLUGIN_INSTANCE *plugin = plugin_get_instance (p, &handle);

  PCAP_TRACE (2, "%s (\"%s\", %d) called.\n", __FUNCTION__, p->opt.device, non_block);

  if (!(*plugin->SetNonBlocking)(handle, non_block, p->errbuf, PCAP_ERRBUF_SIZE))
     return (-1);
  return (0);
}

static int plugin_setnonblock_nop (pcap_t *p, int non_block)
{
  PCAP_TRACE (2, "%s (\"%s\", %d) called.\n", __FUNCTION__, p->opt.device, non_block);
  return (0);
}

static int plugin_stats (pcap_t *p, struct pcap_stat *ps)
{
  void            *handle;
  PLUGIN_INSTANCE *plugin = plugin_get_instance (p, &handle);
  PLUGIN_STATS     stats;

  PCAP_TRACE (2, "%s (\"%s\") called.\n", __FUNCTION__, p->opt.device);

  memset (&stats, 0, sizeof(stats));
  memset (ps, 0, sizeof(*ps));

  if (!(*plugin->GetStats)(handle, &stats, p->errbuf, PCAP_ERRBUF_SIZE))
     return (-1);

  ps->ps_recv = stats.received;
  ps->ps_drop = stats.dropped;
  return (0);
}

static int plugin_setbuff (pcap_t *p, int dim)
{
  void            *handle;
  PLUGIN_INSTANCE *plugin = plugin_get_instance (p, &handle);

  PCAP_TRACE (2, "%s (\"%s\") called.\n", __FUNCTION__, p->opt.device);

  if (!(*plugin->SetBufferSize)(handle, dim, p->errbuf, PCAP_ERRBUF_SIZE))
     return (-1);
  return (0);
}

static int plugin_setmode (pcap_t *p, int mode)
{
  void            *handle;
  PLUGIN_INSTANCE *plugin = plugin_get_instance (p, &handle);
  PLUGIN_MODE      localMode;

  PCAP_TRACE (2, "%s (\"%s\") called.\n", __FUNCTION__, p->opt.device);

  switch (mode)
  {
    case MODE_CAPT:
         localMode = PLUGIN_MODE_CAPT;
         break;
    case MODE_STAT:
         localMode = PLUGIN_MODE_STAT;
         break;
    default:
        pcap_strlcpy (p->errbuf, "Unknown pcap mode encountered", PCAP_ERRBUF_SIZE);
        return (-1);
  }

  if (!(*plugin->SetMode)(handle, localMode, p->errbuf, PCAP_ERRBUF_SIZE))
     return (-1);
  return (0);
}

static int plugin_setmintocopy (pcap_t *p, int size)
{
  void            *handle;
  PLUGIN_INSTANCE *plugin = plugin_get_instance (p, &handle);

  PCAP_TRACE (2, "%s (\"%s\") called.\n", __FUNCTION__, p->opt.device);

  if (!(*plugin->SetMinToCopy)(handle, size, p->errbuf, PCAP_ERRBUF_SIZE))
     return (-1);
  return (0);
}

static void plugin_cleanup (pcap_t *p)
{
  void            *handle;
  PLUGIN_INSTANCE *plugin = plugin_get_instance (p, &handle);

  /* We cannot use 'p->opt.device' here since it was freed in 'pcap_close()'
   * right before we got called.
   */
  PCAP_TRACE (2, "plugin_cleanup (\"%s\") called.\n", plugin->PluginName);

  (*plugin->CloseInstance) (handle);
  plugin_kill_instance (p, plugin);
  pcap_cleanup_live_common (p);
}

static int plugin_can_set_rfmon (pcap_t *p)
{
  UNUSED (p);
  return (0);
}

/*
 * Called from pcap.c in '(*capture_source_types[].create_op)()'.
 */
pcap_t *plugin_create (const char *device, char *ebuf, int *is_ours)
{
  pcap_if_t *our_dev = NULL;
  pcap_if_t *dev;
  pcap_t    *p;
  int        i, j;

  plugin_load_all (NULL);

  *is_ours = 0;

  PCAP_TRACE (2, "plugin_create (\"%s\").\n", device);

  if (!plugin_find_device(device,NULL))
     return (NULL);

  *is_ours = 1;
  p = pcap_create_common (ebuf, sizeof(struct plugin_priv));
  if (!p)
     return (NULL);

#if 0  /* How to use these? */
  pcap_do_addexit (p);
  pcap_add_to_pcaps_to_close (p);
#endif

#if (USE_SET_DUMMY == 1)
  plugin_initialize_ops_to_dummies (p);
#endif

  p->activate_op      = plugin_activate;
  p->can_set_rfmon_op = plugin_can_set_rfmon;
  return (p);
}

static BOOL plugin_find_device (const char *device, int *pluginIndex)
{
  int i;

  if (pluginIndex)
     *pluginIndex = -1;

  for (i = 0; i < g_PluginCount; i++)
  {
    if (plugin_search_device_list(g_Plugins+i, device))
    {
      if (pluginIndex)
         *pluginIndex = i;
      return (TRUE);
    }
  }
  return (FALSE);
}

/*
 * Check if running under WOW64 (Windows-on-Windows).
 * Should always be FALSE for 64-bit processes and FALSE
 * for a 32-bit Windows.
 */
static BOOL is_wow64_active (void)
{
  BOOL rc    = FALSE;
  BOOL wow64 = FALSE;

  typedef BOOL (WINAPI *func_IsWow64Process) (HANDLE proc, BOOL *wow64);
  func_IsWow64Process p_IsWow64Process;

  const  char *dll = "kernel32.dll";
  HANDLE hnd = LoadLibrary (dll);

  if (!hnd || hnd == INVALID_HANDLE_VALUE)
  {
    PCAP_TRACE (2, "Failed to load %s; %lu\n", dll, GetLastError());
    return (rc);
  }

  p_IsWow64Process = (func_IsWow64Process) GetProcAddress (hnd, "IsWow64Process");
  if (!p_IsWow64Process)
  {
    PCAP_TRACE (2, "Failed to find \"p_IsWow64Process()\" in %s; %lu\n",
                dll, GetLastError());
    FreeLibrary (hnd);
    return (rc);
  }

  if (p_IsWow64Process)
     if ((*p_IsWow64Process)(GetCurrentProcess(), &wow64))
        rc = wow64;
  FreeLibrary (hnd);

  PCAP_TRACE (2, "is_wow64_active(): rc: %d, wow64: %d.\n", rc, wow64);
  return (rc);
}

