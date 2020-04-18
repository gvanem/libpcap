/**
 * This stuff must be included from pcap-npf.c only.
 * And not compiled on it's own.
 *
 * Reason is that it needs the definition of
 * 'struct pcap_win' in pcap-npf.c.
 */
#ifdef BDEBUG
int dflag;
#endif

#if defined(USE_WIN10PCAP)
  struct bpf_stat {
         UINT bs_recv;
         UINT bs_drop;
         UINT ps_ifdrop;
         UINT bs_capt;
       };

  struct bpf_hdr {
         struct timeval bh_tstamp;
         UINT           bh_caplen;
         UINT           bh_datalen;
         USHORT         bh_hdrlen;
       };
#endif

PCAP_API ADAPTER *pcap_get_adapter (pcap_t *p);

ADAPTER *pcap_get_adapter (pcap_t *p)
{
  struct pcap_win *pw;

  if (!p)
     return (NULL);

  pw = p->priv;

 /**
  * \todo: if this is a plugin, make sure 'pw->adapter' is NULL
  *        since it makes sense only to NPF/NPcap/Win10Pcap adapters.
  *        But how to do that best?
  */
#if 1
  return (pw ? pw->adapter : NULL);
#else
  return ((pw && p->handle && p->handle != INVALID_HANDLE_VALUE) ? pw->adapter : NULL);
#endif
}

#if defined(_MSC_VER)

static void _plugin_cleanup (void)
{
#ifdef PCAP_SUPPORT_PLUGINS
  extern void plugin_exit (void);
  plugin_exit();
#endif
}

#if defined(USE_VLD)
static void crtdbug_exit (void)
{
  _plugin_cleanup();
  VLDGlobalDisable();
  printf ("VLD leaks: %u\n", VLDReportLeaks());
}

void crtdbug_init (void)
{
  static int done = 0;
  VLD_UINT opts;

  if (done)
     return;

  atexit (crtdbug_exit);

  /* Force all reports to "stdout" in "ASCII"
   */
  VLDSetReportOptions (VLD_OPT_REPORT_TO_STDOUT, NULL);

  opts = VLDGetOptions();
  opts |= VLD_OPT_SAFE_STACK_WALK;

  /* Force all reports to "stdout" in "ASCII"
   */
  VLDSetOptions (opts, 100, 4);

  /* Needed to get filename and line-numbers correctly reported
   */
  VLDResolveCallstacks();
  done = 1;
}

#elif defined(_DEBUG)
/**
 * Only effective for 'cl' + 'clang-cl' using '-MDd' or '-MTd'.
 */
static _CrtMemState last_state;

static void crtdbug_exit (void)
{
  _CrtMemState new_state, diff_state;

  _plugin_cleanup();

  _CrtMemCheckpoint (&new_state);

  /* No significant difference in the mem-state. So just get out.
   */
  if (!_CrtMemDifference(&diff_state, &last_state, &new_state))
     return;

  _CrtCheckMemory();
  _CrtMemDumpAllObjectsSince (&last_state);
  _CrtDumpMemoryLeaks();
}

void crtdbug_init (void)
{
  static int done = 0;
  _HFILE file;
  int    flags, mode;

  if (done)
     return;

  atexit (crtdbug_exit);

  file = _CRTDBG_FILE_STDERR;
  mode = _CRTDBG_MODE_FILE;

  /* Let all CRT asserts, errors and warnings go to 'stderr'.
   */
  _CrtSetReportFile (_CRT_ASSERT, file);
  _CrtSetReportMode (_CRT_ASSERT, mode);
  _CrtSetReportFile (_CRT_ERROR, file);
  _CrtSetReportMode (_CRT_ERROR, mode);
  _CrtSetReportFile (_CRT_WARN, file);
  _CrtSetReportMode (_CRT_WARN, mode);

  flags = _CRTDBG_LEAK_CHECK_DF | _CRTDBG_DELAY_FREE_MEM_DF | _CRTDBG_ALLOC_MEM_DF;
  flags |= _CrtSetDbgFlag (_CRTDBG_REPORT_FLAG);

  _CrtSetDbgFlag (flags);
  _CrtMemCheckpoint (&last_state);
  done = 1;
}

#else
void crtdbug_init (void)
{
}
#endif  /* _DEBUG */
#endif  /* _MSC_VER */

/* Watcom is really no longer supported.
 */
#if defined(__WATCOMC__)
char *str_rip (char *s)
{
  char *p;

  if ((p = strrchr(s,'\n')) != NULL) *p = '\0';
  if ((p = strrchr(s,'\r')) != NULL) *p = '\0';
  return (s);
}

const char *gai_strerror (int err)
{
  static char err_buf [512];

  err_buf[0] = '\0';
  FormatMessageA (FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS |
                  FORMAT_MESSAGE_MAX_WIDTH_MASK,
                  NULL, err, LANG_NEUTRAL,
                  err_buf, sizeof(err_buf)-1, NULL);
  return str_rip (err_buf);
}
#endif

#ifdef HAVE_AIRPCAP_API  /* Rest of file */
#include <airpcap.h>

/* Copied from Packet32-int.h:
 */
typedef PCHAR (*AirpcapGetLastErrorHandler) (struct _AirpcapHandle *Handle);
typedef BOOL  (*AirpcapSetLinkTypeHandler) (struct _AirpcapHandle *Handle,
                                            AirpcapLinkType LinkLayer);
typedef struct _AirpcapHandle * (*AirpcapOpenHandler) (char *DeviceName, char *Ebuf);

/* Initialised by 'GetProcAddress (AirpcapLib,"xx")' in Packet32.c
 */
AirpcapGetLastErrorHandler g_PAirpcapGetLastError;
AirpcapSetLinkTypeHandler  g_PAirpcapSetLinkType;
AirpcapOpenHandler         g_PAirpcapOpen;

static int pcap_set_datalink_airpcap (pcap_t *p, int dlt)
{
  struct pcap_win *pw = p->priv;
  struct _AirpcapHandle *hnd = PacketGetAirPcapHandle (pw->adapter);
  AirpcapLinkType type;

  PCAP_TRACE (2, "hnd: %p, g_PAirpcapSetLinkType: %p\n",
              (const void*)hnd, (const void*)g_PAirpcapSetLinkType);

  if (!hnd)
  {
    snprintf (p->errbuf, PCAP_ERRBUF_SIZE, "handle from PacketGetAirPcapHandle() is NULL");
    return (-1);
  }

  if (!g_PAirpcapSetLinkType)
  {
    snprintf (p->errbuf, PCAP_ERRBUF_SIZE, "(*g_PAirpcapSetLinkType) is NULL");
    return (-1);
  }

  switch (dlt) {
    case DLT_IEEE802_11:
         type = AIRPCAP_LT_802_11;
         PCAP_TRACE (2, "DLT_IEEE802_11\n");
         break;
    case DLT_IEEE802_11_RADIO:
         type = AIRPCAP_LT_802_11_PLUS_RADIO;
         PCAP_TRACE (2, "DLT_IEEE802_11_RADIO\n");
         break;
    case DLT_PPI:
         type = AIRPCAP_LT_802_11_PLUS_PPI;
         PCAP_TRACE (2, "DLT_PPI\n");
         break;
     default:
         snprintf (p->errbuf, PCAP_ERRBUF_SIZE, "Unsupported dlt: %d\n", dlt);
         PCAP_TRACE (2, "%s", p->errbuf);
         return (-1);
  }

  p->linktype = dlt;

  if ((*g_PAirpcapSetLinkType)(hnd, type))
     return (0);

  snprintf (p->errbuf, PCAP_ERRBUF_SIZE,
            "(*g_PAirpcapSetLinkType)() failed: %s\n",
            (*g_PAirpcapGetLastError)(hnd));
  PCAP_TRACE (2, "%s", p->errbuf);
  return (-1);
}

static void init_airpcap_dlts (pcap_t *p)
{
  p->dlt_list = (u_int *) malloc(sizeof(u_int) * 4);
  if (!p->dlt_list)
     return;

  p->dlt_list[0] = DLT_DOCSIS;
  p->dlt_list[1] = DLT_IEEE802_11;
  p->dlt_list[2] = DLT_IEEE802_11_RADIO;
  p->dlt_list[3] = DLT_PPI;
  p->dlt_count = 4;

  PCAP_TRACE (2, "p->dlt_list: %p, p->dlt_count: %d\n", (const void*)p->dlt_list, p->dlt_count);
}
#endif  /* HAVE_AIRPCAP_API */

