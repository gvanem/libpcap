/*
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

 /* \todo: if this is a plugin, make sure 'pw->adapter' is NULL
  *        since it makes sense only to NPF/NPcap/Win10Pcap adapters.
  *        But how to do that best?
  */
#if 1
  return (pw ? pw->adapter : NULL);
#else
  return ((pw && p->handle && p->handle != INVALID_HANDLE_VALUE) ? pw->adapter : NULL);
#endif
}

#if defined(_MSC_VER) && defined(_DEBUG)
static _CrtMemState last_state;

static void crtdbug_exit (void)
{
#ifdef PCAP_SUPPORT_PLUGINS
  extern void plugin_exit (void);
  plugin_exit();
#endif

  _CrtMemDumpAllObjectsSince (&last_state);
  _CrtMemDumpStatistics (&last_state);
#if 0
  _CrtCheckMemory();
  _CrtDumpMemoryLeaks();
#endif
}

void crtdbug_init (void)
{
  static int done = 0;

  if (done)
     return;

  _CrtSetReportFile (_CRT_WARN, _CRTDBG_FILE_STDERR);
  _CrtSetReportMode (_CRT_WARN, _CRTDBG_MODE_FILE);
  _CrtSetDbgFlag (_CRTDBG_LEAK_CHECK_DF     |
                  _CRTDBG_DELAY_FREE_MEM_DF |
                  _CRTDBG_ALLOC_MEM_DF      |
                  _CrtSetDbgFlag(_CRTDBG_REPORT_FLAG));
  _CrtMemCheckpoint (&last_state);
  atexit (crtdbug_exit);
  done = 1;
}
#endif

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

#if 0
/*
 * This is needed in optimize.c. But not for MSVC. So just add it here.
 */
#if defined(__MINGW32__)
int ffs(int mask)
{
  return __builtin_ffs(mask);
}

#elif !defined (_MSC_VER)
/*
 * ffs -- vax ffs instruction
 * Copyright (C) 1991, 1992 Free Software Foundation, Inc.
 * Contributed by Torbjorn Granlund (tege@sics.se).
 */
int ffs(int mask)
{
  static unsigned char table[] = {
    0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
    6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
    8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8
  };
  unsigned long a, x = mask & (-mask);

  a = x <= 0xFFFFUL ? (x <= 0xFF ? 0 : 8) : (x <= 0xFFFFFF ? 16 : 24);
  return (table[x >> a] + a);
}
#endif
#endif  /* 0 */

#ifdef HAVE_AIRPCAP_API  /* Rest of file */

#include <airpcap.h>

#if defined(USE_WIN10PCAP)
  #error Win10Pcap with AirPcap is not supported at the moment.
#endif

#if defined(USE_NPCAP) && 0
  #error NPcap with AirPcap is not supported at the moment.
#endif

/* Copied from Packet32-int.h:
 */
typedef PCHAR (*AirpcapGetLastErrorHandler) (struct _AirpcapHandle *Handle);
typedef BOOL  (*AirpcapSetLinkTypeHandler) (struct _AirpcapHandle *Handle,
                                            AirpcapLinkType LinkLayer);
typedef struct _AirpcapHandle * (*AirpcapOpenHandler) (char *DeviceName, char *Ebuf);

/* Set in Packet32.c
 */
/* PCAP_API_DEF */ AirpcapGetLastErrorHandler g_PAirpcapGetLastError;
/* PCAP_API_DEF */ AirpcapSetLinkTypeHandler  g_PAirpcapSetLinkType;
/* PCAP_API_DEF */ AirpcapOpenHandler         g_PAirpcapOpen;

/* A private in Packet32.c
 */
void PacketLoadLibrariesDynamically (void);

static int pcap_set_datalink_airpcap (pcap_t *p, int dlt)
{
  struct pcap_win *pw = p->priv;
  struct _AirpcapHandle *hnd = PacketGetAirPcapHandle (pw->adapter);
  AirpcapLinkType type;

  PCAP_TRACE (2, "hnd: %p, g_PAirpcapSetLinkType: %p\n",
              (const void*)hnd, (const void*)g_PAirpcapSetLinkType);

  if (!hnd)
  {
    pcap_snprintf (p->errbuf, PCAP_ERRBUF_SIZE,
                  "handle from PacketGetAirPcapHandle() is NULL");
    return (-1);
  }

  if (!g_PAirpcapSetLinkType)
  {
    pcap_snprintf (p->errbuf, PCAP_ERRBUF_SIZE,
                  "(*g_PAirpcapSetLinkType) is NULL");
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
         pcap_snprintf (p->errbuf, PCAP_ERRBUF_SIZE,
                        "Unsupported dlt: %d\n", dlt);
         PCAP_TRACE (2, "%s", p->errbuf);
         return (-1);
  }

  p->linktype = dlt;

  if ((*g_PAirpcapSetLinkType)(hnd, type))
     return (0);

  pcap_snprintf (p->errbuf, PCAP_ERRBUF_SIZE,
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

