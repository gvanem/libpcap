/*
 *  This file is part of DOS-libpcap
 *  Ported to DOS/DOSX by G. Vanem <gvanem@yahoo.no>
 *
 *  pcap-dos.c: Interface to PKTDRVR network drivers only.
 *              NDIS2 + protected-mode drivers are no longer
 *              supported.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <float.h>
#include <fcntl.h>
#include <io.h>

#include "pcap-int.h"
#include "pcap-dos.h"
#include "msdos/pktdrvr.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_ether.h>
#include <net/if_packe.h>
#include <tcp.h>

/*
 * Internal variables/functions in Watt-32
 */
extern WORD  _pktdevclass;
extern BOOL  _eth_is_init;
extern int   _w32_dynamic_host;
extern int   _watt_do_exit;
extern int   _watt_is_init;
extern int   _w32__bootp_on, _w32__dhcp_on, _w32__rarp_on, _w32__do_mask_req;
extern void (*_w32_usr_post_init) (void);
extern void (*_w32_print_hook)();

extern void dbug_write (const char *);  /* pcdbug.c */
extern int  pkt_get_mtu (void);         /* pcpkt.c */

static int    ref_count = 0;
static u_long mac_count    = 0;
static u_long filter_count = 0;

int pcap_pkt_debug = -1;

static pcap_t *g_pcap = NULL;

static volatile BOOL exc_occured = 0;

static int  pcap_activate_dos (pcap_t *p);
static int  pcap_read_dos (pcap_t *p, int cnt, pcap_handler callback,
                           u_char *data);
static void pcap_cleanup_dos (pcap_t *p);
static int  pcap_stats_dos (pcap_t *p, struct pcap_stat *ps);
static int  pcap_sendpacket_dos (pcap_t *p, const void *buf, size_t len);
static int  pcap_setfilter_dos (pcap_t *p, struct bpf_program *fp);

static void close_driver (void);
static int  init_watt32 (pcap_t *p);
static int  first_init (pcap_t *p);

static void watt32_recv_hook (u_char *dummy, const struct pcap_pkthdr *p,
                              const u_char *buf);

/*
 * Private data for capturing on MS-DOS.
 */
struct pcap_dos {
       void  (*wait_proc)(void);  /* call proc while waiting */
       struct pcap_stat  stats;
     };

static int pkt_open (int promisc)
{
  PKT_RX_MODE mode;

  /* Select what traffic to receive
   */
  if (promisc)
       mode = PDRX_ALL_PACKETS;
  else mode = PDRX_BROADCAST;

  if (!PktInitDriver(mode))
     return (0);

  PktResetStatistics (pktInfo.handle);
  PktQueueBusy (FALSE);
  return (1);
}

static int pkt_xmit (pcap_t *p, const void *buf, int len)
{
  struct pcap_dos *pd = p->priv;

  if (pcap_pkt_debug > 0)
     dbug_write ("pcap_xmit\n");

  if (!PktTransmit(buf,len))
  {
    pd->stats.ps_tx_err++;
    return (0);
  }
  return (len);
}

static void *pkt_stats (pcap_t *p)
{
  struct pcap_dos *pd = p->priv;

  if (!pd || !PktSessStatistics(pktInfo.handle))
     return (NULL);

  pd->stats.ps_recv   = pktStat.inPackets;
  pd->stats.ps_ifdrop = pktStat.lost;
  pd->stats.ps_drop   = PktRxDropped();
  return (&pd->stats);
}

/*
 * Return network statistics
 */
static int pcap_stats_dos (pcap_t *p, struct pcap_stat *ps)
{
  struct pcap_stat *stats = pkt_stats (p);

  if (!stats)
  {
    strcpy (p->errbuf, "device statistics not available");
    return (-1);
  }
  if (ps)
     *ps = *stats;
  return (0);
}

pcap_t *pcap_create_interface (const char *device _U_, char *ebuf)
{
  pcap_t *p = pcap_create_common(ebuf, sizeof (struct pcap_dos));

  if (!p)
     return (NULL);

  p->activate_op = pcap_activate_dos;
  return (p);
}

/*
 * Open MAC-driver with name 'device_name' for live capture of
 * network packets.
 */
static int pcap_activate_dos (pcap_t *pcap)
{
  if (pcap->opt.rfmon) {
    /*
     * No monitor mode on DOS.
     */
    return (PCAP_ERROR_RFMON_NOTSUP);
  }

  /*
   * Turn a negative snapshot value (invalid), a snapshot value of
   * 0 (unspecified), or a value bigger than the normal maximum
   * value, into the maximum allowed value.
   *
   * If some application really *needs* a bigger snapshot
   * length, we should just increase MAXIMUM_SNAPLEN.
   */
  if (pcap->snapshot <= 0 || pcap->snapshot > MAXIMUM_SNAPLEN)
     pcap->snapshot = MAXIMUM_SNAPLEN;

  if (pcap->snapshot < ETH_MIN+8)
     pcap->snapshot = ETH_MIN+8;

  if (pcap->snapshot > ETH_MAX)   /* silently accept and truncate large MTUs */
     pcap->snapshot = ETH_MAX;

  pcap->linktype        = DLT_EN10MB;  /* !! */
  pcap->cleanup_op      = pcap_cleanup_dos;
  pcap->read_op         = pcap_read_dos;
  pcap->stats_op        = pcap_stats_dos;
  pcap->inject_op       = pcap_sendpacket_dos;
  pcap->setfilter_op    = pcap_setfilter_dos;
  pcap->setdirection_op = NULL;  /* Not implemented.*/
  pcap->fd              = ++ref_count;

  pcap->bufsize = ETH_MAX+100;     /* add some margin */
  pcap->buffer = calloc (pcap->bufsize, 1);

  if (ref_count == 1)  /* first time we're called */
  {
    if (!init_watt32(pcap) || !first_init(pcap))
    {
      /* The above 'pcap->buffer' should gets freed in 'pcap_cleanup_live_common()'
       */
      return (PCAP_ERROR);
    }
    g_pcap = pcap;
    atexit (close_driver);
  }
  return (0);
}

/*
 * Poll the receiver queue and call the pcap callback-handler
 * with the packet.
 */
static int
pcap_read_one (pcap_t *p, pcap_handler callback, u_char *data)
{
  struct pcap_dos   *pd = p->priv;
  struct pcap_pkthdr pcap;
  struct timeval     now, expiry = { 0,0 };
  int    rx_len = 0;

  if (p->opt.timeout > 0)
  {
    gettimeofday2 (&now, NULL);
    expiry.tv_usec = now.tv_usec + 1000UL * p->opt.timeout;
    expiry.tv_sec  = now.tv_sec;
    while (expiry.tv_usec >= 1000000L)
    {
      expiry.tv_usec -= 1000000L;
      expiry.tv_sec++;
    }
  }

  while (!exc_occured)
  {
    rx_len = PktReceive (p->buffer, p->snapshot);

    if (rx_len > 0)  /* got a packet */
    {
      mac_count++;

      pcap.caplen = min (rx_len, p->snapshot);
      pcap.len    = rx_len;

      if (callback &&
          (!p->fcode.bf_insns || bpf_filter(p->fcode.bf_insns, p->buffer, pcap.len, pcap.caplen)))
      {
        filter_count++;

        /* Fix-me!! Should be time of arrival. Not time of
         * capture.
         */
        gettimeofday2 (&pcap.ts, NULL);
        (*callback) (data, &pcap, p->buffer);
      }

      if (pcap_pkt_debug > 0)
      {
        if (callback == watt32_recv_hook)
             dbug_write ("pcap_recv_hook\n");
        else dbug_write ("pcap_read_op\n");
      }
      return (1);
    }

    /* Has "pcap_breakloop()" been called?
     */
    if (p->break_loop)
    {
      /*
       * Yes - clear the flag that indicates that it
       * has, and return -2 to indicate that we were
       * told to break out of the loop.
       */
      p->break_loop = 0;
      return (-2);
    }

    /* If not to wait for a packet or pcap_cleanup_dos() called from
     * e.g. SIGINT handler, exit loop now.
     */
    if (p->opt.timeout <= 0 || (volatile int)p->fd <= 0)
       break;

    gettimeofday2 (&now, NULL);

    if (timercmp(&now, &expiry, >))
       break;

#ifndef DJGPP
    kbhit();    /* a real CPU hog */
#endif

    if (pd->wait_proc)
      (*pd->wait_proc)();     /* call yield func */
  }

  if (rx_len < 0)            /* receive error */
  {
    pd->stats.ps_drop++;
    return (-1);
  }
  return (0);
}

static int
pcap_read_dos (pcap_t *p, int cnt, pcap_handler callback, u_char *data)
{
  int rc, num = 0;

  while (num <= cnt || PACKET_COUNT_IS_UNLIMITED(cnt))
  {
    if (p->fd <= 0)
       return (-1);
    rc = pcap_read_one (p, callback, data);
    if (rc > 0)
       num++;
    if (rc < 0)
       break;
    _w32_os_yield();  /* allow SIGINT generation, yield to Win95/NT */
  }
  return (num);
}

/*
 * Simply store the filter-code for the pcap_read_dos() callback
 * Some day the filter-code could be handed down to the active
 * device (pkt_rx1.s or 32-bit device interrupt handler).
 */
static int pcap_setfilter_dos (pcap_t *p, struct bpf_program *fp)
{
  if (!p)
     return (-1);
  p->fcode = *fp;
  return (0);
}

/*
 * Return # of packets received in pcap_read_dos()
 */
u_long pcap_mac_packets (void)
{
  return (mac_count);
}

/*
 * Return # of packets passed through filter in pcap_read_dos()
 */
u_long pcap_filter_packets (void)
{
  return (filter_count);
}

/*
 * Close pcap device. Not called for offline captures.
 */
static void pcap_cleanup_dos (pcap_t *pcap)
{
  if (!exc_occured)
  {
    struct pcap_dos *pd = pcap->priv;

    if (pcap_stats(pcap,NULL) < 0)
       pd->stats.ps_drop = 0;
    pcap->fd = 0;
    if (ref_count > 0)
        ref_count--;
    if (ref_count > 0)
       return;
  }
  close_driver();
  pcap_cleanup_live_common (pcap);
}

/*
 * Return the name of a PktDrvr interface,
 * or NULL if none can be found.
 */
char *pcap_lookupdev (char *ebuf)
{
  if (PktSearchDriver())
     return ("pkt");
  if (ebuf)
     strcpy (ebuf, "No driver found");
  return (NULL);
}

/*
 * Gets localnet & netmask from Watt-32.
 */
int pcap_lookupnet (const char *device, bpf_u_int32 *localnet,
                    bpf_u_int32 *netmask, char *errbuf)
{
  DWORD mask, net;

  if (!_watt_is_init)
  {
    strcpy (errbuf, "pcap_open_offline() or pcap_activate() must be "
                    "called first");
    return (-1);
  }

  mask  = _w32_sin_mask;
  net = my_ip_addr & mask;
  if (net == 0)
  {
    if (IN_CLASSA(*netmask))
       net = IN_CLASSA_NET;
    else if (IN_CLASSB(*netmask))
       net = IN_CLASSB_NET;
    else if (IN_CLASSC(*netmask))
       net = IN_CLASSC_NET;
    else
    {
      pcap_snprintf (errbuf, PCAP_ERRBUF_SIZE, "inet class for 0x%lx unknown", mask);
      return (-1);
    }
  }
  *localnet = htonl (net);
  *netmask = htonl (mask);

  ARGSUSED (device);
  return (0);
}

/*
 * Get a list of all interfaces that are present and that we probe okay.
 * Returns -1 on error, 0 otherwise.
 * The list may be NULL empty if no interfaces were up and could be opened.
 */
int pcap_platform_finddevs (pcap_if_list_t *devlistp, char *errbuf)
{
  pcap_if_t         *curdev;
  struct sockaddr_in sa_ll_1, sa_ll_2;
  struct sockaddr   *addr, *netmask, *broadaddr, *dstaddr;
  pcap_if_list_t    *devlist = NULL;
  int                ret = 0;
  int                found = 0;

  if (!PktSearchDriver())
     goto fail;

  close_driver();

  /*
   * XXX - find out whether it's up or running?  Does that apply here?
   */
  curdev = add_dev (devlist, "pkt", 0, "Packet-Driver", errbuf);
  if (!curdev)
  {
    ret = -1;
    goto fail;
  }

  found = 1;
  memset (&sa_ll_1, 0, sizeof(sa_ll_1));
  memset (&sa_ll_2, 0, sizeof(sa_ll_2));
  sa_ll_1.sin_family = AF_INET;
  sa_ll_2.sin_family = AF_INET;

  addr      = (struct sockaddr*) &sa_ll_1;
  netmask   = (struct sockaddr*) &sa_ll_1;
  dstaddr   = (struct sockaddr*) &sa_ll_1;
  broadaddr = (struct sockaddr*) &sa_ll_2;
  memset (&sa_ll_2.sin_addr, 0xFF, sizeof(sa_ll_2.sin_addr));

  if (add_addr_to_dev(curdev, addr, sizeof(*addr),
                      netmask, sizeof(*netmask),
                      broadaddr, sizeof(*broadaddr),
                      dstaddr, sizeof(*dstaddr), errbuf) < 0)
  {
    ret = -1;
    goto fail;
  }

fail:
  if (ret == 0 && !found)
     strcpy (errbuf, "No Pkt-Driver found");

  return (ret);
}

/*
 * pcap_assert() is mainly used for debugging
 */
void pcap_assert (const char *what, const char *file, unsigned line)
{
  fprintf (stderr, "%s (%u): Assertion \"%s\" failed\n",
           file, line, what);
  close_driver();
  _exit (-1);
}

/*
 * For pcap_offline_read(): wait and yield between printing packets
 * to simulate the pace packets where actually recorded.
 */
void pcap_set_wait (pcap_t *pcap, void (*yield)(void), int wait)
{
  if (pcap)
  {
    struct pcap_dos *pd = pcap->priv;

    pd->wait_proc  = yield;
    pcap->opt.timeout = wait;
  }
}

/*
 * Initialise the PktDrvr.
 */
static int open_driver (pcap_t *pcap)
{
  if (!PktSearchDriver())
  {
    pcap_snprintf (pcap->errbuf, PCAP_ERRBUF_SIZE, "failed to detect a Pkt-Driver");
    return (0);
  }

  if (!pkt_open(pcap->opt.promisc))
  {
    pcap_snprintf (pcap->errbuf, PCAP_ERRBUF_SIZE, "failed to activate the Pkt-Driver");
    if (pktInfo.error)
    {
      strcat (pcap->errbuf, ": ");
      strcat (pcap->errbuf, pktInfo.error);
    }
    return (0);
  }
  return (1);
}

/*
 * Deinitialise MAC driver.
 * Set receive mode back to default mode.
 */
static void close_driver (void)
{
  if (g_pcap)
  {
    BOOL okay = PktExitDriver();

    if (pcap_pkt_debug > 1)
       fprintf (stderr, "close_driver(): %d\n", okay);
    g_pcap = NULL;
  }
}

#ifdef __DJGPP__
static void setup_signals (void (*handler)(int))
{
  signal (SIGSEGV,handler);
  signal (SIGILL, handler);
  signal (SIGFPE, handler);
}

static void exc_handler (int sig)
{
  switch (sig)
  {
    case SIGSEGV:
         fputs ("Catching SIGSEGV.\n", stderr);
         break;
    case SIGILL:
         fputs ("Catching SIGILL.\n", stderr);
         break;
    case SIGFPE:
         _fpreset();
         fputs ("Catching SIGFPE.\n", stderr);
         break;
    default:
         fprintf (stderr, "Catching signal %d.\n", sig);
  }
  exc_occured = 1;
  close_driver();
}
#endif  /* __DJGPP__ */


/*
 * Open the pcap device for the first client calling pcap_activate()
 */
static int first_init (pcap_t *pcap)
{
#ifdef __DJGPP__
  setup_signals (exc_handler);
#endif

  if (!open_driver(pcap))
  {
#ifdef __DJGPP__
    setup_signals (SIG_DFL);
#endif
    return (0);
  }
  return (1);
}

/*
 * Hook functions for using Watt-32 together with libpcap
 */
static char   rxbuf [ETH_MAX+100]; /* rx-buffer with some margin */
static WORD   etype;
static pcap_t pcap_save;

static void watt32_recv_hook (u_char *dummy, const struct pcap_pkthdr *pcap,
                              const u_char *buf)
{
  /* Fix me: assumes Ethernet II only */
  struct ether_header *ep = (struct ether_header*) buf;

  memcpy (rxbuf, buf, pcap->caplen);
  etype = ep->ether_type;
  ARGSUSED (dummy);
}

#if (WATTCP_VER >= 0x0224)
/*
 * This function is used by Watt-32 to poll for a packet.
 * i.e. it's set to bypass _eth_arrived()
 */
static void *pcap_recv_hook (WORD *type)
{
  int len = pcap_read_dos (&pcap_save, 1, watt32_recv_hook, NULL);

  if (len < 0)
     return (NULL);

  *type = etype;
  return (void*) &rxbuf;
}

/*
 * This function is called by Watt-32 (via _eth_xmit_hook).
 * If dbug_init() was called, we should trace packets sent.
 */
static int pcap_xmit_hook (const void *buf, unsigned len)
{
  int rc = 0;

  if (pcap_pkt_debug > 0)
     dbug_write ("pcap_xmit_hook: ");

   if (pkt_xmit(g_pcap, buf, len) > 0)
      rc = len;

  if (pcap_pkt_debug > 0)
     dbug_write (rc ? "ok\n" : "fail\n");
  return (rc);
}
#endif

static int pcap_sendpacket_dos (pcap_t *pcap, const void *buf, size_t len)
{
  if (pcap->fd > -1)
     return pkt_xmit (pcap, buf, len);
  strcpy (pcap->errbuf, "Pkt-Driver not initialised");
  return (-1);
}

/*
 * This function is called by Watt-32 in tcp_post_init().
 * We should prevent Watt-32 from using BOOTP/DHCP/RARP etc.
 */
static void (*prev_post_hook) (void);

static void pcap_init_hook (void)
{
  _w32__bootp_on = _w32__dhcp_on = _w32__rarp_on = 0;
  _w32__do_mask_req = 0;
  _w32_dynamic_host = 0;
  if (prev_post_hook)
    (*prev_post_hook)();
}

/*
 * Supress PRINT message from Watt-32's sock_init()
 */
static void null_print (void) {}

/*
 * To use features of Watt-32 (netdb functions and socket etc.)
 * we must call sock_init(). But we set various hooks to prevent
 * using normal PKTDRVR functions in pcpkt.c. This should hopefully
 * make Watt-32 and libpcap co-operate.
 */
static int init_watt32 (pcap_t *pcap)
{
  char *env;
  int   rc, MTU;

  /* If user called sock_init() first, we need to reinit in
   * order to open debug/trace-file properly
   */
  if (_watt_is_init)
     sock_exit();

  env = getenv ("PCAP_TRACE");
  if (env && atoi(env) > 0 && pcap_pkt_debug < 0)   /* if not already set */
  {
    dbug_init();
    pcap_pkt_debug = atoi (env);
  }

  _watt_do_exit      = 0;    /* prevent sock_init() calling exit() */
  prev_post_hook     = _w32_usr_post_init;
  _w32_usr_post_init = pcap_init_hook;
  _w32_print_hook    = null_print;

  rc = sock_init();
  _watt_is_init = 1;

  if (rc)
  {
    pcap_snprintf (pcap->errbuf, PCAP_ERRBUF_SIZE, "sock_init() failed, code %d", rc);
    return (0);
  }

  /* Set recv-hook for peeking in _eth_arrived().
   */
#if (WATTCP_VER >= 0x0224)
  _eth_recv_hook = pcap_recv_hook;
  _eth_xmit_hook = pcap_xmit_hook;
#endif

  /* Free the pkt-drvr handle allocated in pkt_init().
   * The above hooks should thus use the handle reopened in open_driver()
   */
  _eth_release();
/*_eth_is_init = 1; */  /* hack to get Rx/Tx-hooks in Watt-32 working */

  memcpy (&pcap_save, pcap, sizeof(pcap_save));
  MTU = pkt_get_mtu();
  pcap_save.fcode.bf_insns = NULL;
  pcap_save.linktype       = _eth_get_hwtype (NULL, NULL);
  pcap_save.snapshot       = MTU > 0 ? MTU : ETH_MAX; /* assume 1514 */

#if 1
  /* prevent use of resolve() and resolve_ip()
   */
  last_nameserver = 0;
#endif

  return (1);
}

/*
 * Application config hooks to set various driver parameters.
 */
static const struct config_table debug_tab[] = {
            { "PKT.DEBUG",  ARG_ATOI,   &pcap_pkt_debug },
            { "PKT.VECTOR", ARG_ATOX_W, NULL            },
            { NULL }
          };

/*
 * pcap_config_hook() is an extension to application's config
 * handling. Uses Watt-32's config-table function.
 */
int pcap_config_hook (const char *keyword, const char *value)
{
  return parse_config_table (debug_tab, NULL, keyword, value);
}

#include "pcap_version.h"

/*
 * Libpcap version string.
 */
const char *
pcap_lib_version(void)
{
  return ("DOS-" PCAP_VERSION_STRING);
}

