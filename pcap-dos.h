/*
 * Internal details for libpcap on DOS.
 * 32-bit targets: djgpp, Pharlap or DOS4GW.
 */

#ifndef __PCAP_DOS_H
#define __PCAP_DOS_H

#ifdef __DJGPP__
  #include <pc.h>    /* simple non-conio kbhit */
#else
  #include <conio.h>
#endif

typedef int            BOOL;
typedef unsigned char  BYTE;
typedef unsigned short WORD;
typedef unsigned long  DWORD;
typedef BYTE           ETHER[6];

#define ETH_ALEN       sizeof(ETHER)   /* Ether address length */
#define ETH_HLEN       (2*ETH_ALEN+2)  /* Ether header length  */
#define ETH_MTU        1500
#define ETH_MIN        60
#define ETH_MAX        (ETH_MTU+ETH_HLEN)

#ifndef TRUE
  #define TRUE   1
  #define FALSE  0
#endif

#define PHARLAP  1
#define DJGPP    2
#define DOS4GW   4

#ifdef __DJGPP__
  #undef  DOSX
  #define DOSX DJGPP
#endif

#ifdef __WATCOMC__
  #undef  DOSX
  #define DOSX DOS4GW
#endif

#ifdef __HIGHC__
  #include <pharlap.h>
  #undef  DOSX
  #define DOSX PHARLAP
  #define inline
#else
  typedef unsigned int UINT;
#endif

#if defined(__GNUC__) || defined(__HIGHC__)
  typedef unsigned long long  uint64;
  typedef unsigned long long  QWORD;
#endif

#if defined(__WATCOMC__)
  typedef unsigned __int64  uint64;
  typedef unsigned __int64  QWORD;
#endif

#define ARGSUSED(x)  (void) x

#if defined (__SMALL__) || defined(__LARGE__)
  #define DOSX 0

#elif !defined(DOSX)
  #error DOSX not defined; 1 = PharLap, 2 = djgpp, 4 = DOS4GW
#endif

#ifdef __HIGHC__
#define min(a,b) _min(a,b)
#define max(a,b) _max(a,b)
#endif

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define max(a,b) ((a) < (b) ? (b) : (a))
#endif

#if !defined(_U_) && defined(__GNUC__)
#define _U_  __attribute__((unused))
#endif

#ifndef _U_
#define _U_
#endif

extern int pcap_pkt_debug;

extern void _w32_os_yield (void); /* Watt-32's misc.c */

#ifdef NDEBUG
  #define PCAP_ASSERT(x) ((void)0)
#else
  extern void pcap_assert (const char *what, const char *file, unsigned line);
  #define PCAP_ASSERT(x) do { \
                           if (!(x)) \
                              pcap_assert (#x, __FILE__, __LINE__); \
                         } while (0)
#endif

#endif  /* __PCAP_DOS_H */
