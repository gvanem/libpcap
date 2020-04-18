
#include "Win32/config.h"

#include <pcap-int.h>
#include <iphlpapi.h>

/* Printing a wide string on Windows.
 * E.g. printf (buf, "%"WIDESTR_FMT, wide_str);
 *
 * Note: we don't build with -D_UNICODE. Hence Ascii formats sometimes
 *       need to print wide-chars using this format.
 */
#if defined(__GNUC__)
  #define WIDESTR_FMT  "S"
#else
  #define WIDESTR_FMT  "wS"
#endif

#if defined(USE_PCAP_TRACE)
  #define SET_COLOR(color)  _pcap_trace_color (color)
#else
  #define SET_COLOR(color)
#endif

static void _cprintf (int color, const char *fmt, ...)
{
  char    buf [200];
  va_list args;

  va_start (args, fmt);
  SET_COLOR (color);
  fflush (stdout);

  vsnprintf (buf, sizeof(buf), fmt, args);
  va_end (args);
  fputs (buf, stdout);
  fflush (stdout);
  SET_COLOR (0);
}

static void PCAP_NORETURN Usage (const char *argv0)
{
  printf (" Usage: %s family\n", argv0);
  printf ("        %s 4 (for IPv4)\n", argv0);
  printf ("        %s 6 (for IPv6)\n", argv0);
  printf ("        %s * (for unspecified families)\n", argv0);
  exit (1);
}

int main (int argc, char **argv)
{
  DWORD    dwRetVal = 0;
  unsigned i = 0;
  int color[4] = { 0,
                   FOREGROUND_INTENSITY | 3,  /* bright cyan */
                   FOREGROUND_INTENSITY | 7,  /* bright white */
                   FOREGROUND_INTENSITY | 4,  /* bright red */
                 };

  /* Set the flags to pass to GetAdaptersAddresses */
  ULONG flags = GAA_FLAG_INCLUDE_PREFIX;

  /* default to unspecified address family (both) */
  ULONG family = AF_UNSPEC;

  LPVOID lpMsgBuf = NULL;

  PIP_ADAPTER_ADDRESSES pAddresses = NULL;
  ULONG                 outBufLen = 0;

  PIP_ADAPTER_ADDRESSES          pCurrAddresses = NULL;
  PIP_ADAPTER_UNICAST_ADDRESS    pUnicast = NULL;
  PIP_ADAPTER_ANYCAST_ADDRESS    pAnycast = NULL;
  PIP_ADAPTER_MULTICAST_ADDRESS  pMulticast = NULL;
  IP_ADAPTER_DNS_SERVER_ADDRESS *pDnServer = NULL;
  IP_ADAPTER_PREFIX             *pPrefix = NULL;

  if (argc != 2)
     Usage (argv[0]);

  if (atoi(argv[1]) == 4)
     family = AF_INET;
  else if (atoi(argv[1]) == 6)
     family = AF_INET6;
  else if (argv[1][0] == '*')
  {
    family = AF_UNSPEC;
    flags |= GAA_FLAG_INCLUDE_ALL_INTERFACES;
  }
  else
    Usage (argv[0]);

  outBufLen = sizeof (IP_ADAPTER_ADDRESSES);
  pAddresses = alloca (outBufLen);

  /* Make an initial call to GetAdaptersAddresses to get the
   * size needed into the outBufLen variable
   */
  if (GetAdaptersAddresses(family, flags, NULL, pAddresses, &outBufLen) == ERROR_BUFFER_OVERFLOW)
     pAddresses = alloca (outBufLen);

  /* Make a second call to GetAdapters Addresses to get the
   * actual data we want
   */
  PCAP_TRACE (2, "Memory allocated for GetAdapterAddresses = %lu bytes (equals %lu of IP_ADAPTER_ADDRESS) \n",
              outBufLen, outBufLen / sizeof(IP_ADAPTER_ADDRESSES));

  _cprintf (color[0], "Calling GetAdaptersAddresses function with family = ");
  if (family == AF_INET)
    _cprintf (color[1], "AF_INET\n");

  if (family == AF_INET6)
    _cprintf (color[1], "AF_INET6\n");

  if (family == AF_UNSPEC)
    _cprintf (color[1], "AF_UNSPEC\n\n");

  dwRetVal = GetAdaptersAddresses (family, flags, NULL, pAddresses, &outBufLen);

  if (dwRetVal == NO_ERROR)
  {
    /* If successful, output some information from the data we received
     */
    pCurrAddresses = pAddresses;
    while (pCurrAddresses)
    {
      PCAP_TRACE (2, "Length of the IP_ADAPTER_ADDRESS struct: %ld\n",
                  pCurrAddresses->Length);

      _cprintf (color[2], "IfIndex: %lu\n", pCurrAddresses->IfIndex);
      _cprintf (color[2], "\tAdapter name: %s\n", pCurrAddresses->AdapterName);

      pUnicast = pCurrAddresses->FirstUnicastAddress;
      if (pUnicast)
      {
        for (i = 0; pUnicast; i++)
            pUnicast = pUnicast->Next;
        _cprintf (color[2], "\tNumber of Unicast Addresses: %d\n", i);
      }
      else
        _cprintf (color[3], "\tNo Unicast Addresses\n");

      pAnycast = pCurrAddresses->FirstAnycastAddress;
      if (pAnycast)
      {
        for (i = 0; pAnycast; i++)
            pAnycast = pAnycast->Next;
        _cprintf (color[2], "\tNumber of Anycast Addresses: %d\n", i);
      }
      else
        _cprintf (color[3], "\tNo Anycast Addresses\n");

      pMulticast = pCurrAddresses->FirstMulticastAddress;
      if (pMulticast)
      {
        for (i = 0; pMulticast; i++)
            pMulticast = pMulticast->Next;
        _cprintf (color[2], "\tNumber of Multicast Addresses: %d\n", i);
      }
      else
        _cprintf (color[3], "\tNo Multicast Addresses\n");

      pDnServer = pCurrAddresses->FirstDnsServerAddress;
      if (pDnServer)
      {
        for (i = 0; pDnServer; i++)
            pDnServer = pDnServer->Next;
        _cprintf (color[2], "\tNumber of DNS Server Addresses: %d\n", i);
      }
      else
        _cprintf (color[3], "\tNo DNS Server Addresses\n");

      _cprintf (color[2], "\tDNS Suffix: %" WIDESTR_FMT "\n", pCurrAddresses->DnsSuffix);
      _cprintf (color[2], "\tDescription: %" WIDESTR_FMT "\n", pCurrAddresses->Description);
      _cprintf (color[2], "\tFriendly name: %" WIDESTR_FMT "\n", pCurrAddresses->FriendlyName);

      if (pCurrAddresses->PhysicalAddressLength != 0)
      {
        _cprintf (color[2], "\tPhysical address: ");
        for (i = 0; i < pCurrAddresses->PhysicalAddressLength; i++)
        {
          if (i == (pCurrAddresses->PhysicalAddressLength - 1))
               _cprintf (color[3], "%.2X\n", (int) pCurrAddresses->PhysicalAddress[i]);
          else _cprintf (color[3], "%.2X-", (int) pCurrAddresses->PhysicalAddress[i]);
        }
      }
      _cprintf (color[2], "\tFlags:      0x%04lX\n", pCurrAddresses->Flags);
      _cprintf (color[2], "\tMtu:        %lu\n", pCurrAddresses->Mtu);
      _cprintf (color[2], "\tIfType:     %ld\n", pCurrAddresses->IfType);
      _cprintf (color[2], "\tOperStatus: %u\n", pCurrAddresses->OperStatus);
      _cprintf (color[2], "\tIpv6IfIndex (IPv6 interface): %lu\n",
                pCurrAddresses->Ipv6IfIndex);
      _cprintf (color[2], "\tZoneIndices (hex): ");
      for (i = 0; i < 16; i++)
          _cprintf (color[2], "%lx ", pCurrAddresses->ZoneIndices[i]);
      _cprintf (color[2], "\n");

      pPrefix = pCurrAddresses->FirstPrefix;
      if (pPrefix)
      {
        for (i = 0; pPrefix; i++)
            pPrefix = pPrefix->Next;
        _cprintf (color[2], "\tNumber of IP Adapter Prefix entries: %d\n", i);
      }
      else
        _cprintf (color[3], "\tNo IP Adapter Prefix entries\n");

      _cprintf (color[2], "\n");

      pCurrAddresses = pCurrAddresses->Next;
    }
  }
  else
  {
    _cprintf (color[3], "Call to GetAdaptersAddresses failed with error: %lu\n", dwRetVal);
    if (dwRetVal == ERROR_NO_DATA)
      _cprintf (color[2], "\tNo addresses were found for the requested parameters\n");
    else
    {
      DWORD flags2 = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
      DWORD lang   = MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);   /* default language */

      if (FormatMessage(flags2, NULL, dwRetVal, lang, (LPTSTR)&lpMsgBuf, 0, NULL))
      {
        _cprintf (color[3], "\tError: %s", (const char*)lpMsgBuf);
        LocalFree (lpMsgBuf);
        return (1);
      }
    }
  }
  return 0;
}
