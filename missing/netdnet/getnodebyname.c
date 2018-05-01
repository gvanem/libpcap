/******************************************************************************
    (c) 1995-1998 E.M. Serrat          emserrat@geocities.com
    (c) 1999      P.J. Caulfield       patrick@tykepenguin.cix.co.uk

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	Modified for libpcap by G. Vanem <giva@bgnett.no> Febr 2003
	Merged getnodebyname.c and dnet_addr.c
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcap.h>
#include <pcap-int.h>
#include <netdnet/dnetdb.h>
#include <netdnet/dn.h>

static char             nodetag[80],nametag[80],nodeadr[80],nodename[80];
static struct nodeent	dp;
static struct dn_naddr	*naddr;
static struct dn_naddr  binadr = { 0x0002, {0x00, 0x00} };

static struct dn_naddr *__dnet_addr (FILE *fil, char *name);

static const char *get_DECnet_conf (void)
{
#if defined(_PATH_DECNET_CONF)
	return (_PATH_DECNET_CONF);
#elif defined(WIN32)
	static char path[_MAX_PATH];
	const char *env = getenv ("SystemRoot");

	if (!env)
  		return (NULL);
	snprintf (path, sizeof(path)-1, "%s\\System32\\drivers\\etc\\decnet.conf", env);
	return (path);
#else
    return ("/etc/decnet.conf");
#endif
}

struct nodeent *getnodebyname (const char *name)
{
	struct nodeent *rc = NULL;
	FILE  *dnhosts;
	char   nodeln[80];
	const  char *path;
	int    a, n;

	/* See if it is an address really */
	if (sscanf(name, "%d.%d", &a, &n) == 2)
	{
		static struct dn_naddr addr;

		addr.a_addr[0] = n & 0xFF;
		addr.a_addr[1] = (a << 2) | ((n & 0x300) >> 8);
		dp.n_addr   = (unsigned char*)&addr.a_addr;
		dp.n_length = 2;
		dp.n_name = (char*)name;  /* No point looking this up for a real name */
		dp.n_addrtype = AF_DECnet;
		return (&dp);
	}

	path = get_DECnet_conf();
	if (!path || (dnhosts = fopen(path,"r")) == NULL)
	{
		printf("getnodebyname: Can not open %s\n", path);
		return (NULL);
	}

	while (fgets(nodeln,sizeof(nodeln),dnhosts) != NULL)
	{
		char *cp = strpbrk(nodeln, "#\r\n");

		if (!cp || *cp == '#')
			continue;

		sscanf (cp,"%s%s%s%s",nodetag,nodeadr,nametag,nodename);
		if (((pcap_strcasecmp(nodetag,"executor") != 0) &&
    			(pcap_strcasecmp(nodetag,"node") != 0)) ||
			(pcap_strcasecmp(nametag,"name") != 0))
		{
			printf("getnodebyname: Invalid decnet.conf syntax\n");
			break;
		}
		if (strcmp(nodename,name))
			continue;

		if ((naddr = __dnet_addr(dnhosts,nodename)) != NULL) {
			dp.n_addr   = (unsigned char*)&naddr->a_addr;
			dp.n_length = 2;
			dp.n_name   = nodename;
			dp.n_addrtype = AF_DECnet;
			rc = &dp;
		}
		break;
	}
	fclose (dnhosts);
	return (rc);
}

static struct dn_naddr *__dnet_addr (FILE *dnhosts, char *name)
{
  char   nodeln[80];
  char **endptr, *aux;
  long   area, node;

  while (fgets (nodeln, sizeof(nodeln), dnhosts))
  {
    sscanf (nodeln, "%s%s%s%s\n", nodetag, nodeadr, nametag, nodename);
    if (nodetag[0] != '#')
    {
      if (((pcap_strcasecmp (nodetag, "executor") != 0) &&
           (pcap_strcasecmp (nodetag, "node") != 0)) ||
           (pcap_strcasecmp (nametag, "name") != 0))
      {
        printf ("__dnet_addr: Invalid decnet.conf syntax\n");
        return (NULL);
      }
      if (strcmp (nodename, name) == 0)
      {
        aux = nodeadr;
        endptr = &aux;
        area = strtol (nodeadr, endptr, 0);
        node = strtol (*endptr + 1, endptr, 0);
        if ((area < 0) || (area > 63) || (node < 0) || (node > 1023))
        {
          printf ("__dnet_addr: Invalid address %d.%d\n", (int) area, (int) node);
          return (NULL);
        }
        binadr.a_addr[0] = node & 0xFF;
        binadr.a_addr[1] = (area << 2) | ((node & 0x300) >> 8);
        return (&binadr);
      }
    }
  }
  return (NULL);
}
