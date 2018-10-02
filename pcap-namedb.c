#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <pcap/namedb.h>
#include <pcap-types.h>
#include <pcap/pcap-inttypes.h>

#define MAXALIASES  35

static int net_stayopen;
static int serv_stayopen;

static FILE *servf = NULL;
static FILE *netf = NULL;

static char line[BUFSIZ+1];

static struct servent serv;
static char *serv_aliases[MAXALIASES];

static struct netent net;
static char *net_aliases[MAXALIASES];

static char *any(char *, char *);

/*
 * Internet network address interpretation routine.
 * The library routines call this routine to interpret
 * network numbers.
 */
uint32_t
pcap_inet_network(const char *cp)
{
	uint32_t val, base, n;
	char c;
	uint32_t parts[4], *pp = parts;
	int i;

again:
	/*
	 * Collect number up to ``.''.
	 * Values are specified as for C:
	 * 0x=hex, 0=octal, other=decimal.
	 */
	val = 0; base = 10;
	/*
	 * The 4.4BSD version of this file also accepts 'x__' as a hexa
	 * number.  I don't think this is correct.  -- Uli
	 */
	if (*cp == '0') {
		if (*++cp == 'x' || *cp == 'X')
			base = 16, cp++;
		else
			base = 8;
	}
	while ((c = *cp)) {
		if (isdigit(c)) {
			val = (val * base) + (c - '0');
			cp++;
			continue;
		}
		if (base == 16 && isxdigit(c)) {
			val = (val << 4) + (c + 10 - (islower(c) ? 'a' : 'A'));
			cp++;
			continue;
		}
		break;
	}
	if (*cp == '.') {
		if (pp >= parts + 4)
			return (INADDR_NONE);
		*pp++ = val, cp++;
		goto again;
	}
	if (*cp && !isspace(*cp))
		return (INADDR_NONE);
	*pp++ = val;
	n = pp - parts;
	if (n > 4)
		return (INADDR_NONE);

	for (val = 0, i = 0; i < (int)n; i++) {
		val <<= 8;
		val |= parts[i] & 0xff;
	}
	return (val);
}

struct netent *
pcap_getnetbyname (const char *name)
{
	struct netent *p;
	char **cp;

	pcap_setnetent (net_stayopen);
	while ((p = pcap_getnetent()) != NULL) {
		if (!strcmp(p->n_name, name))
			break;
		for (cp = p->n_aliases; *cp != 0; cp++)
			if (strcmp(*cp, name) == 0)
				goto found;
	}

found:
	if (!net_stayopen)
		pcap_endnetent();
	return (p);
}

void
pcap_setnetent (int f)
{
	if (netf == NULL)
		netf = fopen (pcap_etc_subpath("networks"), "r" );
	else
		rewind(netf);
	net_stayopen |= f;
}

void
pcap_endnetent (void)
{
	if (netf) {
		fclose(netf);
		netf = NULL;
	}
	net_stayopen = 0;
}

struct netent *
pcap_getnetent (void)
{
	char *p, *cp, **q;

	if (netf == NULL && (netf = fopen(pcap_etc_subpath("networks"), "r" )) == NULL)
		return (NULL);
again:
	p = fgets(line, BUFSIZ, netf);
	if (p == NULL)
		return (NULL);
	if (*p == '#')
		goto again;
	cp = any(p, "#\r\n");
	if (cp == NULL)
		goto again;
	*cp = '\0';
	net.n_name = p;
	cp = any(p, " \t");
	if (cp == NULL)
		goto again;
	*cp++ = '\0';
	while (*cp == ' ' || *cp == '\t')
		cp++;
	p = any(cp, " \t");
	if (p != NULL)
		*p++ = '\0';

	net.n_net = pcap_inet_network(cp);
	net.n_addrtype = AF_INET;
	q = net.n_aliases = net_aliases;
	if (p != NULL)
		cp = p;

	while (cp && *cp) {
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		if (q < &net_aliases[MAXALIASES - 1])
			*q++ = cp;
		cp = any(cp, " \t");
		if (cp != NULL)
			*cp++ = '\0';
	}
	*q = NULL;
	return (&net);
}

static char *
any (char *cp, char *match)
{
	char *mp, c;

	while ((c = *cp) != 0) {
		for (mp = match; *mp; mp++)
			if (*mp == c)
				return (cp);
		cp++;
	}
	return (NULL);
}

void
pcap_setservent (int f)
{
	if (servf == NULL)
		servf = fopen (pcap_etc_subpath("services"), "r" );
	else
		rewind(servf);
	serv_stayopen |= f;
}

void
pcap_endservent (void)
{
	if (servf) {
		fclose(servf);
		servf = NULL;
	}
	serv_stayopen = 0;
}

struct servent *
pcap_getservent (void)
{
	char *p, *cp, **q;

	if (servf == NULL && (servf = fopen(pcap_etc_subpath("services"), "r" )) == NULL)
		return (NULL);

again:
	if ((p = fgets(line, BUFSIZ, servf)) == NULL)
		return (NULL);

	if (*p == '#')
		goto again;

	cp = strpbrk(p, "#\r\n");
	if (cp == NULL)
		goto again;

	*cp = '\0';
	serv.s_name = p;
	p = strpbrk(p, " \t");
	if (p == NULL)
		goto again;

	*p++ = '\0';
	while (*p == ' ' || *p == '\t')
		p++;
	cp = strpbrk(p, ",/");
	if (cp == NULL)
		goto again;

	*cp++ = '\0';
	serv.s_port = htons((uint16_t)atoi(p));
	serv.s_proto = cp;
	q = serv.s_aliases = serv_aliases;
	cp = strpbrk(cp, " \t");
	if (cp != NULL)
		*cp++ = '\0';

	while (cp && *cp) {
		if (*cp == ' ' || *cp == '\t') {
			cp++;
			continue;
		}
		if (q < &serv_aliases[MAXALIASES - 1])
			*q++ = cp;
		cp = strpbrk(cp, " \t");
		if (cp != NULL)
			*cp++ = '\0';
	}
	*q = NULL;
	return (&serv);
}

/*
 * Return path to "%SystemRoot%/drivers/etc/<file>"
 */
const char *
pcap_etc_subpath (const char *file)
{
	const char *env = getenv ("SystemRoot");
	static char path[MAX_PATH];

	if (!env)
		return (file);

	pcap_snprintf (path, sizeof(path), "%s\\system32\\drivers\\etc\\%s", env, file);
	return (path);
}

