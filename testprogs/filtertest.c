/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* Example usage:
 *   filtertest EN10MB ip and udp
 */

#include "varattrs.h"

#ifndef lint
static const char copyright[] _U_ =
    "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
#endif

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#ifdef _WIN32
  #include "getopt.h"
  #include "unix.h"
#else
  #include <unistd.h>
#endif
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <time.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
#else
  #include <sys/socket.h>
  #include <arpa/inet.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include "pcap/funcattrs.h"

#ifdef BDEBUG
  /*
   * We have pcap_set_optimizer_debug() and pcap_set_print_dot_graph() in
   * libpcap; declare them (they're not declared by any libpcap header,
   * because they're special hacks, only available if libpcap was configured
   * to include them, and only intended for use by libpcap developers trying
   * to debug the optimizer for filter expressions).
   */
  PCAP_API void pcap_set_optimizer_debug(int);
  PCAP_API void pcap_set_print_dot_graph(int);

  #define g_FLAG "g"

#else
  #define pcap_set_optimizer_debug(level) do {             \
                                            if (level > 0) \
                                               error("libpcap and filtertest not built with optimizer debugging enabled"); \
                                          } while (0)

  #define pcap_set_print_dot_graph(level) do {             \
                                            if (level > 0) \
                                               error("libpcap and filtertest not built with optimizer debugging enabled"); \
                                          } while (0)
  #define g_FLAG ""
#endif


static char *program_name;

/* Forwards */
static void PCAP_NORETURN usage(void);
static void PCAP_NORETURN error(const char *, ...) PCAP_PRINTFLIKE(1, 2);
static void warn(const char *, ...) PCAP_PRINTFLIKE(1, 2);

static int dflag = 0;

/*
 * On Windows, we need to open the file in binary mode, so that
 * we get all the bytes specified by the size we get from "fstat()".
 * On UNIX, that's not necessary.  O_BINARY is defined on Windows;
 * we define it as 0 if it's not defined, so it does nothing.
 */
#ifndef O_BINARY
#define O_BINARY	0
#endif

#ifndef STDIN_FILENO
#define STDIN_FILENO 0
#endif

#if defined(__MINGW32__) && !defined(HAVE_INET_PTON)
static int inet_pton (int af, const char *src, bpf_u_int32 *dst)
{
	bpf_u_int32 a;

	if (af != AF_INET) {
		errno = EAFNOSUPPORT;
		return -1;
	}
	a = inet_addr (src);
	if (a == INADDR_NONE)
	   return 0;
	*dst = a;
	return (1);
}
#endif

static char *
read_infile(const char *fname)
{
	int i, fd, cc;
	char *cp;
	struct stat buf;

	if (fname[0] == '-' && fname[1] == '\0') {
		fd = fileno(stdin);
		fname = "<stdin>";
	}
	else
		fd = open(fname, O_RDONLY|O_BINARY);

	if (fd < 0)
		error("can't open %s: %s", fname, pcap_strerror(errno));

	if (fstat(fd, &buf) < 0)
		error("can't stat %s: %s", fname, pcap_strerror(errno));

	cp = malloc((u_int)buf.st_size + 1);
	if (cp == NULL)
		error("malloc(%d) for %s: %s", (u_int)buf.st_size + 1,
			fname, pcap_strerror(errno));
	cc = read(fd, cp, (u_int)buf.st_size);
	if (cc < 0)
		error("read %s: %s", fname, pcap_strerror(errno));
	if (cc != buf.st_size && fd != STDIN_FILENO)
		error("short read %s (%d != %d)", fname, cc, (int)buf.st_size);

	close(fd);
	/* replace "# comment" with spaces */
	for (i = 0; i < cc; i++) {
		if (cp[i] == '#')
			while (i < cc && cp[i] != '\n')
				cp[i++] = ' ';
	}
	cp[cc] = '\0';
	return (cp);
}

/* VARARGS */
static void
error(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
	exit(1);
	/* NOTREACHED */
}

/* VARARGS */
static void
warn(const char *fmt, ...)
{
	va_list ap;

	(void)fprintf(stderr, "%s: WARNING: ", program_name);
	va_start(ap, fmt);
	(void)vfprintf(stderr, fmt, ap);
	va_end(ap);
	if (*fmt) {
		fmt += strlen(fmt);
		if (fmt[-1] != '\n')
			(void)fputc('\n', stderr);
	}
}

/*
 * Copy arg vector into a new buffer, concatenating arguments with spaces.
 */
static char *
copy_argv(register char **argv)
{
	register char **p;
	register u_int len = 0;
	char *buf;
	char *src, *dst;

	p = argv;
	if (*p == 0)
		return 0;

	while (*p)
		len += strlen(*p++) + 1;

	buf = (char *)malloc(len);
	if (buf == NULL)
		error("copy_argv: malloc");

	p = argv;
	dst = buf;
	while ((src = *p++) != NULL) {
		while ((*dst++ = *src++) != '\0')
			;
		dst[-1] = ' ';
	}
	dst[-1] = '\0';

	return buf;
}

/*
 * Standard libpcap format.
 */
#define TCPDUMP_MAGIC  0xa1b2c3d4
#define PCAP_FILE      "dummy.pcap"

struct pcap_timeval {
    bpf_int32 tv_sec;		/* seconds */
    bpf_int32 tv_usec;		/* microseconds */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;	/* time stamp */
    bpf_u_int32 caplen;		/* length of portion present */
    bpf_u_int32 len;		/* length this packet (off wire) */
};

static int make_dummy_pcap_file (int num_pkt, int linktype, long snaplen)
{
	struct pcap_file_header hdr;
	struct pcap_sf_pkthdr   sf_hdr;
	unsigned char rdata [66000];
	int   i, pkt, rc = 0;
 	FILE *f = fopen (PCAP_FILE, "wb+");

 	if (!f)
 		return (0);

	hdr.magic = TCPDUMP_MAGIC;
	hdr.version_major = PCAP_VERSION_MAJOR;
	hdr.version_minor = PCAP_VERSION_MINOR;

	hdr.thiszone = 0;
	hdr.snaplen = snaplen;
	hdr.sigfigs = 0;
	hdr.linktype = linktype;

	if (fwrite((char*)&hdr, sizeof(hdr), 1, f) != 1)
		goto quit;

	assert (snaplen < sizeof(rdata));

	srand (time(NULL));

	for (pkt = 0; pkt < num_pkt; pkt++) {
		for (i = 0; i < snaplen; i++)
		    rdata[i] = rand();

		sf_hdr.ts.tv_sec  = 0;
		sf_hdr.ts.tv_usec = 0;
		sf_hdr.caplen     = snaplen;
		sf_hdr.len        = snaplen;

		if (fwrite(&sf_hdr, sizeof(sf_hdr), 1, f) != 1)
			goto quit;

		if (snaplen > 0 && fwrite(&rdata, snaplen, 1, f) != 1)
			goto quit;
	}

	rc = 1;

quit:
	if (f)
		fclose(f);
	return (rc);
}

/*
 *
 */
static int pass_0;
static int pass_1;

static int
run_and_compare_packet (pcap_t *pd, int loop,
						const struct bpf_program *f_0,
						const struct bpf_program *f_1)
{
#if 1
	return (rand() & 1);
#else
	return (1);
#endif
}

/*
 * The purpose of this function is to check if 2 versions of the same
 * filter-program will perform the same filtering. The steps done to check
 * if this is the case are:
 *
 *   1. A random packet of data written to './dummy.pcap' is used as input
 *      to a callback handler and the optimized or un-optimized filter.
 *
 *   2. At even numbered 'loop' counts the filter is NOT optimized ('opt==0').
 *
 *   3. At odd  numbered 'loop' counts the filter is optimized ('opt==1').
 *
 *   4. The callback compares the results of these 2 'opt' values and
 *      increments the 'err_cnt' if a difference is found; i.e.
 *      'pass_0 != pass_1'.
 *
 * Here it is assumed that a higher 'optimize_loops' value is better to detect
 * any difference in behaviour. To use this function, call this program as
 * e.g.:
 *   filtertest -dd -r 10 -s 1000 EN10mb ip and port 54
 */

static pcap_t *
run_pcap_optimize (int optimize_loops,
				   const char *filter, int linktype,
				   bpf_u_int32 netmask, long snaplen)
{
	struct bpf_program fcode_0, fcode_1, *fcode;
	int     loop, rc, opt, err_cnt;
	char    errbuf [PCAP_ERRBUF_SIZE];
	pcap_t *pd;

	rc = make_dummy_pcap_file(10, linktype, snaplen);
	if (!rc)
		error("Can't create %s.", PCAP_FILE);

	pd = pcap_open_offline(PCAP_FILE, errbuf);
	if (pd == NULL)
		error("Can't open %s.", PCAP_FILE);

	if (pcap_compile(pd, &fcode_0, filter, 0, netmask) < 0)
		error("%s(%u): %s", __FILE__, __LINE__, pcap_geterr(pd));

	if (pcap_compile(pd, &fcode_1, filter, 1, netmask) < 0)
		error("%s(%u): %s", __FILE__, __LINE__, pcap_geterr(pd));

	for (loop = 0, opt = err_cnt = 0; loop < optimize_loops; loop++, opt ^= 1) {
		fcode = (opt == 1) ? &fcode_1 : &fcode_0;

		if (!bpf_validate(fcode->bf_insns, fcode->bf_len)) {
			warn("%s(%u): Filter '%s' doesn't pass validation at loop %d. Optimize: %d",
				 __FILE__, __LINE__, filter, loop, opt);
	    	err_cnt++;
			continue;
		}

		if (dflag > 1)
			fprintf(stderr, "loop: %3d, opt: %d, fcode->bf_len: %2d err_cnt: %2d.\n",
					loop, opt, fcode->bf_len, err_cnt);

    	if (pcap_setfilter(pd, fcode) < 0) {
	    	warn("pcap_setfilter(): %s", pcap_geterr(pd));
	    	err_cnt++;
			continue;
    	}

		if (!run_and_compare_packet(pd, loop, &fcode_0, &fcode_1)) {
			warn("pcap_compile() problem at loop: %d. Opt: %d", loop, opt);
	    	err_cnt++;
		}
	}

	fprintf(stderr, "%s: err_cnt: %d", program_name, err_cnt);
	if (!dflag)
		unlink (PCAP_FILE);
	return (pd);
}

int
main(int argc, char **argv)
{
	char *cp;
	int op;
	char *infile = NULL;
	int Dflag = 0;
	int Oflag;
	int gflag;
	long snaplen;
	char *p;
	int dlt;
	int optimize_loops = -1;
	int have_fcode = 0;
	bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN;
	char *cmdbuf;
	pcap_t *pd;
	struct bpf_program fcode;

#ifdef _WIN32
	if (pcap_wsockinit() != 0)
		return 1;
#endif /* _WIN32 */

	dflag = 1;
	gflag = 0;

	infile = NULL;
	Oflag = 1;
	snaplen = 68;

	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((op = getopt(argc, argv, "dDF:" g_FLAG "m:Or:s:")) != -1) {
		switch (op) {

		case 'd':
			++dflag;
			break;
		case 'D':
			++Dflag;
			pcap_set_optimizer_debug(4);
			dflag = 0;
			break;

		case 'g':
			++gflag;
			break;

		case 'F':
			infile = optarg;
			break;

		case 'O':
			Oflag = 0;
			break;

		case 'm': {
			bpf_u_int32 addr;

			switch (inet_pton(AF_INET, optarg, &addr)) {
				case 0:
						error("invalid netmask %s", optarg);
						break;

				case -1:
						error("invalid netmask %s: %s", optarg,
						    pcap_strerror(errno));
						break;

				case 1:
					netmask = addr;
					break;
				}
			break;
		}

		case 'r': {
			char *end;

			optimize_loops = strtol(optarg, &end, 0);
			if (optarg == end || *end != '\0'
		    	|| optimize_loops < 0 || optimize_loops > 65535)
				error("invalid number of optimize loops %s", optarg);
			else if (optimize_loops == 0)
				optimize_loops = 1;
			break;
		}

		case 's': {
			char *end;

			snaplen = strtol(optarg, &end, 0);
			if (optarg == end || *end != '\0'
			    || snaplen < 0 || snaplen > 65535)
				error("invalid snaplen %s", optarg);
			else if (optimize_loops == -1 && snaplen == 0)
				snaplen = 65535;
			break;
		}

		default:
			usage();
			/* NOTREACHED */
		}
	}

	if (optind >= argc) {
		usage();
		/* NOTREACHED */
	}

	dlt = pcap_datalink_name_to_val(argv[optind]);
	if (dlt < 0) {
		dlt = (int)strtol(argv[optind], &p, 10);
		if (p == argv[optind] || *p != '\0')
		error("invalid data link type %s", argv[optind]);
	}

	if (infile)
		cmdbuf = read_infile(infile);
	else
		cmdbuf = copy_argv(&argv[optind+1]);

	if (optimize_loops > -1) {
		pd = run_pcap_optimize(optimize_loops, cmdbuf, dlt, netmask, snaplen);
	}
	else
	{
		pcap_set_optimizer_debug(dflag);
		pcap_set_print_dot_graph(gflag);

		pd = pcap_open_dead(dlt, snaplen);
		if (pd == NULL)
			error("Can't open fake pcap_t");

		if (pcap_compile(pd, &fcode, cmdbuf, Oflag, netmask) < 0)
			error("%s", pcap_geterr(pd));

		have_fcode = 1;
		if (!bpf_validate(fcode.bf_insns, fcode.bf_len))
			warn("Filter doesn't pass validation");

		/* Don't print both machine-code and DOT-output to stdout.
		 */
		if (gflag == 0) {
#ifdef BDEBUG
			if (cmdbuf != NULL) {
				// replace line feed with space
				for (cp = cmdbuf; *cp != '\0'; ++cp) {
					if (*cp == '\r' || *cp == '\n') {
						*cp = ' ';
					}
				}
				/* only show machine code if BDEBUG defined, since dflag > 3 */
				printf("machine codes for filter: %s\n", cmdbuf);
			} else
				printf("machine codes for empty filter:\n");
#endif
			bpf_dump(&fcode, dflag);
		}
	}

	free(cmdbuf);
	if (have_fcode)
	   pcap_freecode (&fcode);
	pcap_close(pd);
	exit(0);
}

static void
usage(void)
{
	(void)fprintf(stderr, "%s, with %s\n", program_name,
	    pcap_lib_version());
	(void)fprintf(stderr,
	    "Usage: %s [-d" g_FLAG "DO] [ -F file ] [ -m netmask] [ -s snaplen ] [ -r <optimize test loops>]] dlt [ expression ]\n",
	    program_name);
	exit(1);
}
