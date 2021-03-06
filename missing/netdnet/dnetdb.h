/* DNLIB FUNCTIONS PROTOTYPING */
#ifndef NETDNET_DNLIB_H
#define NETDNET_DNLIB_H

#include <time.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct	nodeent	{
	char	*n_name;		/* name of node */
	unsigned short n_addrtype;	/* node address type */
	unsigned short n_length;	/* length of address */
	unsigned char	*n_addr;	/* address	*/
	unsigned char	*n_params;	/* node parameters */
	unsigned char	n_reserved[16];	/* reserved */
};

/* DECnet database & utility functions on libdnet */
extern  struct  dn_naddr *dnet_addr(char *cp);
extern  int               dnet_conn(char *node, char *object, int type,
                                unsigned char *opt_out, int opt_outl,
                                unsigned char *opt_in, int *opt_inl);
extern  char             *dnet_htoa(struct dn_naddr *add);
extern  char             *dnet_ntoa(struct dn_naddr *add);
extern  struct  dn_naddr *getnodeadd(void);
extern  struct  nodeent  *getnodebyaddr(const char *addr, int len, int type);
extern  struct  nodeent  *getnodebyname(const char *name);

extern  char             *getexecdev(void);
extern  void              setnodeent(int);
extern  void             *dnet_getnode(void);
extern  char             *dnet_nextnode(void *);
extern  void              dnet_endnode(void *);
extern  int               dnet_recv(int s, void *buf, int len, unsigned int flags);
extern  int               dnet_pton(int af, const char *src, void *addr);
extern  const char       *dnet_ntop(int af, const void *addr, char *str, size_t len);

/* DECnet daemon functions in libdnet_daemon */
extern int   dnet_daemon(int object, char *named_object,
			 int verbosity, int do_fork);
extern void  dnet_accept(int sockfd, short status, char *data, int len);
extern void  dnet_reject(int sockfd, short status, char *data, int len);
extern void  dnet_set_optdata(char *data, int len);
extern char *dnet_daemon_name(void);
extern int   getnodename(char *, size_t);
extern int   setnodename(char *, size_t);

extern void  init_daemon_logging(char *, char);
extern void  dnetlog(int level, char *fmt, ...);
#define DNETLOG(x) dnetlog x

/* Used by dnet_ntop/dnet_pton */
#define DNET_ADDRSTRLEN  8

/*
 * Define DECnet object numerically.
 */
#define DNOBJECT_FAL	17	/* file access listener */
#define DNOBJECT_NICE	19	/* NICE */
#define DNOBJECT_DTERM	23	/* DECnet remote terminals */
#define DNOBJECT_MIRROR	25	/* DECnet mirror */
#define DNOBJECT_EVR	26	/* DECnet event receiver */
#define DNOBJECT_MAIL11	27	/* mail service */
#define DNOBJECT_PHONE	29	/* DECnet phone utility */
#define DNOBJECT_CTERM	42	/* DECnet command terminals */
#define DNOBJECT_DTR	63	/* DECnet test receiver */

/* Connect/Reject codes. These are my symbolic names, not DEC's */
#define DNSTAT_REJECTED         0 /* Rejected by object */
#define DNSTAT_RESOURCES        1 /* No resources available */
#define DNSTAT_NODENAME         2 /* Unrecognised node name */
#define DNSTAT_LOCNODESHUT      3 /* Local Node is shut down */
#define DNSTAT_OBJECT           4 /* Unrecognised object */
#define DNSTAT_OBJNAMEFORMAT    5 /* Invalid object name format */
#define DNSTAT_TOOBUSY          6 /* Object too busy */
#define DNSTAT_NODENAMEFORMAT  10 /* Invalid node name format */
#define DNSTAT_REMNODESHUT     11 /* Remote Node is shut down */
#define DNSTAT_ACCCONTROL      34 /* Access control rejection */
#define DNSTAT_NORESPONSE      38 /* No response from object */
#define DNSTAT_NODEUNREACH     39 /* Node Unreachable */

/* Disconnect notification errors */
#define DNSTAT_MANAGEMENT       8 /* Abort by management/third party */
#define DNSTAT_ABORTOBJECT      9 /* Remote object aborted the link */
#define DNSTAT_FAILED          38 /* Node or object failed */

#define DNSTAT_NODERESOURCES   32 /* Node does not have sufficient resources for a new link */
#define DNSTAT_OBJRESOURCES    33 /* Object does not have sufficient resources for a new link */
#define DNSTAT_BADACCOUNT      36 /* The Account field in unacceptable */
#define DNSTAT_TOOLONG         43 /* A field in the access control message was too long */

/* We need this for 'Eduardo' kernels */
#ifndef MSG_EOR
#define MSG_EOR 0x80
#endif


#ifdef __cplusplus
}
#endif

#endif

