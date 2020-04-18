#undef PCAP_TRACE

#if !defined(_libpcap_CONFIG_H)
  #error "Include me inside 'Win32/config.h'."
#endif

#if !defined(_WIN32)
  #define PCAP_TRACE(level, fmt, ...)  (void)0

#else  /* Rest of file */

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincon.h>

/** \todo Use 'g_cfg.color.file' and 'g_cfg.color.text'
 *        set from %HOME%/wpcap.cfg.
 */
#define TRACE_COLOUR_GREEN   (FOREGROUND_INTENSITY | 2)
#define TRACE_COLOUR_CYAN    (FOREGROUND_INTENSITY | 3)
#define TRACE_COLOUR_MAGENTA (FOREGROUND_INTENSITY | 5)
#define TRACE_COLOUR_YELLOW  (FOREGROUND_INTENSITY | 6)
#define TRACE_COLOUR_WHITE   (FOREGROUND_INTENSITY | 7)

#define TRACE_COLOUR_START  TRACE_COLOUR_GREEN
#define TRACE_COLOUR_ARGS   TRACE_COLOUR_WHITE

#if !defined(COMPILING_PCAP_PLUGIN)
  /*
   * Plugin source-files must set it's own
   * '__FILE()' and 'TRACE_PREFIX'. They also
   * redefine 'TRACE_COLOUR_START'.
   */
  #define __FILE()           _pcap_trace_basename (__FILE__)

  #if defined(USE_WIN10PCAP)
    #define TRACE_PREFIX  "[Win10Pcap] "

  #elif defined(USE_NPCAP)
    #define TRACE_PREFIX  "[NPcap] "

  #else
    #define TRACE_PREFIX  ""
  #endif
#endif

/*
 * Use this macro as e.g.:
 *   PCAP_TRACE (1, "%s() -> %s\n", __FUNCTION__, file);
 *
 * The stuff in '_pcap_trace_level()' should initialise itself once.
 */
#if defined(USE_PCAP_TRACE)
  #define PCAP_TRACE(level, fmt, ...)                 \
          do {                                        \
            if (_pcap_trace_level() >= level) {       \
              EnterCriticalSection (&g_trace_crit);   \
              _pcap_trace_color (TRACE_COLOUR_START); \
              printf ("%s%s(%u): ", TRACE_PREFIX,     \
                      __FILE(), __LINE__);            \
              _pcap_trace_color (TRACE_COLOUR_ARGS);  \
              printf (fmt, ## __VA_ARGS__);           \
              _pcap_trace_color (0);                  \
              LeaveCriticalSection (&g_trace_crit);   \
            }                                         \
          } while (0)

  /* The generated grammar.c has this:
   *   ifndef YYFPRINTF
   *    include <stdio.h> // INFRINGES ON USER NAME SPACE
   *    define YYFPRINTF fprintf
   *   endif
   *
   * Thus, if 'YYDEBUG' is defined and 'yydebug > 0', the above
   * macro is used to trace the inner workings of grammar.c.
   * All in shining colours.
   */
  #undef  YYFPRINTF
  #define YYFPRINTF(stream_ignore, fmt, ...)            \
          do {                                          \
            static const char *last_fmt;                \
            static int         add_prefix;              \
                                                        \
            if (_pcap_trace_level() >= 1) {             \
              /* Should be start a new trace-prefix? */ \
              add_prefix = !last_fmt ||                 \
                (last_fmt[strlen(last_fmt)-1] == '\n'); \
              fflush (stdout);                          \
              last_fmt = fmt;                           \
              if (add_prefix) {                         \
                _pcap_trace_color (TRACE_COLOUR_GREEN); \
                printf ("grammar.c(%u): ", __LINE__);   \
                _pcap_trace_color (TRACE_COLOUR_WHITE); \
              }                                         \
              printf (fmt, ## __VA_ARGS__);             \
              _pcap_trace_color (0);                    \
            }                                           \
          } while (0)

#else
  #define PCAP_TRACE(level, fmt, ...)   (void)0
#endif

#if defined(COMPILING_NPCAPHELPERTEST_C)
  /*
   * Hacks to turn '$(NPCAP_ROOT)/PacketWin7/Helper/debug.h' code into
   * nice colour traces.
   */
  #undef _DBG
  #undef _DEBUG_TO_FILE

  #include <packetWin7/Helper/debug.h>

  #undef  TRACE_ENTER
  #undef  TRACE_EXIT
  #undef  TRACE_PRINT1
  #undef  TRACE_PRINT2
  #undef  TRACE_PREFIX

  #define TRACE_ENTER(where)             PCAP_TRACE (1, " -> " where "().\n")
  #define TRACE_EXIT(where)              PCAP_TRACE (1, " <- " where "().\n")
  #define TRACE_PRINT1(fmt, arg1)        PCAP_TRACE (1, fmt, arg1)
  #define TRACE_PRINT2(fmt, arg1, arg2)  PCAP_TRACE (1, fmt, arg1, arg2)
  #define TRACE_PREFIX                  "[NPcapHelper] "
#endif

#ifdef __cplusplus
extern "C" {
#endif

extern CRITICAL_SECTION g_trace_crit;

extern int         _pcap_trace_level (void);
extern void        _pcap_trace_color (unsigned short col);
extern const char *_pcap_trace_basename (const char *fname);

#ifdef __cplusplus
}
#endif
#endif  /* _WIN32 */

