#undef  WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN

#include "config.h"

#if defined(USE_PCAP_TRACE)  /* Rest of file */

static CONSOLE_SCREEN_BUFFER_INFO console_info;
static HANDLE                     stdout_hnd;
static CRITICAL_SECTION           trace_crit;

void _pcap_trace_exit (void)
{
  PCAP_TRACE (1, "In %s()\n", __FUNCTION__);
  DeleteCriticalSection (&trace_crit);
}

int _pcap_trace_level (void)
{
  static int dbg_level = -1;
  const char *env;

  if (dbg_level != -1)   /* Already done this, get out */
     return (dbg_level);

  env = getenv ("PCAP_TRACE");
  if (env)
  {
    if (isdigit((int)*env))
         dbg_level = (*env - '0');
    else dbg_level = 0;
  }
  if (dbg_level > 0)
  {
    stdout_hnd = GetStdHandle (STD_OUTPUT_HANDLE);
    GetConsoleScreenBufferInfo (stdout_hnd, &console_info);
    InitializeCriticalSection (&trace_crit);
    atexit (_pcap_trace_exit);
  }
  return (dbg_level);
}

void _pcap_trace_color (unsigned short col)
{
  fflush (stdout);
  if (col == 0)
  {
    SetConsoleTextAttribute (stdout_hnd, console_info.wAttributes);
    LeaveCriticalSection (&trace_crit);
  }
  else
  {
    EnterCriticalSection (&trace_crit);
    SetConsoleTextAttribute (stdout_hnd, (console_info.wAttributes & ~7) | col);
  }
}

/*
 * Strip drive-letter and directory from a filename.
 */
#define IS_SLASH(c)  ((c) == '\\' || (c) == '/')

const char *_pcap_trace_basename (const char *fname)
{
  const char *base = fname;

  if (fname && *fname)
  {
    if (fname[0] && fname[1] == ':')
    {
      fname += 2;
      base = fname;
    }
    while (*fname)
    {
      if (IS_SLASH(*fname))
         base = fname + 1;
      fname++;
    }
  }
  return (base);
}
#endif /* USE_PCAP_TRACE */
