#ifndef __UTIL_H__
#define __UTIL_H__

#define ERROR_LEVEL 0
#define WARN_LEVEL  1
#define INFO_LEVEL  2
#define DEBUG_LEVEL 3

#ifndef LOG_LEVEL
#define LOG_LEVEL INFO_LEVEL
#endif

#if LOG_LEVEL > DEBUG_LEVEL
#undef LOG_LEVEL
#define LOG_LEVEL INFO_LEVEL
#endif
#if LOG_LEVLE < ERROR_LEVEL
#undef LOG_LEVEL
#define LOG_LEVEL INFO_LEVEL
#endif

#define pr_err(fmt, args...) report('!', ERROR_LEVEL, fmt, ## args)
#define pr_warn(fmt, args...) report('*', WARN_LEVEL, fmt, ## args)
#define pr_info(fmt, args...) report('+', INFO_LEVEL, fmt, ## args)
#define pr_debug(fmt, args...) report('?', DEBUG_LEVEL, fmt, ## args)

void report(char indicator, int level, const char *fmt, ...);
void hexdump(void *mem, unsigned int len);

#endif /* __UTIL_H__ */