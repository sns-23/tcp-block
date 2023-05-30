#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>

#include "util.h"

void report(char indicator, int level, const char *fmt, ...) 
{
    FILE *stream = (level == ERROR_LEVEL) ? stderr : stdout;
    va_list a;

    if (level > LOG_LEVEL)
        return;

    va_start(a, fmt);
    fprintf(stream, "[%c] %s", indicator, (level == ERROR_LEVEL) ? "ERROR: " : "");
    vfprintf(stream, fmt, a);
    va_end(a);
}

/* see https://gist.github.com/richinseattle/c527a3acb6f152796a580401057c78b4 */
#ifndef HEXDUMP_COLS
#define HEXDUMP_COLS 16
#endif
 
void hexdump(void *mem, unsigned int len)
{
    unsigned int i, j;
    
    for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
        /* print offset */
        if(i % HEXDUMP_COLS == 0)
        {
            printf("0x%06x: ", i);
        }

        /* print hex data */
        if(i < len)
        {
            printf("%02x ", 0xFF & ((char*)mem)[i]);
        }
        else /* end of block, just aligning for ASCII dump */
        {
            printf("   ");
        }
        
        /* print ASCII dump */
        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1))
        {
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++)
            {
                if(j >= len) /* end of block, not really printing */
                {
                    putchar(' ');
                }
                else if(isprint(((char*)mem)[j])) /* printable char */
                {
                    putchar(0xFF & ((char*)mem)[j]);        
                }
                else /* other char */
                {
                    putchar('.');
                }
            }
            putchar('\n');
        }
    }
}