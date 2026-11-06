typedef __builtin_va_list va_list;
#define va_start(v, l) __builtin_va_start(v, l)
#define va_end(v) __builtin_va_end(v)

extern int vsscanf(const char *s, const char *format, va_list ap);

__attribute__((weak))
int __isoc23_sscanf(const char *s, const char *format, ...) {
    va_list ap;
    va_start(ap, format);
    int ret = vsscanf(s, format, ap);
    va_end(ap);
    return ret;
}

extern long strtol(const char *s, char **end, int base);

/* C23 also reads a 0b prefix; aws-lc only calls it with base 10, where both agree. */
__attribute__((weak))
long __isoc23_strtol(const char *s, char **end, int base) {
    return strtol(s, end, base);
}
