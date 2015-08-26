#ifndef KEYWORD
#define __MAKE_KEYWORD_ENUM__
#define KEYWORD(symbol, flags, nargs, func) K_##symbol,
enum {
    K_UNKNOWN,
#endif
    KEYWORD(class,       OPTION,  0, 0)
    KEYWORD(console,     OPTION,  0, 0)
    KEYWORD(critical,    OPTION,  0, 0)
    KEYWORD(disabled,    OPTION,  0, 0)
    KEYWORD(group,       OPTION,  0, 0)
    KEYWORD(ioprio,      OPTION,  0, 0)
    KEYWORD(keycodes,    OPTION,  0, 0)
    KEYWORD(oneshot,     OPTION,  0, 0)
    KEYWORD(onrestart,   OPTION,  0, 0)
    KEYWORD(seclabel,    OPTION,  0, 0)
    KEYWORD(setenv,      OPTION,  2, 0)
    KEYWORD(socket,      OPTION,  0, 0)
    KEYWORD(user,        OPTION,  0, 0)
    KEYWORD(writepid,    OPTION,  0, 0)
#ifdef __MAKE_KEYWORD_ENUM__
    KEYWORD_COUNT,
};
#undef __MAKE_KEYWORD_ENUM__
#undef KEYWORD
#endif
