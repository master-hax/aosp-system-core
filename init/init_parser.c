/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <ctype.h>

#include "init.h"
#include "parser.h"
#include "init_parser.h"
#include "log.h"
#include "property_service.h"
#include "util.h"

#include <cutils/iosched_policy.h>
#include <cutils/list.h>

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

static list_declare(service_list);
static list_declare(action_list);
static list_declare(action_queue);

struct import {
    struct listnode list;
    const char *filename;
};

static void *parse_service(struct parse_state *state, int nargs, char **args);
static void parse_line_service(struct parse_state *state, int nargs, char **args);

static void *parse_action(struct parse_state *state, int nargs, char **args);
static void parse_line_action(struct parse_state *state, int nargs, char **args);

#define SECTION 0x01
#define COMMAND 0x02
#define OPTION  0x04

#include "keywords.h"

#define KEYWORD(symbol, flags, nargs, func) \
    [ K_##symbol ] = { #symbol, func, nargs + 1, flags, },

struct {
    const char *name;
    int (*func)(int nargs, char **args);
    unsigned char nargs;
    unsigned char flags;
} keyword_info[KEYWORD_COUNT] = {
    [ K_UNKNOWN ] = { "unknown", 0, 0, 0 },
#include "keywords.h"
};
#undef KEYWORD

#define kw_is(kw, type) (keyword_info[kw].flags & (type))
#define kw_name(kw) (keyword_info[kw].name)
#define kw_func(kw) (keyword_info[kw].func)
#define kw_nargs(kw) (keyword_info[kw].nargs)

int lookup_keyword(const char *s)
{
    switch (*s++) {
    case 'c':
    if (!strcmp(s, "opy")) return K_copy;
        if (!strcmp(s, "apability")) return K_capability;
        if (!strcmp(s, "hdir")) return K_chdir;
        if (!strcmp(s, "hroot")) return K_chroot;
        if (!strcmp(s, "lass")) return K_class;
        if (!strcmp(s, "lass_start")) return K_class_start;
        if (!strcmp(s, "lass_stop")) return K_class_stop;
        if (!strcmp(s, "lass_reset")) return K_class_reset;
        if (!strcmp(s, "onsole")) return K_console;
        if (!strcmp(s, "hown")) return K_chown;
        if (!strcmp(s, "hmod")) return K_chmod;
        if (!strcmp(s, "ritical")) return K_critical;
        break;
    case 'd':
        if (!strcmp(s, "isabled")) return K_disabled;
        if (!strcmp(s, "omainname")) return K_domainname;
        break;
    case 'e':
        if (!strcmp(s, "xec")) return K_exec;
        if (!strcmp(s, "xport")) return K_export;
        break;
    case 'g':
        if (!strcmp(s, "roup")) return K_group;
        break;
    case 'h':
        if (!strcmp(s, "ostname")) return K_hostname;
        break;
    case 'i':
        if (!strcmp(s, "oprio")) return K_ioprio;
        if (!strcmp(s, "fup")) return K_ifup;
        if (!strcmp(s, "nsmod")) return K_insmod;
        if (!strcmp(s, "mport")) return K_import;
        break;
    case 'k':
        if (!strcmp(s, "eycodes")) return K_keycodes;
        break;
    case 'l':
        if (!strcmp(s, "oglevel")) return K_loglevel;
        if (!strcmp(s, "oad_persist_props")) return K_load_persist_props;
        break;
    case 'm':
        if (!strcmp(s, "kdir")) return K_mkdir;
        if (!strcmp(s, "ount_all")) return K_mount_all;
        if (!strcmp(s, "ount")) return K_mount;
        break;
    case 'o':
        if (!strcmp(s, "n")) return K_on;
        if (!strcmp(s, "neshot")) return K_oneshot;
        if (!strcmp(s, "nrestart")) return K_onrestart;
        break;
    case 'r':
        if (!strcmp(s, "estart")) return K_restart;
        if (!strcmp(s, "estorecon")) return K_restorecon;
        if (!strcmp(s, "mdir")) return K_rmdir;
        if (!strcmp(s, "m")) return K_rm;
        break;
    case 's':
        if (!strcmp(s, "eclabel")) return K_seclabel;
        if (!strcmp(s, "ervice")) return K_service;
        if (!strcmp(s, "etcon")) return K_setcon;
        if (!strcmp(s, "etenforce")) return K_setenforce;
        if (!strcmp(s, "etenv")) return K_setenv;
        if (!strcmp(s, "etkey")) return K_setkey;
        if (!strcmp(s, "etprop")) return K_setprop;
        if (!strcmp(s, "etrlimit")) return K_setrlimit;
        if (!strcmp(s, "etsebool")) return K_setsebool;
        if (!strcmp(s, "ocket")) return K_socket;
        if (!strcmp(s, "tart")) return K_start;
        if (!strcmp(s, "top")) return K_stop;
        if (!strcmp(s, "ymlink")) return K_symlink;
        if (!strcmp(s, "ysclktz")) return K_sysclktz;
        break;
    case 't':
        if (!strcmp(s, "rigger")) return K_trigger;
        break;
    case 'u':
        if (!strcmp(s, "ser")) return K_user;
        break;
    case 'w':
        if (!strcmp(s, "rite")) return K_write;
        if (!strcmp(s, "ait")) return K_wait;
        break;
    }
    return K_UNKNOWN;
}

void parse_line_no_op(struct parse_state *state, int nargs, char **args)
{
}

static void push_chars(char *dst, int *dst_idx, const char *chars,
        int cnt)
{
    memcpy(dst + *dst_idx, chars, cnt);
    *dst_idx += cnt;
}

/* Advance a pointer through a string looking for a closing brace, copying all
 * characters up to the brace into a buffer.
 *
 * src - Pointer to original source string, used to print helpful error messages
 * token - Closing brace character to search for
 * c - Pointer to a memory location within src string, we start the search one
 * additional character from here. When the search is complete it will point to
 * the next character after the token.
 * dst - Destination buffer to copy all the characters inside the braces.
 * limit - Max size of the destination buffer.
 *
 * Returns 0 on success, or -1 on error.
 */
static int find_closing_brace(const char *src, const char token, char **c,
        char *dst, size_t limit)
{
    (*c)++;
    unsigned int i = 0;
    while (**c && **c != token && i < limit) {
        dst[i++] = **c;
        (*c)++;
    }
    if (**c != token) {
        if (i == limit)
            ERROR("prop name too long during expansion of '%s'", src);
        else
            ERROR("unable to find closing '%c' in %s", token, src);
        return -1;
    }
    if (i == 0) {
        ERROR("invalid zero-length prop name in '%s'\n", src);
        return -1;
    }
    dst[i] = '\0';
    (*c)++;
    return 0;
}

/* Expand the destination array to hold sz additional characters
 *
 * dst - Array to expand
 * dst_sz - Pointer to size of dst, which is updated
 * sz - Additional bytes to expand dst
 *
 * Returns NULL on memory errors
 */
static void *realloc_dst(void *dst, size_t *dst_sz,
        size_t sz)
{
    void *dst_new;
    *dst_sz += sz;
    dst_new = realloc(dst, *dst_sz);
    if (!dst_new) {
        free(dst);
        ERROR("out of memory for re-allocation %zu", *dst_sz);
    }
    return dst_new;
}

/* Accepts a source string and expands property and file dereferences.
 * The returned string must be freed; the original is unmodified.
 * Returns NULL if there are errors.
 *
 * no nested property expansion, i.e. ${foo.${bar}} is not supported,
 */
char *expand_references(const char *src)
{
    int cnt = 0;
    int dst_idx = 0;
    const char *src_ptr = src;
    size_t dst_sz;
    char *dst = NULL;

    if (!src)
        return NULL;

    dst_sz = strlen(src) + 1;
    dst = malloc(dst_sz);
    if (!dst) {
        ERROR("out of memory");
        return NULL;
    }

    while (*src_ptr) {
        char *c;

        c = strchr(src_ptr, '$');
        if (!c) {
            while (*src_ptr)
                dst[dst_idx++] = *(src_ptr++);
            break;
        }

        /* Copy everything up to the '$', then decide what to do with
         * what comes next */
        push_chars(dst, &dst_idx, src_ptr, c - src_ptr);
        c++;

        switch (*c) {
        case '$':
            /* $$ is a literal $ */
            dst[dst_idx++] = *(c++);
            src_ptr = c;
            continue;
        case '{': {
            char prop[PROP_NAME_MAX + 1];
            const char *prop_val;
            size_t prop_len = 0;

            /* ${property} = dereference a property */
            if (find_closing_brace(src, '}', &c, prop, PROP_NAME_MAX))
                goto err;
            prop_val = property_get(prop);
            if (!prop_val) {
                ERROR("property '%s' doesn't exist while expanding '%s'\n",
                    prop, src);
                goto err;
            }
            prop_len = strlen(prop_val);
            dst = realloc_dst(dst, &dst_sz, prop_len);
            if (!dst)
                goto err;
            push_chars(dst, &dst_idx, prop_val, prop_len);
            break;
        }
        case '[': {
            char *file_data;
            size_t file_len;
            char file_name[PATH_MAX + 1];

            /* $(file) = dereference file contents */
            if (find_closing_brace(src, ']', &c, file_name, PATH_MAX))
                goto err;
            file_data = read_file(file_name, NULL);
            if (!file_data) {
                ERROR("file %s cannot be opened for reading\n", src_ptr);
                goto err;
            }
            file_len = strlen(file_data);
            /* remove all trailing newlines              */
            /* including the one imposed by read_file() */
            while (file_len > 0 && file_data[file_len - 1] == '\n') {
                file_data[file_len - 1] = '\0';
                file_len--;
            }
            dst = realloc_dst(dst, &dst_sz, file_len);
            if (!dst) {
                free(file_data);
                goto err;
            }
            push_chars(dst, &dst_idx, file_data, file_len);
            free(file_data);
            break;
        }
        default:
            ERROR("expected '{', '[', or '$' after '$' in '%s'",
                src);
            goto err;
        }

        src_ptr = c;
        continue;
    }

    dst[dst_idx] = '\0';
    return dst;

err:
    free(dst);
    return NULL;
}

void parse_import(struct parse_state *state, int nargs, char **args)
{
    struct listnode *import_list = state->priv;
    struct import *import;
    char *conf_file;
    int ret;

    if (nargs != 2) {
        ERROR("single argument needed for import\n");
        return;
    }

    conf_file = expand_references(args[1]);
    if (!conf_file) {
        ERROR("error while handling import on line '%d' in '%s'\n",
              state->line, state->filename);
        return;
    }

    import = calloc(1, sizeof(struct import));
    import->filename = strdup(conf_file);
    list_add_tail(import_list, &import->list);
    free(conf_file);
    INFO("found import '%s', adding to import list", import->filename);
}

void parse_new_section(struct parse_state *state, int kw,
                       int nargs, char **args)
{
    printf("[ %s %s ]\n", args[0],
           nargs > 1 ? args[1] : "");
    switch(kw) {
    case K_service:
        state->context = parse_service(state, nargs, args);
        if (state->context) {
            state->parse_line = parse_line_service;
            return;
        }
        break;
    case K_on:
        state->context = parse_action(state, nargs, args);
        if (state->context) {
            state->parse_line = parse_line_action;
            return;
        }
        break;
    case K_import:
        parse_import(state, nargs, args);
        break;
    }
    state->parse_line = parse_line_no_op;
}

static void parse_config(const char *fn, char *s)
{
    struct parse_state state;
    struct listnode import_list;
    struct listnode *node;
    char *args[INIT_PARSER_MAXARGS];
    int nargs;

    nargs = 0;
    state.filename = fn;
    state.line = 0;
    state.ptr = s;
    state.nexttoken = 0;
    state.parse_line = parse_line_no_op;

    list_init(&import_list);
    state.priv = &import_list;

    for (;;) {
        switch (next_token(&state)) {
        case T_EOF:
            state.parse_line(&state, 0, 0);
            goto parser_done;
        case T_NEWLINE:
            state.line++;
            if (nargs) {
                int kw = lookup_keyword(args[0]);
                if (kw_is(kw, SECTION)) {
                    state.parse_line(&state, 0, 0);
                    parse_new_section(&state, kw, nargs, args);
                } else {
                    state.parse_line(&state, nargs, args);
                }
                nargs = 0;
            }
            break;
        case T_TEXT:
            if (nargs < INIT_PARSER_MAXARGS) {
                args[nargs++] = state.text;
            }
            break;
        }
    }

parser_done:
    list_for_each(node, &import_list) {
         struct import *import = node_to_item(node, struct import, list);
         int ret;

         INFO("importing '%s'", import->filename);
         ret = init_parse_config_file(import->filename);
         if (ret)
             ERROR("could not import file '%s' from '%s'\n",
                   import->filename, fn);
    }
}

int init_parse_config_file(const char *fn)
{
    char *data;
    data = read_file(fn, 0);
    if (!data) return -1;

    parse_config(fn, data);
    DUMP();
    return 0;
}

static int valid_name(const char *name)
{
    if (strlen(name) > 16) {
        return 0;
    }
    while (*name) {
        if (!isalnum(*name) && (*name != '_') && (*name != '-')) {
            return 0;
        }
        name++;
    }
    return 1;
}

struct service *service_find_by_name(const char *name)
{
    struct listnode *node;
    struct service *svc;
    list_for_each(node, &service_list) {
        svc = node_to_item(node, struct service, slist);
        if (!strcmp(svc->name, name)) {
            return svc;
        }
    }
    return 0;
}

struct service *service_find_by_pid(pid_t pid)
{
    struct listnode *node;
    struct service *svc;
    list_for_each(node, &service_list) {
        svc = node_to_item(node, struct service, slist);
        if (svc->pid == pid) {
            return svc;
        }
    }
    return 0;
}

struct service *service_find_by_keychord(int keychord_id)
{
    struct listnode *node;
    struct service *svc;
    list_for_each(node, &service_list) {
        svc = node_to_item(node, struct service, slist);
        if (svc->keychord_id == keychord_id) {
            return svc;
        }
    }
    return 0;
}

void service_for_each(void (*func)(struct service *svc))
{
    struct listnode *node;
    struct service *svc;
    list_for_each(node, &service_list) {
        svc = node_to_item(node, struct service, slist);
        func(svc);
    }
}

void service_for_each_class(const char *classname,
                            void (*func)(struct service *svc))
{
    struct listnode *node;
    struct service *svc;
    list_for_each(node, &service_list) {
        svc = node_to_item(node, struct service, slist);
        if (!strcmp(svc->classname, classname)) {
            func(svc);
        }
    }
}

void service_for_each_flags(unsigned matchflags,
                            void (*func)(struct service *svc))
{
    struct listnode *node;
    struct service *svc;
    list_for_each(node, &service_list) {
        svc = node_to_item(node, struct service, slist);
        if (svc->flags & matchflags) {
            func(svc);
        }
    }
}

void action_for_each_trigger(const char *trigger,
                             void (*func)(struct action *act))
{
    struct listnode *node;
    struct action *act;
    list_for_each(node, &action_list) {
        act = node_to_item(node, struct action, alist);
        if (!strcmp(act->name, trigger)) {
            func(act);
        }
    }
}

void queue_property_triggers(const char *name, const char *value)
{
    struct listnode *node;
    struct action *act;
    list_for_each(node, &action_list) {
        act = node_to_item(node, struct action, alist);
        if (!strncmp(act->name, "property:", strlen("property:"))) {
            const char *test = act->name + strlen("property:");
            int name_length = strlen(name);

            if (!strncmp(name, test, name_length) &&
                    test[name_length] == '=' &&
                    (!strcmp(test + name_length + 1, value) ||
                     !strcmp(test + name_length + 1, "*"))) {
                action_add_queue_tail(act);
            }
        }
    }
}

void queue_all_property_triggers()
{
    struct listnode *node;
    struct action *act;
    list_for_each(node, &action_list) {
        act = node_to_item(node, struct action, alist);
        if (!strncmp(act->name, "property:", strlen("property:"))) {
            /* parse property name and value
               syntax is property:<name>=<value> */
            const char* name = act->name + strlen("property:");
            const char* equals = strchr(name, '=');
            if (equals) {
                char prop_name[PROP_NAME_MAX + 1];
                const char* value;
                int length = equals - name;
                if (length > PROP_NAME_MAX) {
                    ERROR("property name too long in trigger %s", act->name);
                } else {
                    memcpy(prop_name, name, length);
                    prop_name[length] = 0;

                    /* does the property exist, and match the trigger value? */
                    value = property_get(prop_name);
                    if (value && (!strcmp(equals + 1, value) ||
                                  !strcmp(equals + 1, "*"))) {
                        action_add_queue_tail(act);
                    }
                }
            }
        }
    }
}

void queue_builtin_action(int (*func)(int nargs, char **args), char *name)
{
    struct action *act;
    struct command *cmd;

    act = calloc(1, sizeof(*act));
    act->name = name;
    list_init(&act->commands);

    cmd = calloc(1, sizeof(*cmd));
    cmd->func = func;
    cmd->args[0] = name;
    list_add_tail(&act->commands, &cmd->clist);

    list_add_tail(&action_list, &act->alist);
    action_add_queue_tail(act);
}

void action_add_queue_tail(struct action *act)
{
    list_add_tail(&action_queue, &act->qlist);
}

struct action *action_remove_queue_head(void)
{
    if (list_empty(&action_queue)) {
        return 0;
    } else {
        struct listnode *node = list_head(&action_queue);
        struct action *act = node_to_item(node, struct action, qlist);
        list_remove(node);
        return act;
    }
}

int action_queue_empty()
{
    return list_empty(&action_queue);
}

static void *parse_service(struct parse_state *state, int nargs, char **args)
{
    struct service *svc;
    if (nargs < 3) {
        parse_error(state, "services must have a name and a program\n");
        return 0;
    }
    if (!valid_name(args[1])) {
        parse_error(state, "invalid service name '%s'\n", args[1]);
        return 0;
    }

    svc = service_find_by_name(args[1]);
    if (svc) {
        parse_error(state, "ignored duplicate definition of service '%s'\n", args[1]);
        return 0;
    }

    nargs -= 2;
    svc = calloc(1, sizeof(*svc) + sizeof(char*) * nargs);
    if (!svc) {
        parse_error(state, "out of memory\n");
        return 0;
    }
    svc->name = args[1];
    svc->classname = "default";
    memcpy(svc->args, args + 2, sizeof(char*) * nargs);
    svc->args[nargs] = 0;
    svc->nargs = nargs;
    svc->onrestart.name = "onrestart";
    list_init(&svc->onrestart.commands);
    list_add_tail(&service_list, &svc->slist);
    return svc;
}

static void parse_line_service(struct parse_state *state, int nargs, char **args)
{
    struct service *svc = state->context;
    struct command *cmd;
    int i, kw, kw_nargs;

    if (nargs == 0) {
        return;
    }

    svc->ioprio_class = IoSchedClass_NONE;

    kw = lookup_keyword(args[0]);
    switch (kw) {
    case K_capability:
        break;
    case K_class:
        if (nargs != 2) {
            parse_error(state, "class option requires a classname\n");
        } else {
            svc->classname = args[1];
        }
        break;
    case K_console:
        svc->flags |= SVC_CONSOLE;
        break;
    case K_disabled:
        svc->flags |= SVC_DISABLED;
        svc->flags |= SVC_RC_DISABLED;
        break;
    case K_ioprio:
        if (nargs != 3) {
            parse_error(state, "ioprio optin usage: ioprio <rt|be|idle> <ioprio 0-7>\n");
        } else {
            svc->ioprio_pri = strtoul(args[2], 0, 8);

            if (svc->ioprio_pri < 0 || svc->ioprio_pri > 7) {
                parse_error(state, "priority value must be range 0 - 7\n");
                break;
            }

            if (!strcmp(args[1], "rt")) {
                svc->ioprio_class = IoSchedClass_RT;
            } else if (!strcmp(args[1], "be")) {
                svc->ioprio_class = IoSchedClass_BE;
            } else if (!strcmp(args[1], "idle")) {
                svc->ioprio_class = IoSchedClass_IDLE;
            } else {
                parse_error(state, "ioprio option usage: ioprio <rt|be|idle> <0-7>\n");
            }
        }
        break;
    case K_group:
        if (nargs < 2) {
            parse_error(state, "group option requires a group id\n");
        } else if (nargs > NR_SVC_SUPP_GIDS + 2) {
            parse_error(state, "group option accepts at most %d supp. groups\n",
                        NR_SVC_SUPP_GIDS);
        } else {
            int n;
            svc->gid = decode_uid(args[1]);
            for (n = 2; n < nargs; n++) {
                svc->supp_gids[n-2] = decode_uid(args[n]);
            }
            svc->nr_supp_gids = n - 2;
        }
        break;
    case K_keycodes:
        if (nargs < 2) {
            parse_error(state, "keycodes option requires atleast one keycode\n");
        } else {
            svc->keycodes = malloc((nargs - 1) * sizeof(svc->keycodes[0]));
            if (!svc->keycodes) {
                parse_error(state, "could not allocate keycodes\n");
            } else {
                svc->nkeycodes = nargs - 1;
                for (i = 1; i < nargs; i++) {
                    svc->keycodes[i - 1] = atoi(args[i]);
                }
            }
        }
        break;
    case K_oneshot:
        svc->flags |= SVC_ONESHOT;
        break;
    case K_onrestart:
        nargs--;
        args++;
        kw = lookup_keyword(args[0]);
        if (!kw_is(kw, COMMAND)) {
            parse_error(state, "invalid command '%s'\n", args[0]);
            break;
        }
        kw_nargs = kw_nargs(kw);
        if (nargs < kw_nargs) {
            parse_error(state, "%s requires %d %s\n", args[0], kw_nargs - 1,
                kw_nargs > 2 ? "arguments" : "argument");
            break;
        }

        cmd = malloc(sizeof(*cmd) + sizeof(char*) * nargs);
        cmd->func = kw_func(kw);
        cmd->nargs = nargs;
        memcpy(cmd->args, args, sizeof(char*) * nargs);
        list_add_tail(&svc->onrestart.commands, &cmd->clist);
        break;
    case K_critical:
        svc->flags |= SVC_CRITICAL;
        break;
    case K_setenv: { /* name value */
        struct svcenvinfo *ei;
        if (nargs < 2) {
            parse_error(state, "setenv option requires name and value arguments\n");
            break;
        }
        ei = calloc(1, sizeof(*ei));
        if (!ei) {
            parse_error(state, "out of memory\n");
            break;
        }
        ei->name = args[1];
        ei->value = args[2];
        ei->next = svc->envvars;
        svc->envvars = ei;
        break;
    }
    case K_socket: {/* name type perm [ uid gid ] */
        struct socketinfo *si;
        if (nargs < 4) {
            parse_error(state, "socket option requires name, type, perm arguments\n");
            break;
        }
        if (strcmp(args[2],"dgram") && strcmp(args[2],"stream")
                && strcmp(args[2],"seqpacket")) {
            parse_error(state, "socket type must be 'dgram', 'stream' or 'seqpacket'\n");
            break;
        }
        si = calloc(1, sizeof(*si));
        if (!si) {
            parse_error(state, "out of memory\n");
            break;
        }
        si->name = args[1];
        si->type = args[2];
        si->perm = strtoul(args[3], 0, 8);
        if (nargs > 4)
            si->uid = decode_uid(args[4]);
        if (nargs > 5)
            si->gid = decode_uid(args[5]);
        si->next = svc->sockets;
        svc->sockets = si;
        break;
    }
    case K_user:
        if (nargs != 2) {
            parse_error(state, "user option requires a user id\n");
        } else {
            svc->uid = decode_uid(args[1]);
        }
        break;
    case K_seclabel:
        if (nargs != 2) {
            parse_error(state, "seclabel option requires a label string\n");
        } else {
            svc->seclabel = args[1];
        }
        break;

    default:
        parse_error(state, "invalid option '%s'\n", args[0]);
    }
}

static void *parse_action(struct parse_state *state, int nargs, char **args)
{
    struct action *act;
    if (nargs < 2) {
        parse_error(state, "actions must have a trigger\n");
        return 0;
    }
    if (nargs > 2) {
        parse_error(state, "actions may not have extra parameters\n");
        return 0;
    }
    act = calloc(1, sizeof(*act));
    act->name = args[1];
    list_init(&act->commands);
    list_add_tail(&action_list, &act->alist);
        /* XXX add to hash */
    return act;
}

static void parse_line_action(struct parse_state* state, int nargs, char **args)
{
    struct command *cmd;
    struct action *act = state->context;
    int (*func)(int nargs, char **args);
    int kw, n;

    if (nargs == 0) {
        return;
    }

    kw = lookup_keyword(args[0]);
    if (!kw_is(kw, COMMAND)) {
        parse_error(state, "invalid command '%s'\n", args[0]);
        return;
    }

    n = kw_nargs(kw);
    if (nargs < n) {
        parse_error(state, "%s requires %d %s\n", args[0], n - 1,
            n > 2 ? "arguments" : "argument");
        return;
    }
    cmd = malloc(sizeof(*cmd) + sizeof(char*) * nargs);
    cmd->func = kw_func(kw);
    cmd->nargs = nargs;
    memcpy(cmd->args, args, sizeof(char*) * nargs);
    list_add_tail(&act->commands, &cmd->clist);
}
