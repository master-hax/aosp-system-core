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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "action.h"
#include "init.h"
#include "parser.h"
#include "init_parser.h"
#include "property_service.h"
#include "util.h"

#include <base/logging.h>
#include <base/stringprintf.h>
#include <cutils/iosched_policy.h>
#include <cutils/list.h>

static list_declare(service_list);

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

static struct {
    const char *name;
    int (*func)(const std::vector<std::string>& args);
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

void dump_parser_state() {
    if (false) {
        struct listnode* node;
        list_for_each(node, &service_list) {
            service* svc = node_to_item(node, struct service, slist);
            LOG(DEBUG) << "service " << svc->name;
            LOG(DEBUG) << "  class '" << svc->classname << "'";
            std::string log_command;
            for (int n = 0; n < svc->nargs; n++) {
                android::base::StringAppendF(&log_command, " '%s'", svc->args[n]);
            }
            LOG(DEBUG) << "  exec" << log_command;
            for (socketinfo* si = svc->sockets; si; si = si->next) {
                LOG(DEBUG) << "  socket " << si->name << " " 
                           << si->type << " 0" << std::oct << si->perm;
            }
        }
        ActionManager::GetInstance().DumpState();
    }
}

static int lookup_keyword(const char *s)
{
    switch (*s++) {
    case 'b':
        if (!strcmp(s, "ootchart_init")) return K_bootchart_init;
        break;
    case 'c':
        if (!strcmp(s, "opy")) return K_copy;
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
        if (!strcmp(s, "nable")) return K_enable;
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
        if (!strcmp(s, "nstallkey")) return K_installkey;
        break;
    case 'k':
        if (!strcmp(s, "eycodes")) return K_keycodes;
        break;
    case 'l':
        if (!strcmp(s, "oglevel")) return K_loglevel;
        if (!strcmp(s, "oad_persist_props")) return K_load_persist_props;
        if (!strcmp(s, "oad_all_props")) return K_load_all_props;
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
    case 'p':
        if (!strcmp(s, "owerctl")) return K_powerctl;
        break;
    case 'r':
        if (!strcmp(s, "estart")) return K_restart;
        if (!strcmp(s, "estorecon")) return K_restorecon;
        if (!strcmp(s, "estorecon_recursive")) return K_restorecon_recursive;
        if (!strcmp(s, "mdir")) return K_rmdir;
        if (!strcmp(s, "m")) return K_rm;
        break;
    case 's':
        if (!strcmp(s, "eclabel")) return K_seclabel;
        if (!strcmp(s, "ervice")) return K_service;
        if (!strcmp(s, "etenv")) return K_setenv;
        if (!strcmp(s, "etprop")) return K_setprop;
        if (!strcmp(s, "etrlimit")) return K_setrlimit;
        if (!strcmp(s, "ocket")) return K_socket;
        if (!strcmp(s, "tart")) return K_start;
        if (!strcmp(s, "top")) return K_stop;
        if (!strcmp(s, "wapon_all")) return K_swapon_all;
        if (!strcmp(s, "ymlink")) return K_symlink;
        if (!strcmp(s, "ysclktz")) return K_sysclktz;
        break;
    case 't':
        if (!strcmp(s, "rigger")) return K_trigger;
        break;
    case 'u':
        if (!strcmp(s, "ser")) return K_user;
        break;
    case 'v':
        if (!strcmp(s, "erity_load_state")) return K_verity_load_state;
        if (!strcmp(s, "erity_update_state")) return K_verity_update_state;
        break;
    case 'w':
        if (!strcmp(s, "rite")) return K_write;
        if (!strcmp(s, "ritepid")) return K_writepid;
        if (!strcmp(s, "ait")) return K_wait;
        break;
    }
    return K_UNKNOWN;
}

static void parse_line_no_op(struct parse_state*, int, char**) {
}

int expand_props(const std::string& src, std::string* dst) {
    const char *src_ptr = src.c_str();

    if (!dst) {
        return -1;
    }

    /* - variables can either be $x.y or ${x.y}, in case they are only part
     *   of the string.
     * - will accept $$ as a literal $.
     * - no nested property expansion, i.e. ${foo.${bar}} is not supported,
     *   bad things will happen
     */
    while (*src_ptr) {
        const char *c;

        c = strchr(src_ptr, '$');
        if (!c) {
            dst->append(src_ptr);
            break;
        }

        dst->append(src_ptr, c);
        c++;

        if (*c == '$') {
            dst->push_back(*(c++));
            src_ptr = c;
            continue;
        } else if (*c == '\0') {
            break;
        }

        std::string prop_name;
        if (*c == '{') {
            c++;
            const char* end = strchr(c, '}');
            if (!end) {
                // failed to find closing brace, abort.
                LOG(ERROR) << "unexpected end of string in '" << src << "', looking for }";
                goto err;
            }
            prop_name = std::string(c, end);
            c = end + 1;
        } else {
            prop_name = c;
            LOG(ERROR) << "using deprecated syntax for specifying property '"
                       << c << "', use ${name} instead";
            c += prop_name.size();
        }

        if (prop_name.empty()) {
            LOG(ERROR) << "invalid zero-length prop name in '" << src << "'";
            goto err;
        }

        std::string prop_val = property_get(prop_name.c_str());
        if (prop_val.empty()) {
            LOG(ERROR) << "property '" << prop_name
                       << "' doesn't exist while expanding '" << src << "'";
            goto err;
        }

        dst->append(prop_val);
        src_ptr = c;
        continue;
    }

    return 0;
err:
    return -1;
}

static void parse_import(struct parse_state *state, int nargs, char **args)
{
    if (nargs != 2) {
        LOG(ERROR) << "single argument needed for import";
        return;
    }

    std::string conf_file;
    int ret = expand_props(args[1], &conf_file);
    if (ret) {
        LOG(ERROR) << "error while handling import on line '" << state->line
                   << "' in '" << state->filename << "'";
        return;
    }

    struct import* import = (struct import*) calloc(1, sizeof(struct import));
    import->filename = strdup(conf_file.c_str());

    struct listnode *import_list = (listnode*) state->priv;
    list_add_tail(import_list, &import->list);
    LOG(DEBUG) << "Added '" << import->filename << "' to import list";
}

static void parse_new_section(struct parse_state *state, int kw,
                       int nargs, char **args)
{
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

static void parse_config(const char *fn, const std::string& data)
{
    struct listnode import_list;
    struct listnode *node;
    char *args[INIT_PARSER_MAXARGS];

    int nargs = 0;

    parse_state state;
    state.filename = fn;
    state.line = 0;
    state.ptr = strdup(data.c_str());  // TODO: fix this code!
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
         struct import* import = node_to_item(node, struct import, list);
         if (!init_parse_config(import->filename)) {
             PLOG(ERROR) << "could not import file '" << import->filename
                         << "' from '" << fn;
         }
    }
}

static bool init_parse_config_file(const char* path) {
    LOG(DEBUG) << "Parsing file " << path << "...";
    Timer t;
    std::string data;
    if (!read_file(path, &data)) {
        return false;
    }

    data.push_back('\n'); // TODO: fix parse_config.
    parse_config(path, data);
    dump_parser_state();

    LOG(INFO) << "Parsing " << path << " took " << t.duration() << "s.)";
    return true;
}

static bool init_parse_config_dir(const char* path) {
    LOG(DEBUG) << "Parsing directory " << path << "...";
    std::unique_ptr<DIR, int(*)(DIR*)> config_dir(opendir(path), closedir);
    if (!config_dir) {
        LOG(ERROR) << "Could not import directory '" << path << "'";
        return false;
    }
    dirent* current_file;
    while ((current_file = readdir(config_dir.get()))) {
        std::string current_path =
            android::base::StringPrintf("%s/%s", path, current_file->d_name);
        // Ignore directories and only process regular files.
        if (current_file->d_type == DT_REG) {
            if (!init_parse_config_file(current_path.c_str())) {
                LOG(ERROR) << "could not import file '" << current_path << "'";
            }
        }
    }
    return true;
}

bool init_parse_config(const char* path) {
    if (is_dir(path)) {
        return init_parse_config_dir(path);
    }
    return init_parse_config_file(path);
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

service* make_exec_oneshot_service(int nargs, char** args) {
    // Parse the arguments: exec [SECLABEL [UID [GID]*] --] COMMAND ARGS...
    // SECLABEL can be a - to denote default
    int command_arg = 1;
    for (int i = 1; i < nargs; ++i) {
        if (strcmp(args[i], "--") == 0) {
            command_arg = i + 1;
            break;
        }
    }
    if (command_arg > 4 + NR_SVC_SUPP_GIDS) {
        LOG(ERROR) << "exec called with too many supplementary group ids";
        return NULL;
    }

    int argc = nargs - command_arg;
    char** argv = (args + command_arg);
    if (argc < 1) {
        LOG(ERROR) << "exec called without command";
        return NULL;
    }

    service* svc = (service*) calloc(1, sizeof(*svc) + sizeof(char*) * argc);
    if (svc == NULL) {
        PLOG(ERROR) << "Couldn't allocate service for exec of " << argv[0];
        return NULL;
    }

    if ((command_arg > 2) && strcmp(args[1], "-")) {
        svc->seclabel = args[1];
    }
    if (command_arg > 3) {
        svc->uid = decode_uid(args[2]);
    }
    if (command_arg > 4) {
        svc->gid = decode_uid(args[3]);
        svc->nr_supp_gids = command_arg - 1 /* -- */ - 4 /* exec SECLABEL UID GID */;
        for (size_t i = 0; i < svc->nr_supp_gids; ++i) {
            svc->supp_gids[i] = decode_uid(args[4 + i]);
        }
    }

    static int exec_count; // Every service needs a unique name.
    char* name = NULL;
    asprintf(&name, "exec %d (%s)", exec_count++, argv[0]);
    if (name == NULL) {
        LOG(ERROR) << "Couldn't allocate name for exec service '" << argv[0] << "'";
        free(svc);
        return NULL;
    }
    svc->name = name;
    svc->classname = "default";
    svc->flags = SVC_EXEC | SVC_ONESHOT;
    svc->nargs = argc;
    memcpy(svc->args, argv, sizeof(char*) * svc->nargs);
    svc->args[argc] = NULL;
    list_add_tail(&service_list, &svc->slist);
    return svc;
}

static void *parse_service(struct parse_state *state, int nargs, char **args)
{
    if (nargs < 3) {
        parse_error(state, "services must have a name and a program\n");
        return 0;
    }
    if (!valid_name(args[1])) {
        parse_error(state, "invalid service name '%s'\n", args[1]);
        return 0;
    }

    service* svc = (service*) service_find_by_name(args[1]);
    if (svc) {
        parse_error(state, "ignored duplicate definition of service '%s'\n", args[1]);
        return 0;
    }

    nargs -= 2;
    svc = (service*) calloc(1, sizeof(*svc) + sizeof(char*) * nargs);
    if (!svc) {
        parse_error(state, "out of memory\n");
        return 0;
    }
    svc->name = strdup(args[1]);
    svc->classname = "default";
    memcpy(svc->args, args + 2, sizeof(char*) * nargs);
    svc->args[nargs] = 0;
    svc->nargs = nargs;
    svc->onrestart = new Action();
    svc->onrestart->InitSingleTrigger("onrestart");
    list_add_tail(&service_list, &svc->slist);
    return svc;
}

static void parse_line_service(struct parse_state *state, int nargs, char **args)
{
    struct service *svc = (service*) state->context;
    int i, kw, kw_nargs;
    std::vector<std::string> str_args;

    if (nargs == 0) {
        return;
    }

    svc->ioprio_class = IoSchedClass_NONE;

    kw = lookup_keyword(args[0]);
    switch (kw) {
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
            svc->keycodes = (int*) malloc((nargs - 1) * sizeof(svc->keycodes[0]));
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
        str_args.assign(args, args + nargs);
        svc->onrestart->AddCommand(kw_func(kw), str_args);
        break;
    case K_critical:
        svc->flags |= SVC_CRITICAL;
        break;
    case K_setenv: { /* name value */
        if (nargs < 3) {
            parse_error(state, "setenv option requires name and value arguments\n");
            break;
        }
        svcenvinfo* ei = (svcenvinfo*) calloc(1, sizeof(*ei));
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
    case K_socket: {/* name type perm [ uid gid context ] */
        if (nargs < 4) {
            parse_error(state, "socket option requires name, type, perm arguments\n");
            break;
        }
        if (strcmp(args[2],"dgram") && strcmp(args[2],"stream")
                && strcmp(args[2],"seqpacket")) {
            parse_error(state, "socket type must be 'dgram', 'stream' or 'seqpacket'\n");
            break;
        }
        socketinfo* si = (socketinfo*) calloc(1, sizeof(*si));
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
        if (nargs > 6)
            si->socketcon = args[6];
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
    case K_writepid:
        if (nargs < 2) {
            parse_error(state, "writepid option requires at least one filename\n");
            break;
        }
        svc->writepid_files_ = new std::vector<std::string>;
        for (int i = 1; i < nargs; ++i) {
            svc->writepid_files_->push_back(args[i]);
        }
        break;

    default:
        parse_error(state, "invalid option '%s'\n", args[0]);
    }
}

static void *parse_action(struct parse_state* state, int nargs, char **args)
{
    std::string ret_err;
    std::vector<std::string> triggers(args + 1, args + nargs);
    Action* ret = ActionManager::GetInstance().AddNewAction(triggers, &ret_err);

    if (!ret) {
        parse_error(state, "%s\n", ret_err.c_str());
    }

    return ret;
}

static void parse_line_action(struct parse_state* state, int nargs, char **args)
{
    Action* act = (Action*) state->context;
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

    std::vector<std::string> str_args(args, args + nargs);
    act->AddCommand(kw_func(kw), str_args, state->filename, state->line);
}
