/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include <fcntl.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <linux/netlink.h>

#include <selinux/selinux.h>
#include <selinux/label.h>
#include <selinux/android.h>
#include <selinux/avc.h>

#include <private/android_filesystem_config.h>
#include <sys/time.h>
#include <asm/page.h>
#include <sys/wait.h>

#include <cutils/list.h>
#include <cutils/uevent.h>

#include "devices.h"
#include "util.h"
#include "log.h"

#define SYSFS_PREFIX    "/sys"
#define FIRMWARE_DIR1   "/etc/firmware"
#define FIRMWARE_DIR2   "/vendor/firmware"
#define FIRMWARE_DIR3   "/firmware/image"

extern struct selabel_handle *sehandle;

static int device_fd = -1;

struct perms_ {
    char *name;
    char *attr;
    mode_t perm;
    unsigned int uid;
    unsigned int gid;
    unsigned short prefix;
};

struct inet_name_ {
    char *net_link;
    char *if_name;
    char *target_name;
};

struct dev_name_ {
    unsigned int vid;
    unsigned int pid;
    char *dev_if_name;
    char *dev_target_name;
};

struct perm_node {
    struct perms_ dp;
    struct listnode plist;
};

struct platform_node {
    char *name;
    char *path;
    int path_len;
    struct listnode list;
};


struct inet_node {
    struct inet_name_ inet_rename;
    struct listnode plist;
};

struct dev_node {
    struct dev_name_ dev_rename;
    struct listnode plist;
};

static list_declare(sys_perms);
static list_declare(dev_perms);
static list_declare(dev_names);
static list_declare(inet_names);
static list_declare(platform_names);

int add_dev_perms(const char *name, const char *attr,
                  mode_t perm, unsigned int uid, unsigned int gid,
                  unsigned short prefix) {
    struct perm_node *node = calloc(1, sizeof(*node));
    if (!node)
        return -ENOMEM;

    node->dp.name = strdup(name);
    if (!node->dp.name)
        return -ENOMEM;

    if (attr) {
        node->dp.attr = strdup(attr);
        if (!node->dp.attr)
            return -ENOMEM;
    }

    node->dp.perm = perm;
    node->dp.uid = uid;
    node->dp.gid = gid;
    node->dp.prefix = prefix;

    if (attr)
        list_add_tail(&sys_perms, &node->plist);
    else
        list_add_tail(&dev_perms, &node->plist);

    return 0;
}

int add_inet_args(char *net_link, char *if_name, char *target_name)
{
    struct inet_node *node = calloc(1, sizeof(*node));

    NOTICE("%s: Net link:%s, If name:%s, New inet name:%s",
          __func__, net_link, if_name, target_name);

    if (!node)
        goto Error;

    node->inet_rename.net_link = strdup(net_link);
    if (!node->inet_rename.net_link)
        goto Error;

    node->inet_rename.if_name = strdup(if_name);
    if (!node->inet_rename.if_name)
        goto Error;

    node->inet_rename.target_name = strdup(target_name);
    if (!node->inet_rename.target_name)
        goto Error;

    list_add_tail(&inet_names, &node->plist);
    return 0;

Error:
    if (node) {
        free(node->inet_rename.net_link);
        free(node->inet_rename.if_name);
        free(node);
    }
    return -ENOMEM;
}

static char *get_inet_name(const char *inet_name, struct uevent *uevent)
{
    struct listnode *node;
    struct inet_node *inetnode;
    struct inet_name_ *names;
    /* Path to inet address */
    char address_path[MAX_DEV_PATH];
    /* inet address */
    char *address = NULL;
    /* To avoid unnecessary addr checking */
    bool addr_check = false;
    unsigned int sz = 0;
    int fd = 0;
    int lennetlink=0;

    if (!inet_name) {
        ERROR("%s:ERROR network interface name is NULL.", __func__);
        return NULL;
    }
    NOTICE("%s:Checking inet:%s", __func__, inet_name);

    if (!uevent || !uevent->path) {
        ERROR("%s:ERROR Uevent is NULL.", __func__);
        return NULL;
    }

    list_for_each(node, &inet_names) {
        inetnode = node_to_item(node, struct inet_node, plist);
        names = &inetnode->inet_rename;

        /* Check inet name with target name */
        if (!strcmp(inet_name, names->target_name)) {
            ERROR("%s:Original inet name:%s is the same as target...skip...",
                  __func__, inet_name);
            /* No need to continue parsing as target is same as original */
            continue;
        }

        /* Check inetnode's inet name */
        if (!strcmp(inet_name, names->if_name)) {
            NOTICE("%s:RULE ==> [%s, %s] Target:%s",
                   __func__, names->net_link,
                   names->if_name, names->target_name);
            /* Check wildcard */
            if (strncmp(names->net_link, "*", 1)) {
                /* Retrieve inet address */
                if (!addr_check) {
                    snprintf(address_path, sizeof(address_path),
                             "/sys%s/address", uevent->path);
                    NOTICE("%s: Read net link addr at:%s",
                          __func__, address_path);
                    address = read_file(address_path, &sz);
                    addr_check = true;
                }
                if (address) {
                    lennetlink = strlen(names->net_link);
                    if (!strncmp(names->net_link, address, lennetlink)) {
                        NOTICE("%s: %s net_link addr FOUND",
                              __func__, address);
                        return names->target_name;
                    } else {
                        ERROR("%s: %s net_link addr NOT FOUND",
                              __func__, names->net_link);
                    }
                } else {
                    ERROR("%s: ERROR: Net link addr is NULL for inet name:%s",
                          __func__, inet_name);
                }
            }
            else {
                NOTICE("%s:WILDCARD (*) FOR net_link", __func__);
                return names->target_name;
            }
        }
    }
    return NULL;
}

int add_dev_args(unsigned int vid, unsigned int pid, char *dev_name, char *target_name)
{
    struct dev_node *node = calloc(1, sizeof(*node));

    NOTICE("%s: Vendor Id:%d, Product Id:%d, Device name:%s, New name:%s",
          __func__, vid, pid, dev_name, target_name);

    if (!node)
        goto Error;

    node->dev_rename.dev_if_name = strdup(dev_name);
    if (!node->dev_rename.dev_if_name)
        goto Error;

    node->dev_rename.dev_target_name = strdup(target_name);
    if (!node->dev_rename.dev_target_name)
        goto Error;

    node->dev_rename.vid = vid;
    node->dev_rename.pid = pid;

    list_add_tail(&dev_names, &node->plist);
    return 0;

Error:
    if (node) {
        free(node->dev_rename.dev_if_name);
        free(node);
    }
    return -ENOMEM;
}

static char *get_dev_name(const char *path, struct uevent *uevent)
{
    struct listnode *node;
    struct dev_node *devnode;
    struct dev_name_ *names;
    unsigned int vid = 0;
    unsigned int pid = 0;
    char dev_path[128];
    char path_ids[MAX_DEV_PATH];
    unsigned int sz = 0;
    bool modalias_check = false;
    const char *modalias = NULL;
    char* data = NULL;

    if ((!uevent) || (!uevent->path))
        return path;

    if (uevent->modalias) {
            NOTICE("%s:Found Modalias:%s for Dev:%s",
              __func__, uevent->modalias, path);
            modalias = uevent->modalias;
    }

    list_for_each(node, &dev_names) {
        devnode = node_to_item(node, struct dev_node, plist);
        names = &devnode->dev_rename;

        /* Find out associated device */
        snprintf(dev_path, sizeof(dev_path),"/dev/%s", names->dev_if_name);
        if (strcmp(path, dev_path))
                continue;

        /* Check dev name with target name */
        if (!strcmp(dev_path, names->dev_target_name)) {
            ERROR("%s:Dev name:%s is the same as target name...skip...",
                  __func__, dev_path);
            /* No need to continue parsing as target is same as original */
            continue;
        }

        NOTICE("%s:Checking %s, looking for vid:%d, pid:%d...",
              __func__, dev_path, names->vid, names->pid);

        /* Retrieve device info */
        if (!modalias_check) {
            if (!modalias) {
                /* Modalias not available in uevent */
                NOTICE("%s:Retrieve Modalias from sysfs for dev:%s",
                       __func__, path);
                snprintf(path_ids, sizeof(path_ids),
                         "/sys%s/device/modalias", uevent->path);
                NOTICE("%s:Modalias sysfs path:%s", __func__, path_ids);
                modalias = read_file(path_ids, &sz);
                if (sz == 0) {
                    ERROR("%s: ERROR reading modalias file, err:%d",
                          __func__, errno);
                    /* Not a problem if wildcard selected for vid and pid */
                } else {
                    NOTICE("%s:Found Modalias:%s, sz:%d",
                          __func__, modalias, sz);
                }
            }

            if (modalias) {
                /* Retrieve Vendor and Product Ids */
                data = strchr(modalias, 'v');
                if (data) {
                    sscanf(data,"v%dp%d", &vid, &pid);
                }
                else {
                    ERROR("%s:Cannot find Vendor ID in %s",
                          __func__, modalias);
                    modalias = NULL;
                }
            }
            modalias_check = true;
        }

        /* names->vid == 0 means wildcard */
        if (names->vid) {
            /* Search for Vendor Id */
            if (modalias) {
                if (names->vid != vid) {
                    ERROR("%s:WRONG ID VENDOR: vid:%d vs %d",
                          __func__, names->vid, vid);
                    continue;
                }
            } else {
                ERROR("%s:No correct Modalias FOUND!\n", __func__);
                continue;
            }
        }
        /* names->pid == 0 means wildcard */
        if (names->pid) {
            /* Search for Product Id */
            if (modalias) {
                if (names->pid != pid) {
                    ERROR("%s:WRONG ID PRODUCT: pid:%d vs %d",
                          __func__, names->pid, pid);
                    continue;
                }
            } else {
                ERROR("%s:No correct Modalias FOUND!\n", __func__);
                continue;
            }
        }
        NOTICE("%s:RENAMING DEVICE %s [vid:%d, pid:%d, New dev name:%s]",
              __func__, path, vid, pid, names->dev_target_name);
        return names->dev_target_name;
    }

    return path;
}

void fixup_sys_perms(const char *upath)
{
    char buf[512];
    struct listnode *node;
    struct perms_ *dp;
    char *secontext;

        /* upaths omit the "/sys" that paths in this list
         * contain, so we add 4 when comparing...
         */
    list_for_each(node, &sys_perms) {
        dp = &(node_to_item(node, struct perm_node, plist))->dp;
        if (dp->prefix) {
            if (strncmp(upath, dp->name + 4, strlen(dp->name + 4)))
                continue;
        } else {
            if (strcmp(upath, dp->name + 4))
                continue;
        }

        if ((strlen(upath) + strlen(dp->attr) + 6) > sizeof(buf))
            return;

        sprintf(buf,"/sys%s/%s", upath, dp->attr);
        INFO("fixup %s %d %d 0%o\n", buf, dp->uid, dp->gid, dp->perm);
        chown(buf, dp->uid, dp->gid);
        chmod(buf, dp->perm);
        if (sehandle) {
            secontext = NULL;
            selabel_lookup(sehandle, &secontext, buf, 0);
            if (secontext) {
                setfilecon(buf, secontext);
                freecon(secontext);
           }
        }
    }
}

static mode_t get_device_perm(const char *path, unsigned *uid, unsigned *gid)
{
    mode_t perm;
    struct listnode *node;
    struct perm_node *perm_node;
    struct perms_ *dp;

    /* search the perms list in reverse so that ueventd.$hardware can
     * override ueventd.rc
     */
    list_for_each_reverse(node, &dev_perms) {
        perm_node = node_to_item(node, struct perm_node, plist);
        dp = &perm_node->dp;

        if (dp->prefix) {
            if (strncmp(path, dp->name, strlen(dp->name)))
                continue;
        } else {
            if (strcmp(path, dp->name))
                continue;
        }
        *uid = dp->uid;
        *gid = dp->gid;
        return dp->perm;
    }
    /* Default if nothing found. */
    *uid = 0;
    *gid = 0;
    return 0600;
}

static void make_device(struct uevent *uevent,
                        const char *path,
                        int block)
{
    int major = uevent->major;
    int minor = uevent->minor;
    unsigned uid;
    unsigned gid;
    mode_t mode;
    dev_t dev;
    char *secontext = NULL;
    char *dev_name = NULL;

    mode = get_device_perm(path, &uid, &gid) | (block ? S_IFBLK : S_IFCHR);

    /* Check if dev name must be updated */
    dev_name = get_dev_name(path, uevent);

    if (sehandle) {
        selabel_lookup(sehandle, &secontext, dev_name, mode);
        setfscreatecon(secontext);
    }

    dev = makedev(major, minor);
    /* Temporarily change egid to avoid race condition setting the gid of the
     * device node. Unforunately changing the euid would prevent creation of
     * some device nodes, so the uid has to be set with chown() and is still
     * racy. Fixing the gid race at least fixed the issue with system_server
     * opening dynamic input devices under the AID_INPUT gid. */
    setegid(gid);

    mknod(dev_name, mode, dev);
    chown(dev_name, uid, -1);

    setegid(AID_ROOT);

    if (secontext) {
        freecon(secontext);
        setfscreatecon(NULL);
    }
}

static void add_platform_device(const char *path)
{
    int path_len = strlen(path);
    struct listnode *node;
    struct platform_node *bus;
    const char *name = path;

    if (!strncmp(path, "/devices/", 9)) {
        name += 9;
        if (!strncmp(name, "platform/", 9))
            name += 9;
    }

    list_for_each_reverse(node, &platform_names) {
        bus = node_to_item(node, struct platform_node, list);
        if ((bus->path_len < path_len) &&
                (path[bus->path_len] == '/') &&
                !strncmp(path, bus->path, bus->path_len))
            /* subdevice of an existing platform, ignore it */
            return;
    }

    INFO("adding platform device %s (%s)\n", name, path);

    bus = calloc(1, sizeof(struct platform_node));
    bus->path = strdup(path);
    bus->path_len = path_len;
    bus->name = bus->path + (name - path);
    list_add_tail(&platform_names, &bus->list);
}

/*
 * given a path that may start with a platform device, find the length of the
 * platform device prefix.  If it doesn't start with a platform device, return
 * 0.
 */
static struct platform_node *find_platform_device(const char *path)
{
    int path_len = strlen(path);
    struct listnode *node;
    struct platform_node *bus;

    list_for_each_reverse(node, &platform_names) {
        bus = node_to_item(node, struct platform_node, list);
        if ((bus->path_len < path_len) &&
                (path[bus->path_len] == '/') &&
                !strncmp(path, bus->path, bus->path_len))
            return bus;
    }

    return NULL;
}

static void remove_platform_device(const char *path)
{
    struct listnode *node;
    struct platform_node *bus;

    list_for_each_reverse(node, &platform_names) {
        bus = node_to_item(node, struct platform_node, list);
        if (!strcmp(path, bus->path)) {
            INFO("removing platform device %s\n", bus->name);
            free(bus->path);
            list_remove(node);
            free(bus);
            return;
        }
    }
}

#if LOG_UEVENTS

static inline suseconds_t get_usecs(void)
{
    struct timeval tv;
    gettimeofday(&tv, 0);
    return tv.tv_sec * (suseconds_t) 1000000 + tv.tv_usec;
}

#define log_event_print(x...) INFO(x)

#else

#define log_event_print(fmt, args...)   do { } while (0)
#define get_usecs()                     0

#endif

static void parse_event(const char *msg, struct uevent *uevent)
{
    uevent->action = "";
    uevent->path = "";
    uevent->subsystem = "";
    uevent->firmware = "";
    uevent->major = -1;
    uevent->minor = -1;
    uevent->partition_name = NULL;
    uevent->partition_num = -1;
    uevent->device_name = NULL;

        /* currently ignoring SEQNUM */
    while(*msg) {
        if(!strncmp(msg, "ACTION=", 7)) {
            msg += 7;
            uevent->action = msg;
        } else if(!strncmp(msg, "DEVPATH=", 8)) {
            msg += 8;
            uevent->path = msg;
        } else if(!strncmp(msg, "SUBSYSTEM=", 10)) {
            msg += 10;
            uevent->subsystem = msg;
        } else if(!strncmp(msg, "FIRMWARE=", 9)) {
            msg += 9;
            uevent->firmware = msg;
        } else if(!strncmp(msg, "MAJOR=", 6)) {
            msg += 6;
            uevent->major = atoi(msg);
        } else if(!strncmp(msg, "MINOR=", 6)) {
            msg += 6;
            uevent->minor = atoi(msg);
        } else if(!strncmp(msg, "PARTN=", 6)) {
            msg += 6;
            uevent->partition_num = atoi(msg);
        } else if(!strncmp(msg, "PARTNAME=", 9)) {
            msg += 9;
            uevent->partition_name = msg;
        } else if(!strncmp(msg, "DEVNAME=", 8)) {
            msg += 8;
            uevent->device_name = msg;
        }

        /* advance to after the next \0 */
        while(*msg++)
            ;
    }

    log_event_print("event { '%s', '%s', '%s', '%s', %d, %d }\n",
                    uevent->action, uevent->path, uevent->subsystem,
                    uevent->firmware, uevent->major, uevent->minor);
}

static char **get_character_device_symlinks(struct uevent *uevent)
{
    const char *parent;
    char *slash;
    char **links;
    int link_num = 0;
    int width;
    struct platform_node *pdev;

    pdev = find_platform_device(uevent->path);
    if (!pdev)
        return NULL;

    links = malloc(sizeof(char *) * 2);
    if (!links)
        return NULL;
    memset(links, 0, sizeof(char *) * 2);

    /* skip "/devices/platform/<driver>" */
    parent = strchr(uevent->path + pdev->path_len, '/');
    if (!*parent)
        goto err;

    if (!strncmp(parent, "/usb", 4)) {
        /* skip root hub name and device. use device interface */
        while (*++parent && *parent != '/');
        if (*parent)
            while (*++parent && *parent != '/');
        if (!*parent)
            goto err;
        slash = strchr(++parent, '/');
        if (!slash)
            goto err;
        width = slash - parent;
        if (width <= 0)
            goto err;

        if (asprintf(&links[link_num], "/dev/usb/%s%.*s", uevent->subsystem, width, parent) > 0)
            link_num++;
        else
            links[link_num] = NULL;
        mkdir("/dev/usb", 0755);
    }
    else {
        goto err;
    }

    return links;
err:
    free(links);
    return NULL;
}

static char **parse_platform_block_device(struct uevent *uevent)
{
    const char *device;
    struct platform_node *pdev;
    char *slash;
    int width;
    char buf[256];
    char link_path[256];
    int fd;
    int link_num = 0;
    int ret;
    char *p;
    unsigned int size;
    struct stat info;

    pdev = find_platform_device(uevent->path);
    if (!pdev)
        return NULL;
    device = pdev->name;

    char **links = malloc(sizeof(char *) * 4);
    if (!links)
        return NULL;
    memset(links, 0, sizeof(char *) * 4);

    INFO("found platform device %s\n", device);

    snprintf(link_path, sizeof(link_path), "/dev/block/platform/%s", device);

    if (uevent->partition_name) {
        p = strdup(uevent->partition_name);
        sanitize(p);
        if (strcmp(uevent->partition_name, p))
            NOTICE("Linking partition '%s' as '%s'\n", uevent->partition_name, p);
        if (asprintf(&links[link_num], "%s/by-name/%s", link_path, p) > 0)
            link_num++;
        else
            links[link_num] = NULL;
        free(p);
    }

    if (uevent->partition_num >= 0) {
        if (asprintf(&links[link_num], "%s/by-num/p%d", link_path, uevent->partition_num) > 0)
            link_num++;
        else
            links[link_num] = NULL;
    }

    slash = strrchr(uevent->path, '/');
    if (asprintf(&links[link_num], "%s/%s", link_path, slash + 1) > 0)
        link_num++;
    else
        links[link_num] = NULL;

    return links;
}

static void handle_device(struct uevent *uevent,
                          const char *devpath,
                          int block,
                          char **links)
{
    int i;
    const char *action = uevent->action;

    if(!strcmp(action, "add")) {
        make_device(uevent, devpath, block);
        if (links) {
            for (i = 0; links[i]; i++)
                make_link(devpath, links[i]);
        }
    }

    if(!strcmp(action, "remove")) {
        if (links) {
            for (i = 0; links[i]; i++)
                remove_link(devpath, links[i]);
        }
        unlink(devpath);
    }

    if (links) {
        for (i = 0; links[i]; i++)
            free(links[i]);
        free(links);
    }
}

static void handle_platform_device_event(struct uevent *uevent)
{
    const char *path = uevent->path;

    if (!strcmp(uevent->action, "add"))
        add_platform_device(path);
    else if (!strcmp(uevent->action, "remove"))
        remove_platform_device(path);
}

static const char *parse_device_name(struct uevent *uevent, unsigned int len)
{
    const char *name;

    /* if it's not a /dev device, nothing else to do */
    if((uevent->major < 0) || (uevent->minor < 0))
        return NULL;

    /* do we have a name? */
    name = strrchr(uevent->path, '/');
    if(!name)
        return NULL;
    name++;

    /* too-long names would overrun our buffer */
    if(strlen(name) > len)
        return NULL;

    return name;
}

static void handle_block_device_event(struct uevent *uevent)
{
    const char *base = "/dev/block/";
    const char *name;
    char devpath[96];
    char **links = NULL;

    name = parse_device_name(uevent, 64);
    if (!name)
        return;

    snprintf(devpath, sizeof(devpath), "%s%s", base, name);
    make_dir(base, 0755);

    if (!strncmp(uevent->path, "/devices/", 9))
        links = parse_platform_block_device(uevent);

    handle_device(uevent, devpath, 1, links);
}

static void handle_generic_device_event(struct uevent *uevent)
{
    char *base;
    const char *name;
    char devpath[96] = {0};
    char **links = NULL;

    name = parse_device_name(uevent, 64);
    if (!name)
        return;

    if (!strncmp(uevent->subsystem, "usb", 3)) {
         if (!strcmp(uevent->subsystem, "usb")) {
            if (uevent->device_name) {
                /*
                 * create device node provided by kernel if present
                 * see drivers/base/core.c
                 */
                char *p = devpath;
                snprintf(devpath, sizeof(devpath), "/dev/%s", uevent->device_name);
                /* skip leading /dev/ */
                p += 5;
                /* build directories */
                while (*p) {
                    if (*p == '/') {
                        *p = 0;
                        make_dir(devpath, 0755);
                        *p = '/';
                    }
                    p++;
                }
             }
             else {
                 /* This imitates the file system that would be created
                  * if we were using devfs instead.
                  * Minors are broken up into groups of 128, starting at "001"
                  */
                 int bus_id = uevent->minor / 128 + 1;
                 int device_id = uevent->minor % 128 + 1;
                 /* build directories */
                 make_dir("/dev/bus", 0755);
                 make_dir("/dev/bus/usb", 0755);
                 snprintf(devpath, sizeof(devpath), "/dev/bus/usb/%03d", bus_id);
                 make_dir(devpath, 0755);
                 snprintf(devpath, sizeof(devpath), "/dev/bus/usb/%03d/%03d", bus_id, device_id);
             }
         } else {
             /* ignore other USB events */
             return;
         }
     } else if (!strncmp(uevent->subsystem, "graphics", 8)) {
         base = "/dev/graphics/";
         make_dir(base, 0755);
     } else if (!strncmp(uevent->subsystem, "drm", 3)) {
         base = "/dev/dri/";
         make_dir(base, 0755);
     } else if (!strncmp(uevent->subsystem, "oncrpc", 6)) {
         base = "/dev/oncrpc/";
         make_dir(base, 0755);
     } else if (!strncmp(uevent->subsystem, "adsp", 4)) {
         base = "/dev/adsp/";
         make_dir(base, 0755);
     } else if (!strncmp(uevent->subsystem, "msm_camera", 10)) {
         base = "/dev/msm_camera/";
         make_dir(base, 0755);
     } else if(!strncmp(uevent->subsystem, "input", 5)) {
         base = "/dev/input/";
         make_dir(base, 0755);
     } else if(!strncmp(uevent->subsystem, "mtd", 3)) {
         base = "/dev/mtd/";
         make_dir(base, 0755);
     } else if(!strncmp(uevent->subsystem, "sound", 5)) {
         base = "/dev/snd/";
         make_dir(base, 0755);
     } else if(!strncmp(uevent->subsystem, "misc", 4) &&
                 !strncmp(name, "log_", 4)) {
         base = "/dev/log/";
         make_dir(base, 0755);
         name += 4;
     } else
         base = "/dev/";
     links = get_character_device_symlinks(uevent);

     if (!devpath[0])
         snprintf(devpath, sizeof(devpath), "%s%s", base, name);

     handle_device(uevent, devpath, 0, links);
}

static void handle_device_event(struct uevent *uevent)
{
    if (!strcmp(uevent->action,"add") || !strcmp(uevent->action, "change"))
        fixup_sys_perms(uevent->path);

    if (!strncmp(uevent->subsystem, "block", 5)) {
        handle_block_device_event(uevent);
    } else if (!strncmp(uevent->subsystem, "platform", 8)) {
        handle_platform_device_event(uevent);
    } else {
        handle_generic_device_event(uevent);
    }
}

static void handle_inet_event(struct uevent *uevent)
{
    char *inet_name = NULL;
    char *name = NULL;
    struct ifreq ifr;
    int fd;
    int err=0;

    if (!uevent) {
        ERROR("%s:ERROR Uevent is NULL", __func__);
        return;
    }

    if(!strncmp(uevent->subsystem, "net", 3))
    {
        NOTICE("%s: FOUND NET SUBSYSTEM, Path:%s",
               __func__, uevent->path);
        NOTICE("%s: FOUND NET SUBSYSTEM, Action:%s",
               __func__, uevent->action);
        NOTICE("%s: FOUND NET SUBSYSTEM, Major:%d, Minor:%d",
               __func__, uevent->major, uevent->minor);

        if (!strcmp(uevent->action,"add")) {
            /* do we have a name? */
            name = strrchr(uevent->path, '/');
            if(!name) {
                ERROR("%s:ERROR NO INET NAME.", __func__);
                return;
            }
            name++;

            /* Check if inet name must be updated */
            inet_name = get_inet_name(name, uevent);
            if (inet_name) {
                /* Rename Net Interface */
                NOTICE("%s:Renaming %s net interface with new name:%s",
                       __func__, name, inet_name);
                if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
                    ERROR("%s:ERROR socket(PF_INET, SOCK_DGRAM, 0)",
                          __func__);
                    return;
                }

                strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
                strncpy(ifr.ifr_newname, inet_name, sizeof(ifr.ifr_newname));
                NOTICE("%s:Calling IOTCL SIOCSIFNAME, %s ==> %s",
                       __func__, ifr.ifr_name, ifr.ifr_newname);
                if ((err = ioctl(fd, SIOCSIFNAME, &ifr))==-1) {
                    ERROR("%s:ERROR ioctl(SIOCSIFNAME), err:0x%X",
                          __func__, errno);
                    return;
                }
                NOTICE("%s:RENAMING SUCCESS !", __func__);
            } else {
                ERROR("%s:No Renaming for %s net interface",
                      __func__, name);
            }
        }
    }
}

static int load_firmware(int fw_fd, int loading_fd, int data_fd)
{
    struct stat st;
    long len_to_copy;
    int ret = 0;

    if(fstat(fw_fd, &st) < 0)
        return -1;
    len_to_copy = st.st_size;

    write(loading_fd, "1", 1);  /* start transfer */

    while (len_to_copy > 0) {
        char buf[PAGE_SIZE];
        ssize_t nr;

        nr = read(fw_fd, buf, sizeof(buf));
        if(!nr)
            break;
        if(nr < 0) {
            ret = -1;
            break;
        }

        len_to_copy -= nr;
        while (nr > 0) {
            ssize_t nw = 0;

            nw = write(data_fd, buf + nw, nr);
            if(nw <= 0) {
                ret = -1;
                goto out;
            }
            nr -= nw;
        }
    }

out:
    if(!ret)
        write(loading_fd, "0", 1);  /* successful end of transfer */
    else
        write(loading_fd, "-1", 2); /* abort transfer */

    return ret;
}

static int is_booting(void)
{
    return access("/dev/.booting", F_OK) == 0;
}

static void process_firmware_event(struct uevent *uevent)
{
    char *root, *loading, *data, *file1 = NULL, *file2 = NULL, *file3 = NULL;
    int l, loading_fd, data_fd, fw_fd;
    int booting = is_booting();

    INFO("firmware: loading '%s' for '%s'\n",
         uevent->firmware, uevent->path);

    l = asprintf(&root, SYSFS_PREFIX"%s/", uevent->path);
    if (l == -1)
        return;

    l = asprintf(&loading, "%sloading", root);
    if (l == -1)
        goto root_free_out;

    l = asprintf(&data, "%sdata", root);
    if (l == -1)
        goto loading_free_out;

    l = asprintf(&file1, FIRMWARE_DIR1"/%s", uevent->firmware);
    if (l == -1)
        goto data_free_out;

    l = asprintf(&file2, FIRMWARE_DIR2"/%s", uevent->firmware);
    if (l == -1)
        goto data_free_out;

    l = asprintf(&file3, FIRMWARE_DIR3"/%s", uevent->firmware);
    if (l == -1)
        goto data_free_out;

    loading_fd = open(loading, O_WRONLY);
    if(loading_fd < 0)
        goto file_free_out;

    data_fd = open(data, O_WRONLY);
    if(data_fd < 0)
        goto loading_close_out;

try_loading_again:
    fw_fd = open(file1, O_RDONLY);
    if(fw_fd < 0) {
        fw_fd = open(file2, O_RDONLY);
        if (fw_fd < 0) {
            fw_fd = open(file3, O_RDONLY);
            if (fw_fd < 0) {
                if (booting) {
                        /* If we're not fully booted, we may be missing
                         * filesystems needed for firmware, wait and retry.
                         */
                    usleep(100000);
                    booting = is_booting();
                    goto try_loading_again;
                }
                INFO("firmware: could not open '%s' %d\n", uevent->firmware, errno);
                write(loading_fd, "-1", 2);
                goto data_close_out;
            }
        }
    }

    if(!load_firmware(fw_fd, loading_fd, data_fd))
        INFO("firmware: copy success { '%s', '%s' }\n", root, uevent->firmware);
    else
        INFO("firmware: copy failure { '%s', '%s' }\n", root, uevent->firmware);

    close(fw_fd);
data_close_out:
    close(data_fd);
loading_close_out:
    close(loading_fd);
file_free_out:
    free(file1);
    free(file2);
    free(file3);
data_free_out:
    free(data);
loading_free_out:
    free(loading);
root_free_out:
    free(root);
}

static void handle_firmware_event(struct uevent *uevent)
{
    pid_t pid;
    int ret;

    handle_inet_event(uevent);

    if(strcmp(uevent->subsystem, "firmware"))
        return;

    if(strcmp(uevent->action, "add"))
        return;

    /* we fork, to avoid making large memory allocations in init proper */
    pid = fork();
    if (!pid) {
        process_firmware_event(uevent);
        exit(EXIT_SUCCESS);
    }
}

#define UEVENT_MSG_LEN  1024
void handle_device_fd()
{
    char msg[UEVENT_MSG_LEN+2];
    int n;
    while ((n = uevent_kernel_multicast_recv(device_fd, msg, UEVENT_MSG_LEN)) > 0) {
        if(n >= UEVENT_MSG_LEN)   /* overflow -- discard */
            continue;

        msg[n] = '\0';
        msg[n+1] = '\0';

        struct uevent uevent;
        parse_event(msg, &uevent);

        if (sehandle && selinux_status_updated() > 0) {
            struct selabel_handle *sehandle2;
            sehandle2 = selinux_android_file_context_handle();
            if (sehandle2) {
                selabel_close(sehandle);
                sehandle = sehandle2;
            }
        }

        handle_device_event(&uevent);
        handle_firmware_event(&uevent);
    }
}

/* Coldboot walks parts of the /sys tree and pokes the uevent files
** to cause the kernel to regenerate device add events that happened
** before init's device manager was started
**
** We drain any pending events from the netlink socket every time
** we poke another uevent file to make sure we don't overrun the
** socket's buffer.  
*/

static void do_coldboot(DIR *d)
{
    struct dirent *de;
    int dfd, fd;

    dfd = dirfd(d);

    fd = openat(dfd, "uevent", O_WRONLY);
    if(fd >= 0) {
        write(fd, "add\n", 4);
        close(fd);
        handle_device_fd();
    }

    while((de = readdir(d))) {
        DIR *d2;

        if(de->d_type != DT_DIR || de->d_name[0] == '.')
            continue;

        fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY);
        if(fd < 0)
            continue;

        d2 = fdopendir(fd);
        if(d2 == 0)
            close(fd);
        else {
            do_coldboot(d2);
            closedir(d2);
        }
    }
}

static void coldboot(const char *path)
{
    DIR *d = opendir(path);
    if(d) {
        do_coldboot(d);
        closedir(d);
    }
}

void device_init(void)
{
    suseconds_t t0, t1;
    struct stat info;
    int fd;

    sehandle = NULL;
    if (is_selinux_enabled() > 0) {
        sehandle = selinux_android_file_context_handle();
        selinux_status_open(true);
    }

    /* is 256K enough? udev uses 16MB! */
    device_fd = uevent_open_socket(256*1024, true);
    if(device_fd < 0)
        return;

    fcntl(device_fd, F_SETFD, FD_CLOEXEC);
    fcntl(device_fd, F_SETFL, O_NONBLOCK);

    if (stat(coldboot_done, &info) < 0) {
        t0 = get_usecs();
        coldboot("/sys/class");
        coldboot("/sys/block");
        coldboot("/sys/devices");
        t1 = get_usecs();
        fd = open(coldboot_done, O_WRONLY|O_CREAT, 0000);
        close(fd);
        log_event_print("coldboot %ld uS\n", ((long) (t1 - t0)));
    } else {
        log_event_print("skipping coldboot, already done\n");
    }
}

int get_device_fd()
{
    return device_fd;
}
