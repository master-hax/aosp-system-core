#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlreader.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "partition.h"

static int fill_gpt_partition_info(struct partition_entry *e,
                                   const xmlNodePtr n)
{
    xmlChar *p;

    p = xmlGetProp(n, (const xmlChar *)"label");
    if (p == nullptr) {
        fprintf(stderr, "missing label attribute\n");
        return -1;
    }
    strncpy(e->name, (char *)p, sizeof e->name);
    xmlFree(p);

    p = xmlGetProp(n, (const xmlChar *)"type");
    if (p == nullptr) {
        fprintf(stderr, "missing type attribute\n");
        return -1;
    }
    strncpy(e->type, (char *)p, sizeof e->type);
    xmlFree(p);

    p = xmlGetProp(n, (const xmlChar *)"guid");
    if (p) {
        strncpy(e->guid, (char *)p, sizeof e->guid);
        xmlFree(p);
    }

    p = xmlGetProp(n, (const xmlChar *)"size_in_kb");
    if (p == nullptr) {
        fprintf(stderr, "missing size_in_kb attribute\n");
        return -1;
    }
    e->size = std::strtoul((char *)p, 0, 0) * 1024;
    xmlFree(p);

    e->attr = 0;
    p = xmlGetProp(n, (const xmlChar *)"bootable");
    if (p && !xmlStrcmp(p, (const xmlChar *)"true"))
        e->attr |= GPT_ATTR_BOOTABLE;
    xmlFree(p);

    p = xmlGetProp(n, (const xmlChar *)"readonly");
    if (p && !xmlStrcmp(p, (const xmlChar *)"true"))
        e->attr |= GPT_ATTR_RO;
    xmlFree(p);

    p = xmlGetProp(n, (const xmlChar *)"extend");
    e->extend = (p && !xmlStrcmp(p, (const xmlChar *)"true"));
    xmlFree(p);

    return 0;
}

static int parse_gpt(struct partition_table *pt, xmlNodePtr n)
{
    unsigned i = 0;
    struct partition_entry *pe;

    pe = pt->pe;

    for (n = n->xmlChildrenNode; n; n = n->next)
        if (!xmlStrcmp(n->name, (const xmlChar *)"partition"))
            if (fill_gpt_partition_info(pe + i++, n))
                return -1;

    pt->num = i;

    return 0;
}

static struct partition_table **parse_partitions(xmlNodePtr n)
{
    int i,l;
    int ret;
    unsigned cnt = xmlChildElementCount(n);
    xmlChar *prop;
    struct partition_table **pts = (struct partition_table **)
                                  calloc(cnt + 1, sizeof pts);

    if (!pts)
        return NULL;

    for (l = 0, i = 0, n = n->xmlChildrenNode; n; n = n->next) {
        struct partition_table *pt;
        unsigned sz = xmlChildElementCount(n);

        if (xmlStrcmp(n->name, (const xmlChar *)"volume"))
            continue;

        pt = static_cast<struct partition_table *>(malloc(sizeof *pt +
                        sz * sizeof (struct partition_entry)));
        if (pt == nullptr)
            goto err;

        prop = xmlGetProp(n, (const xmlChar *)"lun");
        if (prop) {
            l = std::strtoul((char *)prop, NULL, 0);
            xmlFree(prop);
        }
        pt->lun = l++;

        prop = xmlGetProp(n, (const xmlChar *)"disk_guid");
        if (prop) {
            strncpy(pt->disk_guid, (char *)prop, sizeof(pt->disk_guid));
            xmlFree(prop);
        }

        prop = xmlGetProp(n, (const xmlChar *)"type");
        if (prop) {
            if (!strcmp((char *)prop, "gpt")) {
                pt->type = PT_TYPE_GPT;
            } else {
                fprintf(stderr, "partition table type %s no supported\n",
                        prop);
            }
            xmlFree(prop);
        } else {
            // if not type default to GPT
            pt->type = PT_TYPE_GPT;
        }

        switch (pt->type) {
        case PT_TYPE_GPT:
            ret = parse_gpt(pt, n);
            break;
        default:
            goto err;
        }

        if (ret)
            goto err;

        pt->magic = FB_PARTITION_MAGIC;
        pts[i++] = pt;
    }

    return pts;
err:
    free(pts);
    return NULL;
}

struct partition_table **get_partition_table(std::string fname)
{
    xmlDocPtr doc;
    xmlNode *root = NULL;
    partition_table **tables = NULL;

    LIBXML_TEST_VERSION;

    doc = xmlReadFile(fname.c_str(), NULL, 0);
    if (doc == NULL) {
        fprintf(stderr, "Failed to parse %s\n", fname.c_str());
        goto out;
    }

    root = xmlDocGetRootElement(doc);
    if (!root) {
        fprintf(stderr,"xml document is empty\n");
        goto out;
    }

    if (xmlStrcmp(root->name, (const xmlChar *)"storage")) {
        fprintf(stderr, "storage tag not found\n");
        goto out;
    }

    tables = parse_partitions(root);
out:
    xmlFreeDoc(doc);

    return tables;
}

void free_partition_table(struct partition_table **pt)
{
    struct partition_table **tmp;
    for (tmp = pt; *tmp; ++tmp) {
        //free(*tmp); //TODO: check when it should be free
    }
    free(pt);
}
