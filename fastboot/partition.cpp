#include <stdio.h>
#include <string.h>
#include <expat.h>
#include <vector>
#include <string>
#include "partition.h"

#ifndef __unused
#define __unused __attribute__((unused))
#endif

#define BUF_SIZE          4096

static int depth;
static int parse_error;
static unsigned lun;
static std::vector<partition_table>* ptv;
static std::vector<partition_entry>* pev;

static int parse_gpt_partition(partition_entry &e, const char **attr)
{
    for (int i = 0; attr[i]; i += 2 ) {
        if (!strcmp(attr[i], "label")) {
            strncpy(e.name, attr[i + 1], sizeof e.name);
        } else if (!strcmp(attr[i], "type")) {
            strncpy(e.type, attr[i + 1], sizeof e.type);
        } else if (!strcmp(attr[i], "guid")) {
            strncpy(e.guid, attr[i + 1], sizeof e.guid);
        } else if (!strcmp(attr[i], "size_in_kb")) {
            e.size = std::strtoul(attr[i + 1], 0, 0) * 1024;
        } else if (!strcmp(attr[i], "bootable") &&
                   !strcmp(attr[i + 1], "true")) {
            e.attr |= GPT_ATTR_BOOTABLE;
        } else if (!strcmp(attr[i], "readonly") &&
                   !strcmp(attr[i + 1], "true")) {
            e.attr |= GPT_ATTR_RO;
        } else if (!strcmp(attr[i], "extend")) {
            e.extend = !strcmp(attr[i + 1], "true");
        }
    }

    // validate attributes
    if (e.name[0] == '\0') {
        fprintf(stderr, "missing label attr\n");
        return -1;
    }

    if (e.type[0] == '\0') {
        fprintf(stderr, "missing type attr\n");
        return -1;
    }

    return 0;
}

static int parse_table(partition_table &pt, const char **attr)
{
    pt.lun = lun++;

    for (int i = 0; attr[i]; i += 2 ) {
        if (!strcmp(attr[i], "lun")) {
            pt.lun = std::strtoul(attr[i + 1], nullptr, 0);
            lun = pt.lun + 1;
        } else if (!strcmp(attr[i], "type")) {
            if (!strcmp(attr[i + 1], "gpt")) {
                pt.type = PT_TYPE_GPT;
            } else {
                fprintf(stderr, "partition table type %s no supported\n",
                        attr[i + 1]);
                pt.type = PT_TYPE_UNKNOWN;
                return -1;
            }
        } else if (!strcmp(attr[i], "disk_guid")) {
            strncpy(pt.disk_guid, attr[i + 1], sizeof(pt.disk_guid));
        }
    }

    // if type was not specified default to GPT
    if (pt.type == 0)
        pt.type = PT_TYPE_GPT;

    return 0;
}

static void start_element(void *data __unused, const char *element,
                          const char **attr)
{
    static int storage;

    depth++;

    // if there is already an error no point continuing
    if (parse_error)
        return;

    if (!strcmp(element, "storage")) {
        if (depth != 1 || storage) {
            parse_error = true;
            return;
        }
        storage = true;
    } else if (!strcmp(element, "volume")) {
        if (depth != 2) {
            parse_error = true;
            return;
        }
        partition_table table = partition_table();
        if (parse_table(table, attr)) {
            parse_error = true;
            return;
        }
        table.magic = FB_PARTITION_MAGIC;
        ptv->push_back(table);
    } else if (!strcmp(element, "partition")) {
        if (depth != 3) {
            parse_error = true;
            return;
        }
        partition_table& table = ptv->back();
        partition_entry e = partition_entry();
        switch (table.type) {
        case PT_TYPE_GPT:
            if (parse_gpt_partition(e, attr)) {
                parse_error = true;
                return;
            }
            break;
        default:
            parse_error = true;
            return;
        }
        pev->push_back(e);
        table.num++;
    }
}

static partition_table **create_pt_message()
{
    unsigned cnum = 0;
    unsigned pi = 0;

    partition_table **pts = new partition_table*[ptv->size() + 1]();

    for (auto t : *ptv) {
        //create pt info + partition entry info as a single chunk of memory
        pts[pi] = static_cast<partition_table *>(malloc(sizeof t +
                        t.num * sizeof(partition_entry)));
        if (pts[pi] == nullptr) {
            fprintf(stderr, "error allocating memory\n");
            goto error;
        }
        // copy partition table info
        memcpy(pts[pi], &t, sizeof t);
        // copy partiton entre data
        memcpy(pts[pi++]->pe, pev->data() + cnum, sizeof (partition_entry) * t.num);
        cnum += t.num;
    }

    return pts;

error:
    while (pi--) {
        free(pts[pi]);
    }
    delete[] pts;
    return nullptr;
}

partition_table **get_partition_table(const std::string fname)
{
    FILE *fp = nullptr;
    XML_Parser parser = XML_ParserCreate(nullptr);
    void *buf;

    fp = fopen(fname.c_str(), "r");
    if (fp == nullptr) {
        fprintf(stderr, "error open file %s\n", fname.c_str());
        return nullptr;
    }

    // end_element function only decrease depth, so make it an anonymous func
    XML_SetElementHandler(parser, start_element,
                          [](void *, const char *) { depth--;});

    // init partition table vector and partition entries vector
    ptv = new std::vector<partition_table>;
    pev = new std::vector<partition_entry>;
    //XML_SetUserData(parser, &data);

    while (!parse_error) {
        buf = XML_GetBuffer(parser, BUF_SIZE);
        int bytes_read = fread(buf, 1, BUF_SIZE, fp);
        XML_ParseBuffer(parser, bytes_read, bytes_read == 0);
        if (bytes_read == 0) break;
    }

    XML_ParserFree(parser);
    fclose(fp);

    if (parse_error) {
        fprintf(stderr,"error parsing file\n");
        return nullptr;
    }


    partition_table **pts = create_pt_message();

    delete ptv;
    delete pev;

    return pts;
}

void free_partition_table(partition_table **pt)
{
    for (auto tmp = pt; *tmp; ++tmp) {
        //free(*tmp); //TODO: check when it should be free
    }

    delete[] pt;
}
