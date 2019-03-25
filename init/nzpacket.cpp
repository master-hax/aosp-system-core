#include "nzpacket.h"

namespace android {
namespace init {

void CopyStr(char **dest, size_t *remaining, const std::string& from, size_t length = 0) {
    if (length == 0) {
        length = from.length();
    }
    memcpy(*dest, from.c_str(), length);
    *dest += length;
    **dest = '\0';
    *dest += 1;
    *remaining -= length + 1;
}

template <class T>
void WriteInt(char **dest, size_t *remaining, T value) {
    memcpy(*dest, &value, sizeof(value));
    *dest += sizeof(value);
    *remaining -= sizeof(value);
}

void WriteBool(char **dest, size_t *remaining, bool value) {
  WriteInt<short>(dest, remaining, value ? 1 : 0);
}

bool MarkSectionEnd(char **dest, size_t *remaining) {
    if (!*remaining) return false;
    **dest = '\0';
    ++*dest;
    --*remaining;
    return true;
}

bool NzPacket::Serialize(char *buf) {
    size_t length = NZPACKET_SERIALIZED_SIZE;
    char *ptr = buf;

    CopyStr(&ptr, &length, name, 0);

    // Cmdline args
    for (auto const &arg : args) {
        const size_t length_to_copy = std::min(length - 1, arg.length());
        CopyStr(&ptr, &length, arg, length_to_copy);
    }
    if (!MarkSectionEnd(&ptr, &length)) {
        return false;
    }

    // Descriptors
    for (auto const *dinfo : descriptors) {
        if (dinfo->key() == "ANDROID_SOCKET_") {
            *ptr++ = 'S';
        } else {
            // File
            *ptr++ = 'F';
        }
        --length;
        CopyStr(&ptr, &length, dinfo->name_);
        CopyStr(&ptr, &length, dinfo->type_);
        WriteInt(&ptr, &length, static_cast<int>(dinfo->uid_));
        WriteInt(&ptr, &length, static_cast<int>(dinfo->gid_));
        WriteInt(&ptr, &length, static_cast<int>(dinfo->perm_));
        CopyStr(&ptr, &length, dinfo->context_);
    }
    if (!MarkSectionEnd(&ptr, &length)) {
        return false;
    }

    // Writepid Files
    for (auto const &filename : writepid_files) {
        const size_t length_to_copy = std::min(length - 1, filename.length());
        CopyStr(&ptr, &length, filename, length_to_copy);
    }
    if (!MarkSectionEnd(&ptr, &length)) {
        return false;
    }

    // IO Priority
    WriteInt(&ptr, &length, static_cast<int>(ioprio_class));
    WriteInt(&ptr, &length, ioprio_pri);

    // Priority
    WriteInt(&ptr, &length, priority);

    // UID/GIDs
    static_assert(sizeof(uid_t) == sizeof(int), "Oops");
    static_assert(sizeof(gid_t) == sizeof(int), "Oops");
    WriteInt(&ptr, &length, static_cast<int>(uid));
    WriteInt(&ptr, &length, static_cast<int>(gid));
    WriteInt(&ptr, &length, static_cast<int>(supp_gids.size()));
    for (const gid_t g : supp_gids) {
      WriteInt(&ptr, &length, static_cast<int>(g));
    }

    // Security Context
    CopyStr(&ptr, &length, seclabel);
    CopyStr(&ptr, &length, scon);

    // Cap set
    WriteBool(&ptr, &length, has_cap_set);
    WriteInt(&ptr, &length, cap_set);
    WriteInt(&ptr, &length, cap_set_size);

    // Resource limits
    WriteInt(&ptr, &length, rlimits.size());
    for (auto const &r : rlimits) {
      WriteInt(&ptr, &length, r.first);
      WriteInt(&ptr, &length, r.second.rlim_cur);
      WriteInt(&ptr, &length, r.second.rlim_max);
    }

    return true;
}

std::string ParseString(const char **ptr) {
    std::string ret(*ptr);
    *ptr += strlen(*ptr) + 1;
    return ret;
}

template <class T>
T ParseRaw(const char **ptr) {
  T ret;
  memcpy(&ret, *ptr, sizeof(ret));
  *ptr += sizeof(ret);
  return ret;
}

int ParseInt(const char **ptr) {
    return ParseRaw<int>(ptr);
}

unsigned long long ParseULLong(const char **ptr) {
    return ParseRaw<unsigned long long>(ptr);
}

bool ParseBool(const char **ptr) {
    return bool(ParseRaw<short>(ptr));
}

bool IsSectionEnd(const char **ptr) {
    if (**ptr == '\0') {
        *ptr += 1;
        return true;
    } else {
        return false;
    }
}

bool NzPacket::Deserialize(const char *buf) {
    // TODO: Guard against malformed input.  Really we probably want protobuf.
    const char *ptr = buf;
    args.clear();
    descriptors.clear();

    name = ParseString(&ptr);

    while (!IsSectionEnd(&ptr)) {
        args.push_back(ParseString(&ptr));
    }

    while (!IsSectionEnd(&ptr)) {
        bool is_socket = (*ptr++ == 'S');
        std::string name = ParseString(&ptr);
        std::string type = ParseString(&ptr);
        int uid = ParseInt(&ptr);
        int gid = ParseInt(&ptr);
        int perm  = ParseInt(&ptr);
        std::string context = ParseString(&ptr);
        if (is_socket) {
            descriptors.push_back(new SocketInfo(name, type, uid, gid, perm, context));
        } else {
            descriptors.push_back(new FileInfo(name, type, uid, gid, perm, context));
        }
    }

    while (!IsSectionEnd(&ptr)) {
        writepid_files.push_back(ParseString(&ptr));
    }

    ioprio_class = static_cast<IoSchedClass>(ParseInt(&ptr));
    ioprio_pri = ParseInt(&ptr);

    priority = ParseInt(&ptr);

    uid = static_cast<uid_t>(ParseInt(&ptr));
    gid = static_cast<gid_t>(ParseInt(&ptr));
    for (int x = ParseInt(&ptr); x > 0; --x) {
      supp_gids.push_back(static_cast<gid_t>(ParseInt(&ptr)));
    }

    seclabel = ParseString(&ptr);
    scon = ParseString(&ptr);

    has_cap_set = ParseBool(&ptr);
    cap_set = ParseULLong(&ptr);
    cap_set_size = ParseInt(&ptr);

    int rlimit_size = ParseInt(&ptr);
    while (rlimit_size--) {
      int resource = ParseInt(&ptr);
      rlimit rlim;
      rlim.rlim_cur = ParseRaw<rlim_t>(&ptr);
      rlim.rlim_max = ParseRaw<rlim_t>(&ptr);
      rlimits.push_back(std::make_pair(resource, rlim));
    }

    return true;
}

}  // namespace init
}  // namespace android
