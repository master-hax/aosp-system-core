# liblog -> logd

The data that liblog sends to logd is represented below.

    struct {
        android_log_header_t header;
        union {
           struct {
                char     prio;
                char     tag[...];
                char     message[...];
            } string;
            struct {
                android_event_header_t event_header;
                android_event_*_t      payload[...];
            } binary;
        };
    };

The payload, excluding the header, has a max size of LOGGER_ENTRY_MAX_PAYLOAD.

## header

The header is added immediately before sending the log message to logd.  It is represented below.

    typedef struct __attribute__((__packed__)) {
        uint8_t version : 3;
        uint8_t id : 5;
        uint16_t tid;
        log_time realtime;
    } android_log_header_t;

Note the `version` field, which was added in Android-R is intended to be set to 0 for the current
version.  For backwards compatibility, this version field should be bumped and additional items in
the new log message must be appended at the end of the existing data.

## `string` payload

The `string` part of the union is for normal buffers (main, system, radio, etc) and consists of a
single character priority, followed by a variable length null terminated string for the tag, and
finally a variable length null terminated string for the message.

This payload is used for the `__android_log_buf_write()` family of functions.

## `binary` payload

The `binary` part of the union is for binary buffers (events, security, etc) and consists of an
android_event_header_t struct followed by a variable number of android_event_*_t
(android_event_list_t, android_event_int_t, etc) structs.

If multiple android_event_*_t elements are present, then they must be in a list and the first
element in payload must be an android_event_list_t.

This payload is used for the `__android_log_bwrite()` family of functions. It is additionally used
for `android_log_write_list()` and the related functions that manipulate event lists.

# logd -> liblog

logd sends a `logger_entry` struct to liblog followed by the payload. The payload is identical to
the payloads defined above. The max size of the entire message from logd is LOGGER_ENTRY_MAX_LEN.
