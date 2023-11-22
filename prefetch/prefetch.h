#ifndef PREFETCH_H
#define  PREFETCH_H

int prefetch_replay(
    const char* path,
    const uint16_t* io_depth,
    const uint16_t* max_fds,
    int8_t exit_on_error,
    const char* config_path,
);


int prefetch_record(
    const char* path,
    int8_t debug,
    const uint16_t duration,
    const uint64_t* trace_buffer_size,
    const char* tracing_subsystem,
    int8_t setup_tracing,
    const char* tracing_instance
);
#endif
