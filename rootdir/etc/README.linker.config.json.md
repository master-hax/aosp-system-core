# Comments for linker.config.json
Format of linker.config.json can be found from https://android.googlesource.com/platform/system/linkerconfig/+/refs/heads/master/README.md#linker_config_json

## provideLibs
Libraries which has stub interface and installed in the system image so other partition and APEX modules can link to.
TODO(b/147210213) : Generate list of libraries during build and append to linker config file.

## requireLibs
Libraries which are referenced from libraries / executables in the system image.

| Library name | Comment |
| ------------ | -------- |
| libpac.so | TODO(b/136184504) : Remove once migrated to WebView |
| libicui18n.so, libicuuc.so | TODO(b/120786417 or b/134659294) : Kept for app compat |
| libnetd_resolv.so | Library from resolv APEX |
| libneuralnetworks.so | Library from nn APEX |
| libstatspull.so, libstatssocket.so | Libraries from statsd APEX |
| libadb_pairing_auth.so, libadb_pairing_connection.so, libadb_pairing_server.so | Libraries from adbd APEX |