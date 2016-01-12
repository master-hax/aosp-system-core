# crash_reporter

`crash_reporter` is a deamon running on the device that saves the call stack of
crashing programs. It makes use of the
[Breakpad](https://bugs.chromium.org/p/google-breakpad/) library.

During a build, Breakpad symbol files are generated for all binaries.  They are
packaged into a zip file when running `m dist`, so that a developer can upload
them to the crash server.

On a device, if the user has opted in to metrics and crash reporting, a
Breakpad minidump is generated when an executable crashes, which is then
uploaded to the crash server.

On the crash server, it compares the minidump's signature to the symbol files
that the developer has uploaded, and extracts and symbolizes the stack trace
from the minidump.

## SELinux policies

In order to correctly generate a minidump, `crash_reporter` needs to be given
the proper SELinux permissions for accessing the domain of the crashing
executable.  By default, `crash_reporter` has only been given access to a select
number of system domains, such as `metricsd`, `weave`, and `update_engine`.  If
a developer wants their executable's crashes to be caught by `crash_reporter`,
they will have to set their SELinux policies in their .te file to allow
`crash_reporter` access to their domain.  This can be done through a simple
[macro](https://android.googlesource.com/device/generic/brillo/+/master/sepolicy/te_macros):

    allow_crash_reporter(domain_name)

Replace *domain_name* with whatever domain is assigned to the executable in
the `file_contexts` file.

## Configuration

`crash_reporter` has a few different configuration options that have to be set.

- Crashes are only handled and uploaded if analytics reporting is enabled,
  either via weave call to set `_metrics.enableAnalyticsReporting` or by
  manually creating the file `/data/misc/metrics/enabled` (for testing only).
- The `BRILLO_CRASH_SERVER` make variable should be set in the `product.mk`
  file to the URL of the crash server.  For Brillo builds, it is set
  automatically through the product configuration.  Setting this variable will
  populate the `/etc/os-release.d/crash_server` file on the device, which is
  read by `crash_sender`.
- The `BRILLO_PRODUCT_ID` make variable should be set in the `product.mk` file
  to the product's ID.  For Brillo builds, it is set automatically through the
  product configuration.  Setting this variable will populate the
  `/etc/os-release.d/product_id`, which is read by `crash_sender`.

## Using `crash_reporter` during development

While `crash_reporter` is mostly intended to be used in production with `gdb`
being the preferred debugging method during development, it is possible to use
`crash_reporter` during development with a slight change in workflow.

### Execution context

The most common issue that a developer's flow may encounter, is with how the
program is executed.  If a developer is building their code in an *eng* or
*userdebug* image, syncing it to their device, then opening an ADB shell and
running their binary through the command line, they will encounter SELinux
denials when `crash_reporter` runs and tries to generate a minidump for the
crashing executable.  This occurs because in order to sync code to a device,
ADB has to be run as root.  Any subsequent shells will be running as the `su`
domain, so any executable run directly from a command line will use a `su`
SELinux domain source context.  The `su` domain however only exists on *eng*
and *userdebug* images.  *User* builds do not contain the `su` user, and thus
there are no SELinux rules set up to allow access to that domain.

In order to overcome this issue, it is suggested to create a .rc file for the
executable that defines an init target service for starting the executable,
then starting that service to run the test.  For example, if testing
`sample_app`, the following `sample_app.rc` file could be used:

    service sample_app /system/bin/sample_app
        class late_start
        oneshot
        disabled
        seclabel u:r:sample_app_domain:s0
        user system
        group system

This simple .rc file creates a service called *sample_app* that will call the
`sample_app` executable.  The `disabled` flag means it will not start
automatically at boot, `oneshot` means it won't restart itself when it crashes
or exits, the `seclabel` runs it in the `sample_app_domain` SELinux context,
and the `user` and `group` is set to run the service as the `system` user.
With this .rc file loaded (the device has to be rebooted any time this file is
changed in order to pick up the changes during init's boot up), `sample_app`
can then be started simply through `start sample_app`.

The above .rc file method is the preferred way to start an executable during
development, as it mirrors how it will most likely be run during production,
including the SELinux policies as well as the user and group permissions.  If,
however, the executable has a lot of different command line argument
combinations that need to be tested, this method may not be optimal due to
having to reboot to pick up changes to the .rc file.  In this case, the
following SELinux rules can be temporarily added to the `sample_app.te` policy
file:

    allow crash_reporter su:dir { search };
    allow crash_reporter su:lnk_file { read };
    allow crash_reporter su:file { open read };
    allow crash_reporter su:file { getattr };

This provides the necessary policies to allow `crash_reporter` to collect
crashes from the `su` domain, so the executable can be run directly from an
ADB shell.  As previously mentioned, however, the source SELinux context as
well as the user and group of the executable will be different from what is run
in production, and the above policy rules also will not compile when building
a *user* production image.

### Uploading crash reports in eng builds

By default, crash reports are only uploaded to the server for production
*user* and *userdebug* images.  In *eng* builds, with crash reporting enabled
the device will generate minidumps for any crashing executables but will not
send them to the crash server.  If a developer does want to send a crash report
to the server from an *eng* build, they can do so through issuing the command
`SECONDS_SEND_SPREAD=5 FORCE_OFFICIAL=1 crash_sender` from an ADB shell.  This
will send the report to the server, with the *image_type* field set to
*force-official* so that these reports can be differentiated from normal
reports.
