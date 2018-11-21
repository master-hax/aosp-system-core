Android Overlayfs integration with adb remount
==============================================

Introduction
------------

Users working with userdebug or eng builds expect to be able to
remount the system partition as read-write and then add or modify
any number of files without reflashing the system image, which is
understandably efficient for a development cycle.
Limited memory systems that chose to use readonly filesystems like
*squashfs*, or *Logical Resizable Android Partitions* which land
system partition images right-sized, and with filesystem that have
been deduped on the block level to compress the content; means that
either a remount is not possible directly, or when done offers
little or no utility because of remaingin space limitations or
support logistics.

*Overlayfs* comes to the rescue for these debug scenarios, and can be
applied as a workaround on any system by merely providing a writable
filesystem as an upper reference, and mount overtop the lower in one
mount command action. These actions are performed automatically in
the **adb disable-verity** and **adb remount** requests.

Operations
----------

### Cookbook

The typical action to utilize the remount facility is:

    $ adb root
    $ adb disable-verity
    $ adb reboot
    $ adb wait-for-device
    $ adb root
    $ adb remount

Followed by one of the following:

    $ adb sync
    $ adb reboot

*or*

    $ adb push <source> <destination
    $ adb reboot

This does not change when *overlayfs* needs to be engaged.
The decisions whether to use traditional direct filesystem remount,
or one wrapped by *overlayfs* is automatically determined based on
a probe of the filesystem types and space remaining.

### Backing Storage

When *overlayfs* logic is feasible, it will use either the
**/cache/overlay/** directory for non-A/B devices, or the
**/mnt/scratch/overlay** directory for A/B devices that have
access to *Logical Resizeable Android Partitions*.
The backing store is used as soon as possible in the boot
process and can occur at first stage init, or at the
mount_all init rc commands.

This early as possible attachment of *overlayfs* means that
*sepolicy* or *init* itself can also be pushed and used after
the exec phases that accompany each stage.

Architectural Concerns
----------------------

- Space used in the backing storage is on a file by file basis
  and will require more space than if updated in place.
- Kernel must have CONFIG_OVERLAY_FS=y and will need to be patched
  with "*overlayfs: override_creds=off option bypass creator_cred*"
  if higher than 4.6.
- *adb enable-verity* will free up overlayfs and as a bonus the
  device will be reverted pristine to before any content was updated.
- There are other caveats too numerous to mention, discarded complex
  logic to solve.  File a bug if a use case needs to be covered.
