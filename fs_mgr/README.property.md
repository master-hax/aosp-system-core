File System Manager Library
===========================

Android Properties
------------------

#### ro.debuggable
If 1, indicates that the build is debuggable, enables some library features.

#### ro.adb.remount.overlayfs.maxfree
Only enabled on debug builds, ro.debuggable = 1.
Board Configuration parameter.
Globally affect automation for determining if overlayfs is to be made
available for adb remount.
Enable overlayfs for limited space filesystems, treat them like read-only if
the percentage space remaining is less than this parameter.
Default 1 (1%), if 0 (0%) turns off automation, if 100 (100%) enforces for all.

#### persist.adb.remount.overlayfs.maxfree
Only enabled on debug builds, ro.debuggable = 1.
Persistent development switch to override Board Configuration parameter.
Globally affect automation for determining if overlayfs is to be made
available for adb remount.
Enable overlayfs for limited space filesystems, treat them like read-only if
the percentage space remaining is less than this parameter.
Default ro.adb.remount.overlayfs.maxfree, if 0 (0%) turns off automation,
if 100 (100%) enforces for all.
This property is for allowing development control over this feature,
timing and logistics may not be ideal.
