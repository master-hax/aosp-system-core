
# Reads the systrace trace from the device into a viewable 'trace.html' on the
# host.
mydir=`dirname $0`
adb shell cat /sys/kernel/debug/tracing/trace | sed -e $'s/\r$//' -e 's/$/\\n\\/' | cat $mydir/boot_trace_header.html - $mydir/boot_trace_footer.html > trace.html
