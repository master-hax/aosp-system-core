# Test Goal

Demonstrate that high priority Trusty threads are treated as such by the linux scheduler.
A positive verdict is given when the high priority busy thread grabs more cpu than the low-priority thread.