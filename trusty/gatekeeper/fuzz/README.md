Fuzzer for Trusty Gatekeeper service
====================================

# Initial Corpus

The initial corpus for this fuzzer was derived by dumping messages from the
`secure_env` emulator interface for cuttlefish while enrolling a new password in
the emulator. The following patch to `device/google/cuttlefish` adds the
necessary instrumentation to dump these messages:

``` diff
modified   common/libs/security/gatekeeper_channel.cpp
@@ -65,6 +65,20 @@ bool GatekeeperChannel::SendMessage(
   message.Serialize(to_send->payload, to_send->payload + payload_size);
   auto write_size = payload_size + sizeof(GatekeeperRawMessage);
   auto to_send_bytes = reinterpret_cast<const char*>(to_send.get());
+
+  char *filename = strdup("gatekeeper-send-XXXXXX");
+  int fd = mkstemp(filename);
+  if (fd >= 0) {
+    int rc = write(fd, to_send_bytes, write_size);
+    if (rc < 0) {
+      LOG(ERROR) << "Could not write gatekeeper message";
+    }
+    close(fd);
+  } else {
+    LOG(ERROR) << "Could not open gatekeeper message file while sending " <<
+      strerror(errno);
+  }
+
   auto written = WriteAll(channel_, to_send_bytes, write_size);
   if (written == -1) {
     LOG(ERROR) << "Could not write Gatekeeper Message: " << channel_->StrError();
@@ -91,6 +105,23 @@ ManagedGatekeeperMessage GatekeeperChannel::ReceiveMessage() {
     LOG(ERROR) << "Could not read Gatekeeper Message: " << channel_->StrError();
     return {};
   }
+
+  char *filename = strdup("gatekeeper-recv-XXXXXX");
+  int fd = mkstemp(filename);
+  if (fd >= 0) {
+    int rc = write(fd, &message_header, sizeof(GatekeeperRawMessage));
+    if (rc < 0) {
+      LOG(ERROR) << "Could not write gatekeeper message";
+    }
+    rc = write(fd, message->payload, message->payload_size);
+    if (rc < 0) {
+      LOG(ERROR) << "Could not write gatekeeper message";
+    }
+    close(fd);
+  } else {
+    LOG(ERROR) << "Could not open gatekeeper message file while sending " <<
+      strerror(errno);
+  }
   return message;
 }
```
