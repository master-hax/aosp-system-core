/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.fastdeploy;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.Set;

import android.os.Bundle;
import android.os.IBinder;
import android.content.IIntentReceiver;
import android.content.IIntentSender;
import android.content.Intent;
import android.content.IntentSender;
import android.content.pm.IPackageManager;
import android.content.pm.IPackageInstaller;
import android.content.pm.PackageInstaller;
import android.content.pm.PackageInstaller.SessionInfo;
import android.content.pm.PackageInstaller.SessionParams;
import android.content.pm.PackageManager;
import android.content.pm.PackageInfo;
import android.os.ServiceManager;
import android.os.RemoteException;
import android.os.UserHandle;

import com.android.fastdeploy.APKMetaData;
import com.android.fastdeploy.PatchUtils;

import libcore.io.IoUtils;

public final class DeployAgent {
    private static final int BUFFER_SIZE = 128 * 1024;
    private static final int AGENT_VERSION = 0x00000001;

    public static void main(String[] args) {
        try {
            if (args.length < 1) {
                showUsage(0);
            }

            String commandString = args[0];

            if (commandString.equals("extract")) {
                if (args.length < 2) {
                    showUsage(1);
                }

                String packageName = args[1];
                extractMetaData(packageName);
            } else if (commandString.equals("apply")) {
                if (args.length < 4) {
                    showUsage(1);
                }

                String packageName = args[1];
                String patchPath = args[2];
                String outputString = args[3];

                InputStream deltaInputStream = null;
                if (patchPath.compareTo("-") == 0) {
                    deltaInputStream = System.in;
                } else {
                    deltaInputStream = new FileInputStream(patchPath);
                }

                OutputStream outputStream;
                if (outputString.equals("-")) {
                    outputStream = System.out;
                } else if (outputString.equals("pm")) {
                    outputStream = null;
                } else {
                    outputStream = new FileOutputStream(outputString);
                }

                String[] sessionArgs = null;
                if (args.length > 4) {
                    int numSessionArgs = args.length-4;
                    sessionArgs = new String[numSessionArgs];
                    for (int i=0 ; i<numSessionArgs ; i++) {
                        sessionArgs[i] = args[i+4];
                    }
                }

                if (outputStream == null) {
                    applyPatch(packageName, deltaInputStream, sessionArgs);
                } else {
                    if (sessionArgs != null) {
                        System.err.print("Warning: Ignoring ");
                        for (String arg : sessionArgs) {
                            System.err.print(arg);
                        }
                        System.err.println("");
                    }
                    File deviceFile = getFileFromPackageName(packageName);
                    writePatchToStream(
                        new RandomAccessFile(deviceFile, "r"), deltaInputStream, outputStream);
                }
            } else if (commandString.equals("version")) {
                System.err.printf("0x%08X\n", AGENT_VERSION);
            } else {
                showUsage(1);
            }
        } catch (Exception e) {
            System.err.println("Error: " + e);
            e.printStackTrace();
            System.exit(2);
        }
        System.exit(0);
    }

    private static void showUsage(int exitCode) {
        System.err.println(
            "usage: deployagent [version|extract|apply] <packagename> [patchpath] [-o]");
        System.err.println("patchpath - path to patch file (or - to read from stdin)");
        System.err.println(
            "-o - by default output will be sent to packagemanager, - will redirect to stdout");
        System.err.println("-o filename - will redirect output to the specified filename");
        System.err.println("");
        System.exit(exitCode);
    }

    private static File getFileFromPackageName(String packageName) {
        try {
            IPackageManager mPm =
                IPackageManager.Stub.asInterface(ServiceManager.getService("package"));
            ;
            PackageInfo packageInfo = mPm.getPackageInfo(packageName, 0, 0);
            return new File(packageInfo.applicationInfo.sourceDir);
        } catch (RemoteException ex) {
            return null;
        }
    }

    private static void extractMetaData(String packageName) throws IOException {
        File apkFile = getFileFromPackageName(packageName);
        APKMetaData apkMetaData = PatchUtils.getAPKMetaData(apkFile);
        apkMetaData.writeDelimitedTo(System.out);
    }

    private static class LocalIntentReceiver {
        private final SynchronousQueue<Intent> mResult = new SynchronousQueue<>();

        private IIntentSender.Stub mLocalSender = new IIntentSender.Stub() {
            @Override
            public void send(int code, Intent intent, String resolvedType, IBinder whitelistToken,
                IIntentReceiver finishedReceiver, String requiredPermission, Bundle options) {
                try {
                    mResult.offer(intent, 5, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }
        };

        public IntentSender getIntentSender() {
            return new IntentSender((IIntentSender) mLocalSender);
        }

        public Intent getResult() {
            try {
                return mResult.take();
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static int createInstallSession(String[] args) {
        StringBuilder commandBuilder = new StringBuilder();
        commandBuilder.append("pm install-create ");
        for (int i=0 ; args != null && i<args.length ; i++) {
            commandBuilder.append(args[i] + " ");
        }

        try {
            Process p = Runtime.getRuntime().exec(commandBuilder.toString());
            p.waitFor();

            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String line = "";
            String successLineStart = "Success: created install session [";
            String successLineEnd = "]";
            while ((line = reader.readLine()) != null) {
                if (line.startsWith(successLineStart) && line.endsWith(successLineEnd)) {
                    return new Integer(line.substring(successLineStart.length(), line.lastIndexOf(successLineEnd)));
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return -1;
    }

    private static int applyPatch(String packageName, InputStream deltaStream, String[] sessionArgs) throws IOException {
        PackageInstaller.Session session = null;
        try {
            File deviceFile = getFileFromPackageName(packageName);
            IPackageManager mPm =
                IPackageManager.Stub.asInterface(ServiceManager.getService("package"));
            IPackageInstaller mInstaller = mPm.getPackageInstaller();

            int sessionId = createInstallSession(sessionArgs);
            if (sessionId < 0) {
                System.err.println("PM Create Session Failed");
                return -1;
            }
            SessionInfo info = mInstaller.getSessionInfo(sessionId);

            session = new PackageInstaller.Session(mInstaller.openSession(sessionId));
            writePatchedDataToSession(new RandomAccessFile(deviceFile, "r"), deltaStream, session);
            IoUtils.closeQuietly(deltaStream);

            final LocalIntentReceiver receiver = new LocalIntentReceiver();
            session.commit(receiver.getIntentSender());

            final Intent result = receiver.getResult();
            final int status =
                result.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE);
            if (status == PackageInstaller.STATUS_SUCCESS) {
                return 0;
            } else {
                System.err.println("PM Commit Failed:");
                System.err.println("Status: " + status);
                System.err.println(
                    "Message: " + result.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE));
                return status;
            }
        } catch (RemoteException ex) {
            System.err.println(ex.getStackTrace());
            return -1;
        } catch (PatchFormatException ex) {
            System.err.println(ex.getStackTrace());
            return -1;
        } finally {
            if (session != null) {
                session.abandon();
            }
            IoUtils.closeQuietly(session);
            IoUtils.closeQuietly(deltaStream);
        }
    }

    private static long writePatchToStream(RandomAccessFile oldData, InputStream patchData,
        OutputStream outputStream) throws IOException, PatchFormatException {
        long newSize = readSignature(patchData);
        long bytesWritten = writePatchedDataToStream(oldData, newSize, patchData, outputStream);
        outputStream.flush();
        if (bytesWritten != newSize) {
            throw new PatchFormatException(String.format(
                "Output Size Mismatch (expected %ld but wrote %ld)", newSize, bytesWritten));
        }
        return bytesWritten;
    }

    private static long readSignature(InputStream patchData)
        throws IOException, PatchFormatException {
        byte[] signatureBuffer = new byte[PatchUtils.SIGNATURE.length()];
        try {
            PatchUtils.readFully(patchData, signatureBuffer, 0, signatureBuffer.length);
        } catch (IOException e) {
            throw new PatchFormatException("truncated signature");
        }

        String signature = new String(signatureBuffer, 0, signatureBuffer.length, "US-ASCII");
        if (!PatchUtils.SIGNATURE.equals(signature)) {
            throw new PatchFormatException("bad signature");
        }

        long newSize = PatchUtils.readBsdiffLong(patchData);
        if (newSize < 0 || newSize > Integer.MAX_VALUE) {
            throw new PatchFormatException("bad newSize");
        }

        return newSize;
    }

    // Note that this function assumes patchData has been seek'ed to the start of the delta stream
    // (i.e. the signature has already been read by readSignature). For a stream that points to the
    // start of a patch file call writePatchToStream
    private static long writePatchedDataToStream(RandomAccessFile oldData, long newSize,
        InputStream patchData, OutputStream outputStream) throws IOException {
        long newDataBytesWritten = 0;
        byte[] buffer = new byte[BUFFER_SIZE];

        while (newDataBytesWritten < newSize) {
            long copyLen = PatchUtils.readFormattedLong(patchData);
            if (copyLen > 0) {
                PatchUtils.pipe(patchData, outputStream, buffer, (int) copyLen);
            }

            long oldDataOffset = PatchUtils.readFormattedLong(patchData);
            long oldDataLen = PatchUtils.readFormattedLong(patchData);
            oldData.seek(oldDataOffset);
            if (oldDataLen > 0) {
                PatchUtils.pipe(oldData, outputStream, buffer, (int) oldDataLen);
            }

            newDataBytesWritten += copyLen + oldDataLen;
        }

        return newDataBytesWritten;
    }

    private static void writePatchedDataToSession(RandomAccessFile oldData, InputStream patchData,
        PackageInstaller.Session session) throws IOException, PatchFormatException {
        long newSize = readSignature(patchData);

        OutputStream sessionOutputStream = session.openWrite("--", 0, newSize);

        long bytesWritten =
            writePatchedDataToStream(oldData, newSize, patchData, sessionOutputStream);

        sessionOutputStream.flush();
        session.fsync(sessionOutputStream);
        IoUtils.closeQuietly(sessionOutputStream);

        if (bytesWritten != newSize) {
            throw new PatchFormatException(String.format(
                "Output Size Mismatch (expected %d but wrote %)", newSize, bytesWritten));
        }
    }
}
