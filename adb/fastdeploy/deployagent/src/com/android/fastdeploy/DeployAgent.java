/*
 * Copyright (C) 2007 The Android Open Source Project
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

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.TimeUnit;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.lang.StringBuilder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.ArrayList;
import java.util.Set;

import com.android.apkzlib.zip.ZFile;
import com.android.apkzlib.zip.ZFileOptions;
import com.android.apkzlib.zip.StoredEntry;
import com.android.apkzlib.zip.StoredEntryType;
import com.android.apkzlib.zip.CentralDirectoryHeaderCompressInfo;
import com.android.apkzlib.zip.CentralDirectoryHeader;

import com.android.fastdeploy.APKMetaData;
import com.android.fastdeploy.APKEntry;
import com.android.fastdeploy.PatchUtils;

public final class DeployAgent {
    private static final String TAG = "DeployAgent";
    private static final int BUFFER_SIZE = 128 * 1024;

    public static void main(String[] args) {
        int exitCode = 1;
        try {
            if (args.length < 2) {
                showUsage();
            } else {
                String commandString = args[0];
                String packageName = args[1];

                if (commandString.equals("extract")) {
                    extractMetaData(packageName);
                    exitCode = 0;
                } else if (commandString.equals("apply")) {
                    System.err.println("Applying to " + packageName);
                    applyPatch(packageName);
                    exitCode = 0;
                } else {
                    showUsage();
                }
            }
        } catch (Exception e) {
            System.err.println("Error: " + e);
        }
        System.exit(exitCode);
    }

    private static int showUsage() {
        System.err.println("usage: deployagent [extract|apply] <packagename>");
        System.err.println("");
        return 1;
    }

    private static void applyPatch(String packageName) throws IOException {
        String apkPath = getPathFromPackageName(packageName);
        File deviceFile = new File(apkPath);
        InputStream deltaStream = System.in;

        try (OutputStream out = System.out) {
            applyPatch(new RandomAccessFile(deviceFile, "r"), deltaStream, out);
        } catch (PatchFormatException x) {
            System.err.println(x);
            x.printStackTrace();
        }
    }

    private static void applyPatch(RandomAccessFile oldData, InputStream patchData,
        OutputStream newData) throws IOException, PatchFormatException {
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

        long newDataBytesWritten = 0;
        byte[] buffer = new byte[BUFFER_SIZE];

        while (newDataBytesWritten < newSize) {
            long copyLen = PatchUtils.readFormattedLong(patchData);
            if (copyLen > 0) {
                PatchUtils.pipe(patchData, newData, buffer, (int) copyLen);
            }

            long oldDataOffset = PatchUtils.readFormattedLong(patchData);
            long oldDataLen = PatchUtils.readFormattedLong(patchData);
            oldData.seek(oldDataOffset);
            if (oldDataLen > 0) {
                PatchUtils.pipe(oldData, newData, buffer, (int) oldDataLen);
            }

            newDataBytesWritten += copyLen + oldDataLen;
        }
    }

    private static String getPathFromPackageName(String packageName) {
        StringBuilder commandBuilder = new StringBuilder();
        commandBuilder.append("pm list packages -f " + packageName);

        Process p;
        try {
            p = Runtime.getRuntime().exec(commandBuilder.toString());
            p.waitFor();
            BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));

            String packagePrefix = "package:";

            String line = "";
            while ((line = reader.readLine()) != null) {
                int packageIndex = line.indexOf(packagePrefix);
                int equalsIndex = line.indexOf("=" + packageName);
                return line.substring(packageIndex + packagePrefix.length(), equalsIndex);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    private static void extractMetaData(String packageName) throws IOException {
        String apkPath = getPathFromPackageName(packageName);
        File apkFile = new File(apkPath);
        APKMetaData apkMetaData = PatchUtils.getAPKMetaData(apkFile);
        apkMetaData.writeDelimitedTo(System.out);
    }
}
