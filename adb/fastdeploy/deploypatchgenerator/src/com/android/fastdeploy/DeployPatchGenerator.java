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

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.nio.file.StandardOpenOption.CREATE;
import static java.nio.file.StandardOpenOption.TRUNCATE_EXISTING;
import static java.nio.file.StandardOpenOption.WRITE;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.AbstractMap.SimpleEntry;

import com.android.apkzlib.zip.ZFile;
import com.android.apkzlib.zip.ZFileOptions;
import com.android.apkzlib.zip.StoredEntry;
import com.android.apkzlib.zip.StoredEntryType;
import com.android.apkzlib.zip.CentralDirectoryHeaderCompressInfo;
import com.android.apkzlib.zip.CentralDirectoryHeader;
import com.android.apkzlib.zip.CompressionMethod;

import com.android.fastdeploy.APKMetaData;
import com.android.fastdeploy.APKEntry;

public final class DeployPatchGenerator {
    private static final int BUFFER_SIZE = 128 * 1024;

    public static void main(String[] args) {
        int exitCode = 0;
        try {
            exitCode = new DeployPatchGenerator().run(args);
        } catch (Exception e) {
            System.err.println("Error: " + e);
            exitCode = 1;
        }
        System.exit(exitCode);
    }

    private static int showUsage() {
        System.err.println("usage: deploypatchgenerator <apkpath> <devicemetadata>");
        System.err.println("");
        return 1;
    }

    public int run(String[] args) throws IOException, PatchFormatException {
        if (args.length < 2) {
            showUsage();
            return 1;
        }

        String apkPath = args[0];
        String deviceMetadataPath = args[1];
        File hostFile = new File(apkPath);
        boolean verbose = false; // TODO: make a way to set this on the command line

        List<APKEntry> deviceZipEntries = getMetadataFromFile(deviceMetadataPath);

        StringBuilder sb = new StringBuilder();
        for (APKEntry entry : deviceZipEntries) {
            APKEntryToString(entry, sb);
        }

        if (verbose) {
            System.err.println("Device Entries (" + deviceZipEntries.size() + ")");
            System.err.println(sb.toString());
        }

        sb = new StringBuilder();
        List<APKEntry> hostFileEntries = PatchUtils.getAPKMetaData(hostFile).getEntriesList();
        for (APKEntry entry : hostFileEntries) {
            APKEntryToString(entry, sb);
        }

        if (verbose) {
            System.err.println("Host Entries (" + hostFileEntries.size() + ")");
            System.err.println(sb.toString());
        }

        SortedSet<SimpleEntry<APKEntry, APKEntry>> identicalContentsEntrySet =
            getIdenticalContents(deviceZipEntries, hostFileEntries);
        reportIdenticalContents(identicalContentsEntrySet, hostFile);

        sb = new StringBuilder();
        for (SimpleEntry<APKEntry, APKEntry> identicalEntry : identicalContentsEntrySet) {
            APKEntry entry = identicalEntry.getValue();
            APKEntryToString(entry, sb);
        }

        if (verbose) {
            System.err.println("Identical Entries (" + identicalContentsEntrySet.size() + ")");
            System.err.println(sb.toString());
        }

        createPatch(identicalContentsEntrySet, hostFile, System.out);
        return 0;
    }

    private static void APKEntryToString(APKEntry entry, StringBuilder outputString) {
        outputString.append(String.format("Filename: %s\n", entry.getFileName()));
        outputString.append(String.format("CRC32: 0x%08X\n", entry.getCrc32()));
        outputString.append(String.format("Data Offset: %d\n", entry.getDataOffset()));
        outputString.append(String.format("Compressed Size: %d\n", entry.getCompressedSize()));
        outputString.append(String.format("Uncompressed Size: %d\n", entry.getUncompressedSize()));
    }

    private static List<APKEntry> getMetadataFromFile(String deviceMetadataPath) throws IOException {
        InputStream is = new FileInputStream(new File(deviceMetadataPath));
        APKMetaData apkMetaData = APKMetaData.parseDelimitedFrom(is);
        return apkMetaData.getEntriesList();
    }

    private static SortedSet<SimpleEntry<APKEntry, APKEntry>> getIdenticalContents(
        List<APKEntry> deviceZipEntries, List<APKEntry> hostZipEntries) throws IOException {
        SortedSet<SimpleEntry<APKEntry, APKEntry>> identicalContentsEntrySet =
            new TreeSet<SimpleEntry<APKEntry, APKEntry>>(
                new Comparator<SimpleEntry<APKEntry, APKEntry>>() {
                    @Override
                    public int compare(
                        SimpleEntry<APKEntry, APKEntry> p1, SimpleEntry<APKEntry, APKEntry> p2) {
                        return Long.compare(
                            p1.getValue().getDataOffset(), p2.getValue().getDataOffset());
                    }
                });

        for (APKEntry deviceZipEntry : deviceZipEntries) {
            for (APKEntry hostZipEntry : hostZipEntries) {
                if (deviceZipEntry.getCrc32() == hostZipEntry.getCrc32()) {
                    identicalContentsEntrySet.add(new SimpleEntry(deviceZipEntry, hostZipEntry));
                }
            }
        }

        return identicalContentsEntrySet;
    }

    private static void reportIdenticalContents(
        SortedSet<SimpleEntry<APKEntry, APKEntry>> identicalContentsEntrySet, File hostFile)
        throws IOException {
        long totalEqualBytes = 0;
        int totalEqualFiles = 0;
        for (SimpleEntry<APKEntry, APKEntry> entries : identicalContentsEntrySet) {
            APKEntry hostAPKEntry = entries.getValue();
            totalEqualBytes += hostAPKEntry.getCompressedSize();
            totalEqualFiles++;
        }

        float savingPercent = (float) (totalEqualBytes * 100) / hostFile.length();

        System.err.println("Detected " + totalEqualFiles + " equal APK entries");
        System.err.println(totalEqualBytes + " bytes are equal out of " + hostFile.length() + " ("
            + savingPercent + "%)");
    }

    static void createPatch(SortedSet<SimpleEntry<APKEntry, APKEntry>> zipEntrySimpleEntrys,
        File hostFile, OutputStream patchStream) throws IOException, PatchFormatException {
        FileInputStream hostFileInputStream = new FileInputStream(hostFile);

        patchStream.write(PatchUtils.SIGNATURE.getBytes(StandardCharsets.US_ASCII));
        PatchUtils.writeFormattedLong(hostFile.length(), patchStream);

        byte[] buffer = new byte[BUFFER_SIZE];
        long totalBytesWritten = 0;
        Iterator<SimpleEntry<APKEntry, APKEntry>> entrySimpleEntryIterator =
            zipEntrySimpleEntrys.iterator();
        while (entrySimpleEntryIterator.hasNext()) {
            SimpleEntry<APKEntry, APKEntry> entrySimpleEntry = entrySimpleEntryIterator.next();
            APKEntry deviceAPKEntry = entrySimpleEntry.getKey();
            APKEntry hostAPKEntry = entrySimpleEntry.getValue();

            long newDataLen = hostAPKEntry.getDataOffset() - totalBytesWritten;
            long oldDataOffset = deviceAPKEntry.getDataOffset();
            long oldDataLen = deviceAPKEntry.getCompressedSize();

            PatchUtils.writeFormattedLong(newDataLen, patchStream);
            PatchUtils.pipe(hostFileInputStream, patchStream, buffer, newDataLen);
            PatchUtils.writeFormattedLong(oldDataOffset, patchStream);
            PatchUtils.writeFormattedLong(oldDataLen, patchStream);

            long skip = hostFileInputStream.skip(oldDataLen);
            if (skip != oldDataLen) {
                throw new PatchFormatException("skip error: attempted to skip " + oldDataLen
                    + " bytes but return code was " + skip);
            }
            totalBytesWritten += oldDataLen + newDataLen;
        }
        long remainderLen = hostFile.length() - totalBytesWritten;
        PatchUtils.writeFormattedLong(remainderLen, patchStream);
        PatchUtils.pipe(hostFileInputStream, patchStream, buffer, remainderLen);
        PatchUtils.writeFormattedLong(0, patchStream);
        PatchUtils.writeFormattedLong(0, patchStream);
        patchStream.flush();
    }
}
