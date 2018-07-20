#include <android-base/stringprintf.h>

#include "tests.h"
#include "usb.h"

AliveTest::TestResult AliveTest::Run(FastBootHLI& fb) {
    std::string prod;
    return fb.GetVar("product", prod) ? PASS : FAIL;
}

const std::string& AliveTest::Name() {
    static const std::string n("AliveTest");
    return n;
}

const std::string& AliveTest::Descrip() {
    static const std::string n("Tests if device is responsive");
    return n;
}

LongCmd::TestResult LongCmd::Run(FastBootHLI& fb) {
    auto ret = fb.Driver().RawCommand("nskdnf498hrsnfsndfa90sfaf439sjfsnfsdnf39jrnfnoi3jnjdf");
    return ret == FastBootDriver::DEVICE_FAIL ? PASS : FAIL;
}

const std::string& LongCmd::Name() {
    static const std::string n("LongCmd");
    return n;
}

const std::string& LongCmd::Descrip() {
    static const std::string n("Tests to make sure too long a command is rejected");
    return n;
}

// DeviceReconnect TODO
DeviceReconnect::TestResult DeviceReconnect::Run(FastBootHLI& fb) {
    auto ret = fb.Driver().RawCommand("nskdnf498hrsnfsndfa90sfaf439sjfsnfsdnf39jrnfnoi3jnjdf");
    return ret == FastBootDriver::DEVICE_FAIL ? PASS : FAIL;
}

const std::string& DeviceReconnect::Name() {
    static const std::string n("DeviceReconnect");
    return n;
}

const std::string& DeviceReconnect::Descrip() {
    static const std::string n("Tests to make sure USB reconnection works");
    return n;
}

DownloadSize::TestResult DownloadSize::Run(FastBootHLI& fb) {
    std::string resp;
    if (!fb.GetVar("max-download-size", resp)) {
        return FAIL;
    }

    // Query the DL size
    size_t dlsize;
    if (!(dlsize = strtol(resp.c_str(), 0, 16))) {
        return FAIL;
    }

    const std::string cmd = android::base::StringPrintf("download:%08zx", dlsize + 1);
    // The device better reject this...
    if (fb.Driver().RawCommand(cmd, resp) != FastBootDriver::DEVICE_FAIL) {
        return FAIL;
    }

    // Check now with a proper sized download
    std::vector<char> buf(dlsize);
    return fb.Download(buf) ? PASS : FAIL;
}

const std::string& DownloadSize::Name() {
    static const std::string n("LongCmd");
    return n;
}

const std::string& DownloadSize::Descrip() {
    static const std::string n("Tests to make sure max-download-size param is enforced");
    return n;
}

PartionBounds::TestResult PartionBounds::Run(FastBootHLI& fb) {
    std::vector<std::tuple<std::string, uint32_t>> all;

    std::string resp;
    FastBootDriver::RetCode dret;

    if (!fb.GetVar("max-download-size", resp)) {
        return FAIL;
    }

    if (!fb.Partitions(all) || all.size() == 0) {
        return FAIL;
    }
    TestResult ret = PASS;

    size_t dlsize = strtol(resp.c_str(), 0, 16);

    for (auto t : all) {
        if (std::get<1>(t) + 1 > dlsize) {  // TOO large
            continue;
        }
        // Write something too large
        std::vector<char> tmp;
        tmp.resize(std::get<1>(t) + 1);
        // Try and download +1 more than is possible
        const std::string cmd = android::base::StringPrintf("download:%08zx", tmp.size());

        std::vector<std::string> info;

        dret = fb.Driver().RawCommand(cmd, resp);

        if (dret == FastBootDriver::DEVICE_FAIL) {  // This better be rejected by device
            // printf("Response got %s\n", fb.Driver().GetError().c_str());
            continue;
        } else {
            printf("Response got %s\n", fb.Driver().GetError().c_str());
            return FAIL;
        }

        // Now we send the correct sizes one
        tmp.resize(std::get<1>(t));

        // We need to send it the dummy buffer
        printf("Sending (%u)\n", (unsigned int)tmp.size());

        dret = fb.Driver().SendBuffer(tmp);

        // printf("Write got %s\n (%u)", FastBootDriver::RCString(dret).c_str(), (unsigned
        // int)tmp.size()); printf("Resp: %s\n", resp.c_str());

        if (dret == FastBootDriver::SUCCESS) {  // This is correct
            dret = fb.Driver().HandleResponse(resp, info);
            printf("Response got %s\n", FastBootDriver::RCString(dret).c_str());
        } else {
            printf("Response got %s\n", fb.Driver().GetError().c_str());
            return FAIL;
        }
    }

    return ret;
}

const std::string& PartionBounds::Name() {
    static const std::string n("PartitionBounds");
    return n;
}

const std::string& PartionBounds::Descrip() {
    static const std::string n("Tests to make sure too large of images are rejected");
    return n;
}
