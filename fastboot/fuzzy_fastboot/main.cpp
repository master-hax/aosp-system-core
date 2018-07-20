#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <regex>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <map>
#include <random>
#include <set>
#include <thread>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>
#include <sparse/sparse.h>
#include <ziparchive/zip_archive.h>

#include "bootimg_utils.h"
#include "diagnose_usb.h"
#include "fastboot_driver.h"
#include "fs.h"
#include "tcp.h"
#include "transport.h"
#include "udp.h"
#include "usb.h"

#define USB_TIMEOUT 2000

namespace fastboot {

constexpr int rand_seed = 0;
std::default_random_engine rnd(rand_seed);

// Legal ascii
const auto rand_legal = []() -> char { return rnd() % 128; };
// Illegal ascii
const auto rand_illegal = []() -> char { return rand_legal() + 128; };
// All chars
const auto rand_char = []() -> char { return rand_legal() % 256; };

std::string RandomString(size_t length, std::function<char(void)> provider) {
    std::string str(length, 0);
    std::generate_n(str.begin(), length, provider);
    return str;
}

// A special class for sniffing reads and writes
class UsbTransportSniffer : public UsbTransport {
  public:
    enum TransferType {
        READ,
        WRITE,
    };

    UsbTransportSniffer(std::unique_ptr<UsbTransport> transport)
        : transport_(std::move(transport)){};

    virtual ssize_t Read(void* data, size_t len) override {
        size_t ret = transport_->Read(data, len);
        if (ret != len) {
            return ret;
        }

        char* cdata = static_cast<char*>(data);
        std::vector<char> buf(cdata, cdata + len);
        std::pair<const TransferType, const std::vector<char>> t(READ, std::move(buf));
        transfers_.push_back(t);

        return ret;
    }

    virtual ssize_t Write(const void* data, size_t len) override {
        size_t ret = transport_->Write(data, len);
        if (ret != len) {
            return ret;
        }

        const char* cdata = static_cast<const char*>(data);
        std::vector<char> buf(cdata, cdata + len);
        std::pair<const TransferType, const std::vector<char>> t(WRITE, std::move(buf));
        transfers_.push_back(t);

        return ret;
    }

    virtual int Close() override { return transport_->Close(); }

    virtual int Reset() override { return transport_->Reset(); }

    std::vector<std::pair<const TransferType, const std::vector<char>>> Transfers() {
        return transfers_;
    }

  private:
    std::vector<std::pair<const TransferType, const std::vector<char>>> transfers_;
    std::unique_ptr<UsbTransport> transport_;
};

class FastBootTest : public testing::Test {
  public:
    static constexpr int MAX_USB_TRIES = 10;

    static int MatchFastboot(usb_ifc_info* info, const char* local_serial = nullptr) {
        if (info->ifc_class != 0xff || info->ifc_subclass != 0x42 || info->ifc_protocol != 0x03) {
            return -1;
        }

        cb_scratch = info->device_path;

        // require matching serial number or device path if requested
        // at the command line with the -s option.
        if (local_serial && (strcmp(local_serial, info->serial_number) != 0 &&
                             strcmp(local_serial, info->device_path) != 0))
            return -1;
        return 0;
    }

    inline bool UsbStillAvailible() {
        // For some reason someone decided to prefix the path with "usb:"
        std::string prefix("usb:");
        if (std::equal(prefix.begin(), prefix.end(), device_path.begin())) {
            std::string fname(device_path.begin() + prefix.size(), device_path.end());
            std::string real_path =
                    android::base::StringPrintf("/sys/bus/usb/devices/%s/serial", fname.c_str());
            std::ifstream f(real_path.c_str());
            return f.good();
        }
        exit(-1);  // This should never happend
        return true;
    }

  protected:
    RetCode DownloadCommand(uint32_t size, std::string* response = nullptr,
                            std::vector<std::string>* info = nullptr) {
        return fb->DownloadCommand(size, response, info);
    }

    RetCode SendBuffer(const std::vector<char>& buf) { return fb->SendBuffer(buf); }

    RetCode HandleResponse(std::string* response = nullptr,
                           std::vector<std::string>* info = nullptr, int* dsize = nullptr) {
        return fb->HandleResponse(response, info, dsize);
    }

    void SetUp() override {
        if (device_path != "") {               // make sure the device is still connected
            ASSERT_TRUE(UsbStillAvailible());  // The device disconnected
        }

        const auto matcher = [](usb_ifc_info* info) -> int { return MatchFastboot(info, nullptr); };
        for (int i = 0; i < MAX_USB_TRIES && !transport; i++) {
            std::unique_ptr<UsbTransport> usb(usb_open(matcher, USB_TIMEOUT));
            transport =
                    std::unique_ptr<UsbTransportSniffer>(new UsbTransportSniffer(std::move(usb)));
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        ASSERT_TRUE(transport);  // no nullptr

        if (device_path == "") {  // We set it the first time, then make sure it never changes
            device_path = cb_scratch;
        } else {
            ASSERT_EQ(device_path, cb_scratch);  // The path can not change
        }
        fb = std::unique_ptr<FastBootDriver>(
                new FastBootDriver(transport.get(), [](std::string&) {}, true));
    }

    void TearDown() override {
        ASSERT_TRUE(UsbStillAvailible());

        fb.reset();
        if (transport) {
            // transport->Reset();
            transport->Close();
            transport.reset();
        }

        ASSERT_TRUE(UsbStillAvailible());
    }

    std::unique_ptr<UsbTransportSniffer> transport;
    std::unique_ptr<FastBootDriver> fb;

  private:
    static std::string device_path;
    // This is an annoying hack
    static std::string cb_scratch;
};

std::string FastBootTest::device_path = "";
std::string FastBootTest::cb_scratch = "";

class BasicFunctionality : public FastBootTest {};

class Conformance : public FastBootTest {};

class Fuzz : public FastBootTest {
    void TearDown() override {
        ASSERT_TRUE(UsbStillAvailible());

        std::string tmp;
        if (fb->GetVar("product", &tmp) != SUCCESS) {
            printf("DEVICE UNRESPONSE, attempting to recover...");
            transport->Reset();

            if (fb->GetVar("product", &tmp) != SUCCESS) {
                printf("FAIL\n");
                exit(-1);
            }
            printf("SUCCESS!\n");
        }

        fb.reset();
        if (transport) {
            transport->Close();
            transport.reset();
        }

        ASSERT_TRUE(UsbStillAvailible());
    }
};

// Only allow alphanumeric, _, -, and .
const auto not_allowed = [](char c) -> int {
    return !(isalnum(c) || c == '_' || c == '-' || c == '.');
};

// Test that USB even works
TEST(USBFunctionality, USBConnect) {
    const auto matcher = [](usb_ifc_info* info) -> int {
        return FastBootTest::MatchFastboot(info, nullptr);
    };
    Transport* transport = nullptr;
    for (int i = 0; i < FastBootTest::MAX_USB_TRIES && !transport; i++) {
        transport = usb_open(matcher);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    ASSERT_NE(transport, nullptr);
    if (transport) {
        transport->Close();
        delete transport;
    }
}

// Conformance tests
TEST_F(Conformance, GetVar) {
    std::string product;
    EXPECT_EQ(fb->GetVar("product", &product), SUCCESS);
    EXPECT_NE(product, "");
    EXPECT_EQ(std::count_if(product.begin(), product.end(), not_allowed), 0);
    EXPECT_LE(product.size(), FB_RESPONSE_SZ - 4);
}

TEST_F(Conformance, GetVarVersionBootloader) {
    std::string var;
    EXPECT_EQ(fb->GetVar("version-bootloader", &var), SUCCESS);
    EXPECT_NE(var, "");
    EXPECT_EQ(std::count_if(var.begin(), var.end(), not_allowed), 0);
    EXPECT_LE(var.size(), FB_RESPONSE_SZ - 4);
}

TEST_F(Conformance, GetVarVersionBaseband) {
    std::string var;
    EXPECT_EQ(fb->GetVar("version-baseband", &var), SUCCESS);
    EXPECT_NE(var, "");
    EXPECT_EQ(std::count_if(var.begin(), var.end(), not_allowed), 0);
    EXPECT_LE(var.size(), FB_RESPONSE_SZ - 4);
}

TEST_F(Conformance, GetVarSerialNo) {
    std::string var;
    EXPECT_EQ(fb->GetVar("serialno", &var), SUCCESS);
    EXPECT_NE(var, "");
    EXPECT_EQ(std::count_if(var.begin(), var.end(), isalnum), var.size());
    EXPECT_LE(var.size(), FB_RESPONSE_SZ - 4);
}

TEST_F(Conformance, GetVarSecure) {
    std::string var;
    EXPECT_EQ(fb->GetVar("secure", &var), SUCCESS);
    EXPECT_TRUE(var == "yes" || var == "no");
}

TEST_F(Conformance, GetVarOffModeCharge) {
    std::string var;
    EXPECT_EQ(fb->GetVar("off-mode-charge", &var), SUCCESS);
    EXPECT_TRUE(var == "0" || var == "1");
}

TEST_F(Conformance, GetVarVariant) {
    std::string var;
    EXPECT_EQ(fb->GetVar("variant", &var), SUCCESS);
    EXPECT_LE(var.size(), FB_RESPONSE_SZ - 4);
}

TEST_F(Conformance, GetVarRevision) {
    std::string var;
    EXPECT_EQ(fb->GetVar("hw-revision", &var), SUCCESS);
    EXPECT_NE(var, "");
    EXPECT_EQ(std::count_if(var.begin(), var.end(), not_allowed), 0);
    EXPECT_LE(var.size(), FB_RESPONSE_SZ - 4);
}

TEST_F(Conformance, GetVarBattVoltage) {
    std::string var;
    EXPECT_EQ(fb->GetVar("battery-voltage", &var), SUCCESS);
    EXPECT_NE(var, "");
    EXPECT_EQ(std::count_if(var.begin(), var.end(), not_allowed), 0);
    EXPECT_LE(var.size(), FB_RESPONSE_SZ - 4);
}

TEST_F(Conformance, GetVarBattVoltageOk) {
    std::string var;
    EXPECT_EQ(fb->GetVar("battery-soc-ok", &var), SUCCESS);
    EXPECT_TRUE(var == "yes" || var == "no");
}

TEST_F(Conformance, GetVarDownloadSize) {
    std::string var;
    EXPECT_EQ(fb->GetVar("max-download-size", &var), SUCCESS);
    EXPECT_NE(var, "");
    // This must start with 0x
    EXPECT_FALSE(isspace(var.front()));
    EXPECT_FALSE(var.compare(0, 2, "0x"));
    int64_t size = strtoll(var.c_str(), nullptr, 16);
    EXPECT_GT(size, 0);
    // At most 32-bits
    EXPECT_LE(size, std::numeric_limits<uint32_t>::max());
    EXPECT_LE(var.size(), FB_RESPONSE_SZ - 4);
}

TEST_F(Conformance, GetVarAll) {
    std::vector<std::string> vars;
    EXPECT_EQ(fb->GetVarAll(&vars), SUCCESS);
    EXPECT_GT(vars.size(), 0);
    for (const auto s : vars) {
        EXPECT_LE(s.size(), FB_RESPONSE_SZ - 4);
    }
}

TEST_F(Conformance, PartitionInfo) {
    std::vector<std::tuple<std::string, uint32_t>> parts;
    EXPECT_EQ(fb->Partitions(&parts), SUCCESS);
    EXPECT_GT(parts.size(), 0);
    std::set<std::string> allowed{"ext4", "f2fs", "raw"};
    for (const auto p : parts) {
        EXPECT_GT(std::get<1>(p), 0);
        std::string type;
        std::string part(std::get<0>(p));
        EXPECT_EQ(fb->GetVar("partition-type:" + part, &type), SUCCESS);
        EXPECT_NE(allowed.find(type), allowed.end());
    }
}

TEST_F(Conformance, Slots) {
    std::string var;
    EXPECT_EQ(fb->GetVar("slot-count", &var), SUCCESS);
    EXPECT_EQ(std::count_if(var.begin(), var.end(), isdigit), var.size());
    int32_t num_slots = strtol(var.c_str(), nullptr, 10);

    // Can't run out of alphabet letters...
    EXPECT_LE(num_slots, 26);

    std::vector<std::tuple<std::string, uint32_t>> parts;
    EXPECT_EQ(fb->Partitions(&parts), SUCCESS);

    std::map<std::string, std::set<char>> part_slots;
    if (num_slots > 0) {
        EXPECT_EQ(fb->GetVar("current-slot", &var), SUCCESS);

        for (const auto p : parts) {
            std::string part(std::get<0>(p));
            std::regex reg("([[:graph:]]*)_([[:lower:]])");
            std::smatch sm;

            if (std::regex_match(part, sm, reg)) {  // This partition has slots
                std::string part_base(sm[1]);
                std::string slot(sm[2]);
                EXPECT_EQ(fb->GetVar("has-slot:" + part_base, &var), SUCCESS);
                EXPECT_EQ(var, "yes");
                EXPECT_TRUE(islower(slot.front()));
                std::set<char> tmp{slot.front()};
                part_slots.emplace(part_base, tmp);
                part_slots.at(part_base).insert(slot.front());
            } else {
                EXPECT_EQ(fb->GetVar("has-slot:" + part, &var), SUCCESS);
                EXPECT_EQ(var, "no");
            }
        }
        // Ensure each partition has the correct slot suffix
        for (const auto iter : part_slots) {
            const std::set<char>& char_set = iter.second;
            EXPECT_EQ(char_set.size(), num_slots);
            for (const char c : char_set) {
                EXPECT_GE(c, 'a');
                EXPECT_LT(c, 'a' + num_slots);
            }
        }
    }
}

TEST_F(Conformance, Download) {
    std::vector<char> buf{'a', 'o', 's', 'p'};
    EXPECT_EQ(fb->Download(buf), SUCCESS);
}

TEST_F(Fuzz, DownloadSize) {
    std::string var;
    EXPECT_EQ(fb->GetVar("max-download-size", &var), SUCCESS);
    int64_t size = strtoll(var.c_str(), nullptr, 0);
    EXPECT_GT(size, 0);

    EXPECT_EQ(DownloadCommand(size + 1), DEVICE_FAIL);

    std::vector<char> buf(size);
    EXPECT_EQ(fb->Download(buf), SUCCESS);
    ASSERT_TRUE(UsbStillAvailible());
}

TEST_F(Fuzz, DownloadLargerBuf) {
    std::vector<char> buf{'a', 'o', 's', 'p'};
    EXPECT_EQ(DownloadCommand(buf.size() - 1), SUCCESS);
    // There are two ways to handle this
    // Accept download, but send error response
    // Reject the download outright
    std::string resp;
    RetCode ret = SendBuffer(buf);
    EXPECT_TRUE(UsbStillAvailible());
    if (ret == SUCCESS) {
        // If it accepts the buffer, it better send back an error response
        EXPECT_EQ(HandleResponse(&resp), DEVICE_FAIL);
    } else {
        EXPECT_EQ(ret, IO_ERROR);
    }

    ASSERT_TRUE(UsbStillAvailible());
    // The device better still work after all that if we unplug and replug
    EXPECT_EQ(transport->Reset(), 0);
    EXPECT_EQ(fb->GetVar("product", &resp), SUCCESS);
}

TEST_F(Fuzz, DownloadOverRun) {
    std::vector<char> buf(1000, 'F');
    EXPECT_EQ(DownloadCommand(10), SUCCESS);
    // There are two ways to handle this
    // Accept download, but send error response
    // Reject the download outright
    std::string resp;
    RetCode ret = SendBuffer(buf);
    if (ret == SUCCESS) {
        // If it accepts the buffer, it better send back an error response
        EXPECT_EQ(HandleResponse(&resp), DEVICE_FAIL);
    } else {
        EXPECT_EQ(ret, IO_ERROR);
    }

    ASSERT_TRUE(UsbStillAvailible());
    // The device better still work after all that if we unplug and replug
    EXPECT_EQ(transport->Reset(), 0);
    EXPECT_EQ(fb->GetVar("product", &resp), SUCCESS);
}

TEST_F(Fuzz, DownloadInvalid) {
    EXPECT_EQ(DownloadCommand(0), DEVICE_FAIL);
    ASSERT_TRUE(UsbStillAvailible());
    EXPECT_EQ(fb->RawCommand("download:1"), DEVICE_FAIL);
    ASSERT_TRUE(UsbStillAvailible());
    EXPECT_EQ(fb->RawCommand("download:-1"), DEVICE_FAIL);
    ASSERT_TRUE(UsbStillAvailible());
    EXPECT_EQ(fb->RawCommand("download:-01000000"), DEVICE_FAIL);
    ASSERT_TRUE(UsbStillAvailible());
    EXPECT_EQ(fb->RawCommand("download:-0100000"), DEVICE_FAIL);
    ASSERT_TRUE(UsbStillAvailible());
    EXPECT_EQ(fb->RawCommand("download:"), DEVICE_FAIL);
    std::string cmd("download:01000000\0", sizeof("download:01000000\0"));
    EXPECT_EQ(fb->RawCommand(cmd), DEVICE_FAIL);
    ASSERT_TRUE(UsbStillAvailible());
    std::string cmd2("download:01000000\0dkjfvijafdaiuybgidabgybr",
                     sizeof("download:01000000\0dkjfvijafdaiuybgidabgybr"));
    EXPECT_EQ(fb->RawCommand(cmd2), DEVICE_FAIL);
    ASSERT_TRUE(UsbStillAvailible());
}

TEST_F(Fuzz, GetVarAllSpam) {
    for (int i = 0; i < 1000; i++) {
        std::vector<std::string> vars;
        ASSERT_EQ(fb->GetVarAll(&vars), SUCCESS);
    }
}

TEST_F(Fuzz, CommandTooLarge) {
    std::string s1 = RandomString(100, rand_legal);
    EXPECT_EQ(fb->RawCommand(s1), DEVICE_FAIL);
    std::string s2 = RandomString(100, rand_illegal);
    EXPECT_EQ(fb->RawCommand(s2), DEVICE_FAIL);
    std::string s3 = RandomString(100, rand_char);
    EXPECT_EQ(fb->RawCommand(s3), DEVICE_FAIL);
}

// End anonymous namespace
}  // namespace fastboot

/*
static const char* serial = nullptr;

constexpr int KB_MB = 1024;

struct Partition {

  Partition(const std::string name, int64_t min_size) :
  name(name)
  {
    this->minKB = min_size;
  }

  Partition(const std::string name) :
  name(name)
  {
    this->minKB = -1;
  }

  const std::string name;
  int64_t minKB;
};


 const std::vector<const Partition> REQUIRED_PARTITIONS{
    Partition("boot"), Partition("system"), Partition("userdata"),
    Partition("radio"), Partition("misc", 4), Partition("metadata", 16*KB_MB),
    Partition("cache", 50*KB_MB), Partition("recovery"), Partition("bootloader")
  };



static int match_fastboot_with_serial(usb_ifc_info* info, const char* local_serial) {
    if (info->ifc_class != 0xff || info->ifc_subclass != 0x42 || info->ifc_protocol != 0x03) {
        return -1;
    }

    // require matching serial number or device path if requested
    // at the command line with the -s option.
    if (local_serial && (strcmp(local_serial, info->serial_number) != 0 &&
                   strcmp(local_serial, info->device_path) != 0)) return -1;
    return 0;
}

static int match_fastboot(usb_ifc_info* info) {
    return match_fastboot_with_serial(info, serial);
}



int main() {
  std::unique_ptr<Transport> transport;
  while (!transport) {
    transport = std::unique_ptr<Transport>(usb_open(match_fastboot));
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  //auto cb = [](std::string &info){fprintf(stderr, "(bootloader) %s\n", info.c_str()); };
  auto cb = [](std::string &info){(void)info;};
  std::unique_ptr<FastBootHLI> fb = std::make_unique<FastBootHLI>(*transport, cb);

  std::string ret;
  std::vector<std::string> info;
  fb->GetVarAll(info);


  const std::vector<std::string> allowed{"b1c1", "c1b1", "cat", "b1c1-0.1-awisner-20180608.154256"};
  bool met;
  if(!fb->Require("version-bootloader", allowed, met, false)) {
    printf("Error");
    exit(1);
  }

  printf("%s", met ? "Requirements met\n" : "Requirements not met\n");


  std::vector<std::unique_ptr<FastBootTest>> tests;
  tests.push_back(std::make_unique<LongCmd>());
  tests.push_back(std::make_unique<AliveTest>());
  tests.push_back(std::make_unique<PartionBounds>());

  //tests.push_back(std::make_unique<FastBootTest>());

  for (std::unique_ptr<FastBootTest> &t : tests) {

    bool res = t->Run(*fb) == t->PASS;
    printf("[%s] %s\n", res ? "PASS" : "FAIL", t->Name().c_str());

    if (!res) { // if it failed recover
      // delete resources
      fb.reset();
      transport->Close();
      std::this_thread::sleep_for(std::chrono::milliseconds(1000));
      transport.reset(usb_open(match_fastboot));
      fb = std::make_unique<FastBootHLI>(*transport, cb);
      if (!fb)
        break;
    }
  }

  // delete resources
  fb.reset();
  transport->Close();
  transport.reset();

  transport.reset(usb_open(match_fastboot));

  if (!transport) {
    printf("Failed to reopen dev\n");
    exit(1);
      return 1;
  }
*/

/*
  std::vector<std::tuple<std::string,uint32_t>>  all;
  fb.Partitions(all);
  for (auto t : all) {
    printf("%s\n",std::get<0>(t).c_str());
  }
*/
/*
  std::string res;
  if(!fb_getvar(transport, "current-slot", &res)) {
    printf("%s\n", fb_get_error().c_str());
  }

  printf("START: %s\n", res.c_str());
  return 0;

  fb_getvar(transport, "slot-count", &res);
  int nslots = std::stoi(res);
  //fb_queue_reboot();
  for (Partition p : REQUIRED_PARTITIONS) {
    // get device info
    fb_getvar(transport, "has-slot:" + p.name, &res);
    if (res == "yes") {
      for (int i=0; i < nslots; i++) {
        fb_getvar(transport, "partition-size:" + p.name + "_" + std::string(1, 'a' + i), &res);
        printf("%s: %s\n", p.name.c_str(), res.c_str());
      }
    } else if (res == "no") {
      fb_getvar(transport, "partition-size:" + p.name, &res);
      printf("%s: %s\n", p.name.c_str(), res.c_str());
    } else {
      printf("Missing partition '%s'\n", p.name.c_str());
    }

  }
*/
int main(int argc, char** argv) {
    printf("<Waiting for Device>\n");
    const auto matcher = [](usb_ifc_info* info) -> int {
        return fastboot::FastBootTest::MatchFastboot(info, nullptr);
    };
    Transport* transport = nullptr;
    while (!transport) {
        transport = usb_open(matcher);
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    transport->Close();
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
