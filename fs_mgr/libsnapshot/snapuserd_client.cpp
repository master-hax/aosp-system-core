#include <android-base/logging.h>
#include <libsnapshot/snapuserd_client.h>

namespace android {
namespace snapshot {

int SnapuserdClient::ConnectTo(const std::string& address, int port) {
    sockfd_ = 0;

    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ < 0) {
        LOG(ERROR) << "Failed to create socket " << strerror(errno);
        return -1;
    }

    int inetSuccess = inet_aton(address.c_str(), &server_.sin_addr);

    if (!inetSuccess) {
        struct hostent* host;
        struct in_addr** addrList;
        if ((host = gethostbyname(address.c_str())) == NULL) {
            return -1;
        }
        addrList = (struct in_addr**)host->h_addr_list;
        server_.sin_addr = *addrList[0];
    }
    server_.sin_family = AF_INET;
    server_.sin_port = htons(port);

    int connectRet = connect(sockfd_, (struct sockaddr*)&server_, sizeof(server_));
    if (connectRet < 0) {
        LOG(ERROR) << "Failed to connect " << strerror(errno);
        return -1;
    }

    return 0;
}

int SnapuserdClient::Sendmsg(const char* msg, size_t size) {
    int numBytesSent = send(sockfd_, msg, size, 0);
    if (numBytesSent < 0) {  // send failed
        LOG(ERROR) << "Send failed " << strerror(errno);
        return -1;
    }

    if ((uint)numBytesSent < size) {
        LOG(ERROR) << "Partial data sent " << strerror(errno);
        return -1;
    }
    return 0;
}

std::string SnapuserdClient::Receivemsg() {
    char msg[PACKET_SIZE];
    std::string msgStr;

    int ret = recv(sockfd_, msg, PACKET_SIZE, 0);
    if (ret <= 0) {
        msgStr = "fail";
        return msgStr;
    }

    msgStr = msg;
    return msgStr;
}

int SnapuserdClient::StopSnapuserd() {
    int connectRet = ConnectTo("127.0.0.1", PORT_NUM);
    if (connectRet < 0) {
        LOG(ERROR) << "Failed to create socket " << strerror(errno);
        return -1;
    }

    std::string msg = "stop";

    int sendRet = Sendmsg(msg.c_str(), msg.size());
    if (sendRet < 0) {
        LOG(ERROR) << "Failed to send message to snapuserd daemon";
        return -1;
    }

    return 0;
}

int SnapuserdClient::StartSnapuserd() {
    int ret;
    int retry_count = 0;

    if (fork() == 0) {
        const char* argv[] = {"/system/bin/snapuserd", nullptr};
        if (execv(argv[0], const_cast<char**>(argv))) {
            LOG(ERROR) << "Failed to exec snapuserd daemon";
            return -1;
        }
    }

    // snapuserd is a daemon and will never exit; parent can't wait here
    // to get the return code. Since Snapuserd starts the socket server,
    // give it some time to fully launch.
    //
    // Try to connect to server to verify daemon is completely up
    while (retry_count < MAX_CONNECT_RETRY_COUNT) {
        ret = ConnectTo("127.0.0.1", PORT_NUM);

        close(sockfd_);
        if (ret < 0) {
            retry_count++;
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            continue;
        }

        return 0;
    }

    return -1;
}

int SnapuserdClient::InitializeSnapuserd(std::string cow_device, std::string backing_device) {
    int connectRet = ConnectTo("127.0.0.1", PORT_NUM);
    if (connectRet < 0) {
        LOG(ERROR) << "Failed to create socket " << strerror(errno);
        return -1;
    }

    std::string msg = "start," + cow_device + "," + backing_device;

    int sendRet = Sendmsg(msg.c_str(), msg.size());
    if (sendRet < 0) {
        LOG(ERROR) << "Failed to send message to snapuserd daemon";
        return -1;
    }

    std::string str = Receivemsg();

    if (str.find("fail") != std::string::npos) {
        LOG(ERROR) << "Failed to Initialize snapuserd daemon";
        return -1;
    }

    return 0;
}

int SnapuserdClient::RestartSnapuserd() {
    int connectRet = ConnectTo("127.0.0.1", PORT_NUM);
    if (connectRet < 0) {
        LOG(ERROR) << "Failed to create socket " << strerror(errno);
        return -1;
    }

    std::string msg = "restart";

    int sendRet = Sendmsg(msg.c_str(), msg.size());
    if (sendRet < 0) {
        LOG(ERROR) << "Failed to send message to snapuserd daemon";
        return -1;
    }

    msg.clear();
    msg = Receivemsg();

    if (msg.find("fail") != std::string::npos) {
        LOG(ERROR) << "Failed to restart snapuserd daemon";
        return -1;
    }

    close(sockfd_);

    // Wait for snapuserd to completely shutdown
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    if (StartSnapuserd()) {
        LOG(ERROR) << "Failed to start snapuserd daemon";
        return -1;
    }

    // Wait for snapuserd to start
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // As part of restart, retrieve the devices passed to daemon
    // so that when the daemon is restarted, passed those devices
    // back.
    //
    // TODO: When dm-snapshot device is created, snapuserd stores
    // the metadata information. When daemon is restarted, we will
    // loose this metadata. Hence, client has to fetch all the necessary
    // metadata information before restarting.

    const char delim = ',';
    std::vector<std::string> out;
    Parsemsg(msg, delim, out);

    CHECK(out.size() % 2 == 0);

    int i = 0;
    while (i < out.size()) {
        if (InitializeSnapuserd(out[i], out[i + 1])) {
            LOG(ERROR) << "Failed to initialize";
            return -1;
        }

        close(sockfd_);
        i += 2;
    }

    return 0;
}

}  // namespace snapshot
}  // namespace android
