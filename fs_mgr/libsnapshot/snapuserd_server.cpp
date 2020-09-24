#include <android-base/logging.h>
#include <libsnapshot/snapuserd.h>
#include <libsnapshot/snapuserd_server.h>

namespace android {
namespace snapshot {

// new thread
void SnapuserdServer::ThreadStart(std::string cow_device, std::string backing_device) {
    Snapuserd snapd(cow_device, backing_device);
    if (snapd.Init()) {
        LOG(ERROR) << "Snapuserd: Init failed";
        exit(EXIT_FAILURE);
    }

    while (StopRequested() == false) {
        int ret = snapd.Run();

        if (ret == -ETIMEDOUT) continue;

        if (ret < 0) {
            LOG(ERROR) << "snapd.Run() failed..." << ret;
        }
    }
}

void SnapuserdServer::ShutdownThreads() {
    StopThreads();

    for (auto& client : clients_vec_) {
        std::thread* th = client->GetThreadHandler();
        if (th != nullptr && th->joinable()) th->join();
    }
}

int SnapuserdServer::Sendmsg(int fd, char* msg, size_t size) {
    int ret = send(fd, (char*)msg, size, 0);
    if (ret < 0) return -1;
    return 0;
}

int SnapuserdServer::Receivemsg(int fd) {
    char msg[MAX_PACKET_SIZE];
    std::unique_ptr<Client> newClient;

    int ret = recv(fd, msg, MAX_PACKET_SIZE, 0);
    if (ret <= 0) {
        memset(msg, '\0', MAX_PACKET_SIZE);
        sprintf(msg, "fail");
        Sendmsg(fd, msg, MAX_PACKET_SIZE);
        return 0;
    } else {
        std::string str(msg);
        const char delim = ',';

        std::vector<std::string> out;
        Parsemsg(str, delim, out);
        DaemonOperations op = Resolveop(out[0]);
        memset(msg, '\0', MAX_PACKET_SIZE);

        if (op == DaemonOperations::START) {
            newClient = std::make_unique<Client>();
            newClient->SetCowDevice(out[1]);
            newClient->SetBackingStore(out[2]);
            newClient->SetThreadHandler(
                    std::bind(&SnapuserdServer::ThreadStart, this, out[1], out[2]));
            clients_vec_.push_back(std::move(newClient));
            sprintf(msg, "success");
            Sendmsg(fd, msg, MAX_PACKET_SIZE);
            return 0;
        } else if (op == DaemonOperations::STOP) {
            ShutdownThreads();
            return static_cast<int>(DaemonOperations::STOP);
        } else if (op == DaemonOperations::RESTART) {
            ShutdownThreads();
            std::string str = ConstructRestartmsg();
            memcpy(msg, str.c_str(), str.size());
            Sendmsg(fd, msg, MAX_PACKET_SIZE);
            return static_cast<int>(DaemonOperations::STOP);
        } else {
            sprintf(msg, "fail");
            Sendmsg(fd, msg, MAX_PACKET_SIZE);
            return 0;
        }
    }
}

int SnapuserdServer::Start(int port) {
    sockfd_ = 0;
    int ret;

    sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd_ == -1) {
        LOG(ERROR) << "Failed to create socket " << strerror(errno);
        return -1;
    }

    int option = 1;
    setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR, &option, sizeof(option));

    memset(&serverAddress_, 0, sizeof(serverAddress_));
    serverAddress_.sin_family = AF_INET;
    serverAddress_.sin_addr.s_addr = htonl(INADDR_ANY);
    serverAddress_.sin_port = htons(port);

    ret = bind(sockfd_, (struct sockaddr*)&serverAddress_, sizeof(serverAddress_));
    if (ret < 0) {
        LOG(ERROR) << "Failed to bind socket " << strerror(errno);
        return -1;
    }

    ret = listen(sockfd_, CLIENT_BACKLOG);
    if (ret < 0) {
        LOG(ERROR) << "listen failed " << strerror(errno);
        return -1;
    }

    return 0;
}

int SnapuserdServer::AcceptClient() {
    socklen_t sosize = sizeof(clientAddress_);

    int fd = accept(sockfd_, (struct sockaddr*)&clientAddress_, &sosize);
    if (fd < 0) {
        LOG(ERROR) << "Socket accept failed: " << strerror(errno);
        return -1;
    }

    return Receivemsg(fd);
}

}  // namespace snapshot
}  // namespace android
