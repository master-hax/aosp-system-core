#include <android-base/logging.h>
#include <libsnapshot/snapuserd_daemon.h>

namespace android {
namespace snapshot {

int Daemon::StartServer(std::string socketname) {
    int ret;

    ret = server_.Start(socketname);
    if (ret < 0) {
        LOG(ERROR) << "Snapuserd daemon failed to start...";
        exit(EXIT_FAILURE);
    }

    return ret;
}

void Daemon::MaskAllSignalsExceptIntAndTerm() {
    sigset_t signalMask;
    sigfillset(&signalMask);
    sigdelset(&signalMask, SIGINT);
    sigdelset(&signalMask, SIGTERM);
    if (sigprocmask(SIG_SETMASK, &signalMask, NULL) != 0) {
        PLOG(ERROR) << "Failed to set sigprocmask";
    }
}

void Daemon::MaskAllSignals() {
    sigset_t signalMask;
    sigfillset(&signalMask);
    if (sigprocmask(SIG_SETMASK, &signalMask, NULL) != 0) {
        PLOG(ERROR) << "Couldn't mask all signals";
    }
}

Daemon::Daemon() {
    is_running_ = true;
}

bool Daemon::IsRunning() {
    return is_running_;
}

void Daemon::Run() {
    pollFd_ = std::make_unique<struct pollfd>();
    pollFd_->fd = server_.GetSocketFd();
    pollFd_->events = POLLIN;

    sigfillset(&signalMask_);
    sigdelset(&signalMask_, SIGINT);
    sigdelset(&signalMask_, SIGTERM);

    // Masking signals here ensure that after this point, we won't handle INT/TERM
    // until after we call into ppoll()
    MaskAllSignals();
    signal(SIGINT, Daemon::SignalHandler);
    signal(SIGTERM, Daemon::SignalHandler);

    LOG(DEBUG) << "Snapuserd-server: ready to accept connections";

    while (IsRunning()) {
        int ret = ppoll(pollFd_.get(), 1, nullptr, &signalMask_);
        MaskAllSignalsExceptIntAndTerm();

        if (ret == -1) {
            PLOG(ERROR) << "Snapuserd:ppoll error";
            break;
        }

        if (pollFd_->revents == POLLIN) {
            if (server_.AcceptClient() == static_cast<int>(DaemonOperations::STOP)) {
                Daemon::Instance().is_running_ = false;
            }
        }

        // Mask all signals to ensure that is_running_ can't become false between
        // checking it in the while condition and calling into ppoll()
        MaskAllSignals();
    }
}

void Daemon::SignalHandler(int signal) {
    LOG(DEBUG) << "Snapuserd received signal: " << signal;
    switch (signal) {
        case SIGINT:
        case SIGTERM: {
            Daemon::Instance().is_running_ = false;
            break;
        }
        default:
            LOG(ERROR) << "Received unknown signal " << signal;
            break;
    }
}

}  // namespace snapshot
}  // namespace android
