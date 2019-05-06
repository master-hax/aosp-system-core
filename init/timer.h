#include <android-base/chrono_utils.h>

using android::base::boot_clock;

class Timer2 {
  public:
    Timer2() : start_(boot_clock::now()) {}

    std::chrono::microseconds duration() const {
        return std::chrono::duration_cast<std::chrono::microseconds>(boot_clock::now() - start_);
    }

  private:
    boot_clock::time_point start_;
};

inline std::ostream& operator<<(std::ostream& os, const Timer2& t) {
    os << t.duration().count() << "us";
    return os;
}
