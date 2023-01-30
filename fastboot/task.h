#include <string>

class Task {
  public:
    Task() = default;
    virtual void Run() = 0;
    virtual bool Parse(std::string& text) = 0;
    virtual ~Task() = default;
};

class FlashTask : public Task {
  public:
    FlashTask(std::string& _slot) : slot_(_slot) {}
    FlashTask(std::string& _slot, bool _force_flash) : slot_(_slot), force_flash_(_force_flash) {}

    void Run() override;
    bool Parse(std::string& text) override;
    ~FlashTask() {}

  private:
    std::string pname_;
    std::string fname_;
    std::string slot_;
    bool force_flash_ = false;
};

class RebootTask : public Task {
  public:
    RebootTask(){};
    RebootTask(std::string _reboot_target) : reboot_target_(_reboot_target){};
    void Run() override;
    bool Parse(std::string& text) override;
    ~RebootTask() {}

  private:
    std::string reboot_target_ = "";
};