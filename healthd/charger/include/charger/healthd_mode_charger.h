

#pragma once

#include <stdint.h>

#include <string>

#include <cutils/properties.h>
#include <health2impl/HalHealthLoop.h>
#include <health2impl/Health.h>
#include <minui/minui.h>

#include <linux/input.h>

#include <charger/animation.h>

class HealthdDraw;

namespace android {

struct key_state {
    bool pending;
    bool down;
    int64_t timestamp;
};

class Charger;

class ChargerLoop : public ::android::hardware::health::V2_1::implementation::HalHealthLoop {
   public:
    ChargerLoop(Charger* charger);
   protected:
    virtual void Heartbeat() override;
    virtual int PrepareToWait() override;
   private:
    Charger* charger_;
};

class Charger : public ::android::hardware::health::V2_1::implementation::Health {
   public:
    using HealthInfo_1_0 = android::hardware::health::V1_0::HealthInfo;
    using HealthInfo_2_1 = android::hardware::health::V2_1::HealthInfo;
    Charger(const std::string& name);
    ~Charger();

   protected:
    virtual void OnHealthInfoUpdate(const HealthInfo_2_1& health_info) override;

    // Subclass may override this if it has a customized healthd_config->screen_on.
    virtual bool ScreenOn(const HealthInfo_1_0&) {
        return true;
    }

    virtual void Init(android::hardware::health::HealthLoop* loop,
                      struct healthd_config* config) override;
   private:
    friend class ChargerLoop;

    void InitDefaultAnimationFrames();
    void UpdateScreenState(int64_t now);
    int SetKeyCallback(int code, int value);
    void UpdateInputState(input_event* ev);
    void SetNextKeyCheck(key_state* key, int64_t timeout);
    void ProcessKey(int code, int64_t now);
    void HandleInputState(int64_t now);
    void HandlePowerSupplyState(int64_t now);
    int InputCallback(int fd, unsigned int epevents);
    void InitAnimation();


    bool have_battery_state_ = false;
    bool charger_connected_ = false;
    bool screen_blanked_ = false;
    int64_t next_screen_transition_ = 0;
    int64_t next_key_check_ = 0;
    int64_t next_pwr_check_ = 0;
    int64_t wait_batt_level_timestamp_ = 0;

    key_state keys_[KEY_MAX + 1];

    animation batt_anim_;
    GRSurface* surf_unknown_ = nullptr;
    int boot_min_cap_ = 0;

    HealthInfo_1_0 health_info_ = {};
    std::unique_ptr<HealthdDraw> healthd_draw_;
    std::vector<animation::frame> owned_frames_;

};

}  // namespace android

int healthd_charger_main(int argc, char** argv);
