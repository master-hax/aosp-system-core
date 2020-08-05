/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef HEALTHD_ANIMATION_H
#define HEALTHD_ANIMATION_H

#include <inttypes.h>
#include <unistd.h>

#include <string>

class GRSurface;
struct GRFont;

namespace android {

#define CENTER_VAL INT_MAX

struct animation {
    struct frame {
        int disp_time;
        int min_level;
        int max_level;

        GRSurface* surface;
    };

    struct text_field {
        std::string font_file;
        int pos_x;
        int pos_y;
        int color_r;
        int color_g;
        int color_b;
        int color_a;

        GRFont* font;
    };

    // When libminui loads PNG images:
    // - When treating paths as relative paths, it adds ".png" suffix.
    // - When treating paths as absolute paths, it doesn't add the suffix. Hence, the suffix
    //   is added here.
    // If |backup_root| is provided, additionally check if file under |root| is accessbile or not.
    // If not accessbile, use |backup_root| instead.
    void set_resource_root(const std::string& root, const std::string& backup_root = "") {
        set_resource_root_for(root, backup_root, &animation_file);
        set_resource_root_for(root, backup_root, &fail_file);
        set_resource_root_for(root, backup_root, &text_clock.font_file);
        set_resource_root_for(root, backup_root, &text_percent.font_file);
    }

    std::string animation_file;
    std::string fail_file;

    text_field text_clock;
    text_field text_percent;

    bool run;

    frame* frames = nullptr;
    int cur_frame;
    int num_frames;
    int first_frame_repeats;  // Number of times to repeat the first frame in the current cycle

    int cur_cycle;
    int num_cycles;  // Number of cycles to complete before blanking the screen

    int cur_level;  // current battery level being animated (0-100)
    int cur_status;  // current battery status - see BatteryService.h for BATTERY_STATUS_*

    ~animation() { delete frames; }

  private:
    static void set_resource_root_for(const std::string& root, const std::string& backup_root,
                                      std::string* value) {
        if (value->empty()) {
            return;
        }

        std::string new_value = root + *value + ".png";
        // If |backup_root| is provided, additionally check whether the file under |root| is
        // accessible or not. If not accessible, fallback to file under |backup_root|.
        if (!backup_root.empty() && access(new_value.data(), F_OK) == -1) {
            new_value = backup_root + *value + ".png";
        }

        *value = new_value;
    }
};

}

#endif // HEALTHD_ANIMATION_H
