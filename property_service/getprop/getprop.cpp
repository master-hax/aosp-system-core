#include <getopt.h>
#include <sys/system_properties.h>

#include <iostream>
#include <string>
#include <vector>

#include <android-base/properties.h>
#include <property_info_parser/property_info_parser.h>

using android::base::GetProperty;
using android::properties::PropertyInfoAreaFile;

PropertyInfoAreaFile property_info_file;

void PrintAllProperties(bool flag_Z) {
  std::vector<std::pair<std::string, std::string>> properties;
  __system_property_foreach(
      [](const prop_info* pi, void* cookie) {
        __system_property_read_callback(
            pi,
            [](void* cookie, const char* name, const char* value, unsigned) {
              auto properties =
                  reinterpret_cast<std::vector<std::pair<std::string, std::string>>*>(cookie);
              properties->emplace_back(name, value);
            },
            cookie);
      },
      &properties);

  std::sort(properties.begin(), properties.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.first < rhs.first; });

  if (flag_Z) {
    for (auto& [name, value] : properties) {
      const char* context = nullptr;
      property_info_file->GetPropertyInfo(name.c_str(), &context, nullptr);
      value = context;
    }
  }

  for (const auto& [name, value] : properties) {
    std::cout << "[" << name << "]: [" << value << "]" << std::endl;
  }
}

void PrintProperty(const char* name, const char* default_value, bool flag_Z) {
  if (!flag_Z) {
    std::cout << GetProperty(name, default_value) << std::endl;
  } else {
    const char* context = nullptr;
    property_info_file->GetPropertyInfo(name, &context, nullptr);
    std::cout << context << std::endl;
  }
}

int main(int argc, char** argv) {
  bool flag_Z = false;

  while (1) {
    static const struct option long_options[] = {
        {"help", no_argument, nullptr, 'h'},
        {nullptr, 0, nullptr, 0},
    };

    int arg = getopt_long(argc, argv, "Z", long_options, nullptr);

    if (arg == -1) {
      break;
    }

    switch (arg) {
      case 'h':
        std::cout << "usage: getprop [NAME [DEFAULT]]\n\n"
                     "Gets an Android system property, or lists them all.\n"
                  << std::endl;
        return 0;
      case 'Z':
        flag_Z = true;
        break;
      case '?':
        return -1;
      default:
        std::cerr << "getprop: getopt returned invalid result: " << arg << std::endl;
        return -1;
    }
  }

  if (flag_Z) {
    property_info_file.LoadDefaultPath();
    if (!property_info_file) {
      std::cerr << "Unable to load property info file" << std::endl;
      return -1;
    }
  }

  if (optind >= argc) {
    PrintAllProperties(flag_Z);
    return 0;
  }

  if (optind < argc - 2) {
    std::cerr << "getprop: Max 2 arguments (see \"getprop --help\")" << std::endl;
    return -1;
  }

  PrintProperty(argv[optind], (optind == argc - 1) ? "" : argv[optind + 1], flag_Z);

  return 0;
}
