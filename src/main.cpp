// SPDX-License-Identifier: Apache-2.0

#include <iostream>
#include <string_view>

#ifndef CREDBIND_VERSION
#define CREDBIND_VERSION "v0.0.0-dev"
#endif

#ifndef CREDBIND_REVISION
#define CREDBIND_REVISION "unknown"
#endif

#ifndef CREDBIND_SOURCE_DATE_EPOCH
#define CREDBIND_SOURCE_DATE_EPOCH "0"
#endif

#ifndef CREDBIND_TARGET
#define CREDBIND_TARGET "unknown"
#endif

namespace {

constexpr std::string_view kCommand = "credbind-ssh-authorized-keys";

int run(int argc, char* argv[]) {
    if (argc == 2) {
        const std::string_view argument(argv[1]);
        if (argument == "version" || argument == "--version") {
            std::cout << "{\"command\":\"" << kCommand << "\",\"version\":\""
                      << CREDBIND_VERSION << "\",\"revision\":\"" << CREDBIND_REVISION
                      << "\",\"source_date_epoch\":\"" << CREDBIND_SOURCE_DATE_EPOCH
                      << "\",\"target\":\"" << CREDBIND_TARGET << "\"}\n";
            return 0;
        }
    }
    std::cerr << kCommand
              << ": command not implemented in the build baseline; use version\n";
    return 2;
}

}  // namespace

int main(int argc, char* argv[]) { return run(argc, argv); }
