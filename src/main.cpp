// SPDX-License-Identifier: Apache-2.0

#include "command.hpp"

#include <exception>
#include <iostream>
#include <string_view>
#include <vector>

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

int run_main(int argc, char* argv[]) {
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
    std::vector<std::string_view> arguments;
    arguments.reserve(argc > 1 ? static_cast<std::size_t>(argc - 1) : 0U);
    for (int index = 1; index < argc; ++index) arguments.emplace_back(argv[index]);
    credbind::audit::SyslogLogger logger;
    credbind::command::SystemClock clock;
    try {
        return credbind::command::run(arguments, std::cout, std::cerr, logger, clock);
    } catch (...) {
        // Verify must never cause OpenSSH to disclose its expanded bearer argument.
        if (!arguments.empty() && arguments.front() == "verify") {
            try {
                credbind::audit::VerificationEvent event;
                event.outcome = credbind::audit::VerificationOutcome::error;
                event.reason = credbind::ParseErrorKind::internal_error;
                for (std::size_t index = 1U; index + 1U < arguments.size(); ++index) {
                    if (arguments[index] == "--user") {
                        event.requested_user = std::string(arguments[index + 1U]);
                        break;
                    }
                }
                const auto serialized = credbind::audit::serialize(event);
                if (serialized) {
                    logger.emit(credbind::audit::Facility::authpriv,
                                serialized->severity, serialized->payload);
                }
            } catch (...) {
            }
            return 0;
        }
        std::cerr << "internal_error\n";
        return 2;
    }
}

}  // namespace

int main(int argc, char* argv[]) { return run_main(argc, argv); }
