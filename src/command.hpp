// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_COMMAND_HPP
#define CREDBIND_COMMAND_HPP

#include "syslog_logger.hpp"

#include <cstdint>
#include <iosfwd>
#include <string_view>
#include <vector>

namespace credbind::command {

class Clock {
  public:
    virtual ~Clock() = default;
    [[nodiscard]] virtual std::int64_t wall_time_unix() = 0;
    [[nodiscard]] virtual std::uint64_t monotonic_milliseconds() = 0;
};

class SystemClock final : public Clock {
  public:
    [[nodiscard]] std::int64_t wall_time_unix() noexcept override;
    [[nodiscard]] std::uint64_t monotonic_milliseconds() noexcept override;
};

[[nodiscard]] int run(const std::vector<std::string_view>& arguments,
                      std::ostream& output, std::ostream& diagnostics,
                      audit::Logger& logger, Clock& clock);

struct UnsafeTestOnlyBypassDeadline final {};
[[nodiscard]] int run_for_test(
    const std::vector<std::string_view>& arguments, std::ostream& output,
    std::ostream& diagnostics, audit::Logger& logger, Clock& clock,
    UnsafeTestOnlyBypassDeadline);

}  // namespace credbind::command

#endif
