// SPDX-License-Identifier: Apache-2.0

#ifndef CREDBIND_COMMAND_HPP
#define CREDBIND_COMMAND_HPP

#include "syslog_logger.hpp"

#include <cstddef>
#include <csignal>
#include <cstdint>
#include <iosfwd>
#include <string_view>
#include <vector>

#include <tl/expected.hpp>

namespace credbind::command {

class Clock {
  public:
    virtual ~Clock() = default;
    [[nodiscard]] virtual std::int64_t wall_time_unix() = 0;
    [[nodiscard]] virtual std::uint64_t monotonic_nanoseconds() = 0;
    [[nodiscard]] virtual bool cancellation_requested() = 0;
};

class SystemClock final : public Clock {
  public:
    explicit SystemClock(const volatile std::sig_atomic_t* cancellation) noexcept;
    [[nodiscard]] std::int64_t wall_time_unix() noexcept override;
    [[nodiscard]] std::uint64_t monotonic_nanoseconds() noexcept override;
    [[nodiscard]] bool cancellation_requested() noexcept override;

  private:
    const volatile std::sig_atomic_t* cancellation_;
};

[[nodiscard]] tl::expected<void, ParseError> validate_size_bound(
    std::size_t input_size, std::size_t configured_maximum);

[[nodiscard]] int run(const std::vector<std::string_view>& arguments,
                      std::ostream& output, std::ostream& diagnostics,
                      audit::Logger& logger, Clock& clock);

}  // namespace credbind::command

#endif
