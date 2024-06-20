#pragma once
#include <expected>
#include <system_error>

namespace deus {

template <typename T>
using result = std::expected<T, std::error_code>;

using error = std::unexpected<std::error_code>;

}  // namespace deus