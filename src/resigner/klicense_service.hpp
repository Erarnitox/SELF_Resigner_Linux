#pragma once

#include "sce_operations.hpp"
#include "self_types.hpp"

#include <optional>
#include <string>
#include <vector>

namespace resigner {

class KlicenseService {
public:
    explicit KlicenseService(SceOperations& sce_ops);

    [[nodiscard]] std::optional<std::string> resolve(
        const std::string& content_id,
        const SelfEntry& probe_entry);

    void remember(const std::string& content_id, const std::string& klicensee) const;

private:
    SceOperations& sce_;

    [[nodiscard]] std::optional<std::string> lookup_cache(const std::string& content_id) const;
    [[nodiscard]] bool probe_klicensee(
        const SelfEntry& entry,
        const std::string& klicensee) const;

    [[nodiscard]] std::optional<std::string> bruteforce_pool(
        const SelfEntry& probe_entry,
        const std::vector<std::string>& candidates) const;

    [[nodiscard]] std::optional<std::string> bruteforce_with_eboot(
        const SelfEntry& probe_entry) const;
};

} // namespace resigner
