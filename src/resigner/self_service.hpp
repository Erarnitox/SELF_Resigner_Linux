#pragma once

#include "console.hpp"
#include "filesystem.hpp"
#include "klicense_service.hpp"
#include "sce_operations.hpp"
#include "self_types.hpp"
#include "settings.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace resigner {

enum class BatchSelection {
    Back,
    All,
    Single,
};

struct BatchChoice {
    BatchSelection selection{BatchSelection::Back};
    int index{0};
};

/// SELF / SPRX workflows.
class SelfService {
public:
    SelfService(Settings& settings, SceOperations& sce_ops);

    void list_self_files();
    void decrypt_selected();
    void fast_resign_non_drm();
    void fast_resign_npdrm();
    void list_elf_files(bool require_npdrm);

private:
    Settings& settings_;
    SceOperations& sce_;
    KlicenseService klicense_;

    [[nodiscard]] std::vector<SelfEntry> collect_self_entries() const;
    [[nodiscard]] std::optional<SelfEntry> entry_from_filename(
        const std::filesystem::path& filename) const;
    void print_numbered_list(const std::vector<SelfEntry>& entries) const;
    [[nodiscard]] std::optional<SelfEntry> select_entry(
        const std::vector<SelfEntry>& entries) const;
    [[nodiscard]] std::optional<BatchChoice> prompt_batch_selection(
        const std::vector<SelfEntry>& entries) const;

    [[nodiscard]] std::filesystem::path elf_path_for(const SelfEntry& entry) const;
    [[nodiscard]] std::filesystem::path self_path_for(const SelfEntry& entry) const;
    [[nodiscard]] std::filesystem::path backup_path_for(const SelfEntry& entry) const;
    [[nodiscard]] std::string np_app_type_for(const SelfEntry& entry) const;

    [[nodiscard]] bool resign_entry_non_drm(const SelfEntry& entry);
    [[nodiscard]] bool resign_entry_npdrm(
        const SelfEntry& entry,
        const std::string& content_id,
        const std::string& klicensee);

    [[nodiscard]] int batch_resign_non_drm(const std::vector<SelfEntry>& entries);
    [[nodiscard]] int batch_resign_npdrm(
        const std::vector<SelfEntry>& entries,
        const std::string& content_id,
        const std::string& klicensee);

    void report_batch_result(int errors, std::string_view action) const;
    [[nodiscard]] bool ensure_eboot_for_npdrm() const;
    [[nodiscard]] bool resolve_npdrm_credentials(const SelfEntry& probe_entry);
};

} // namespace resigner
