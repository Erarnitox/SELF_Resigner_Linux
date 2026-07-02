#pragma once

#include "console.hpp"
#include "filesystem.hpp"
#include "sce_operations.hpp"
#include "settings.hpp"

namespace resigner {

/// EBOOT.BIN / EBOOT.ELF workflows.
class EbootService {
public:
    EbootService(Settings& settings, SceOperations& sce_ops);

    void decrypt_only();
    void resign_non_drm();
    void resign_npdrm();
    void decrypt_fself();
    void resign_non_drm_dex();
    void resign_npdrm_dex();

private:
    Settings& settings_;
    SceOperations& sce_;

    [[nodiscard]] bool ensure_elf_available(bool& decrypted_temp);
    void backup_eboot_bin();
    void cleanup_temp_elf(bool remove_elf);
    void finish_resign(bool decrypted_temp);
    [[nodiscard]] bool prompt_for_content_id();
    [[nodiscard]] bool validate_content_id(const std::string& content_id) const;
};

} // namespace resigner
