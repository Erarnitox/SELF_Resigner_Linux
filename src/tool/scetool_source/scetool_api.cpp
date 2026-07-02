#include "scetool.hpp"

#include <cstdio>
#include <filesystem>
#include <format>
#include <fstream>
#include <sstream>
#include <string_view>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <unistd.h>
#endif

#include "keys.h"

namespace ps3::sce {

bool ensure_crypto_assets_loaded();

namespace {

std::string bool_arg(bool value) {
    return value ? "TRUE" : "FALSE";
}

class StdoutRedirect {
public:
    bool redirect(const std::filesystem::path& path) {
#ifdef _WIN32
        saved_fd_ = _dup(_fileno(stdout));
#else
        saved_fd_ = dup(STDOUT_FILENO);
#endif
        if (saved_fd_ < 0) {
            return false;
        }

        if (std::freopen(path.string().c_str(), "w", stdout) == nullptr) {
#ifdef _WIN32
            _close(saved_fd_);
#else
            close(saved_fd_);
#endif
            saved_fd_ = -1;
            return false;
        }

        active_ = true;
        return true;
    }

    void restore() {
        if (!active_ || saved_fd_ < 0) {
            return;
        }

        std::fflush(stdout);
#ifdef _WIN32
        _dup2(saved_fd_, _fileno(stdout));
        _close(saved_fd_);
#else
        dup2(saved_fd_, STDOUT_FILENO);
        close(saved_fd_);
#endif
        saved_fd_ = -1;
        active_ = false;
    }

    ~StdoutRedirect() {
        restore();
    }

private:
    int saved_fd_{-1};
    bool active_{false};
};

std::vector<std::string> to_argv(const SelfEncryptParams& params) {
    std::vector<std::string> args;
    if (params.verbose) {
        args.emplace_back("-v");
    }

    args.emplace_back(std::format("--sce-type={}", params.sce_type));
    args.emplace_back(std::format("--compress-data={}", bool_arg(params.compress_data)));
    args.emplace_back(std::format("--skip-sections={}", bool_arg(params.skip_sections)));
    args.emplace_back(std::format("--key-revision={}", params.key_revision));
    args.emplace_back(std::format("--self-auth-id={}", params.self_auth_id));
    args.emplace_back(std::format("--self-vendor-id={}", params.self_vendor_id));
    args.emplace_back(std::format("--self-type={}", params.self_type));
    args.emplace_back(std::format("--self-app-version={}", params.self_app_version));
    args.emplace_back(std::format("--self-fw-version={}", params.self_fw_version));

    if (params.self_add_shdrs.has_value()) {
        args.emplace_back(std::format("--self-add-shdrs={}", bool_arg(*params.self_add_shdrs)));
    }
    if (params.self_ctrl_flags.has_value()) {
        args.emplace_back(std::format("--self-ctrl-flags={}", *params.self_ctrl_flags));
    }
    if (params.self_cap_flags.has_value()) {
        args.emplace_back(std::format("--self-cap-flags={}", *params.self_cap_flags));
    }
    if (params.np_license_type.has_value()) {
        args.emplace_back(std::format("--np-license-type={}", *params.np_license_type));
    }
    if (params.np_app_type.has_value()) {
        args.emplace_back(std::format("--np-app-type={}", *params.np_app_type));
    }
    if (params.np_content_id.has_value()) {
        args.emplace_back(std::format("--np-content-id={}", *params.np_content_id));
    }
    if (params.np_klicensee.has_value()) {
        args.emplace_back(std::format("--np-klicensee={}", *params.np_klicensee));
    }
    if (params.np_real_fname.has_value()) {
        args.emplace_back(std::format("--np-real-fname={}", *params.np_real_fname));
    }

    args.emplace_back("--encrypt");
    args.emplace_back(params.input.string());
    args.emplace_back(params.output.string());
    return args;
}

} // namespace

int scetool_engine_main(const std::vector<std::string>& args);

Result Scetool::run(const std::vector<std::string>& args) {
    const int code = scetool_engine_main(args);
    return Result{.success = code == 0, .exit_code = code};
}

Result Scetool::decrypt(
    const std::filesystem::path& input,
    const std::filesystem::path& output,
    const std::optional<std::string>& klicensee,
    const bool verbose) {
    std::vector<std::string> args;
    if (verbose) {
        args.emplace_back("-v");
    }
    if (klicensee.has_value()) {
        args.emplace_back(std::format("--np-klicensee={}", *klicensee));
    }
    args.emplace_back("--decrypt");
    args.emplace_back(input.string());
    args.emplace_back(output.string());
    return run(args);
}

Result Scetool::encrypt(const SelfEncryptParams& params) {
    return run(to_argv(params));
}

Result Scetool::print_info(
    const std::filesystem::path& input,
    const std::optional<std::filesystem::path>& redirect_to) {
    if (!redirect_to.has_value()) {
        return run({"-i", input.string()});
    }

    const auto parent = redirect_to->parent_path();
    if (!parent.empty() && !std::filesystem::exists(parent)) {
        std::filesystem::create_directories(parent);
    }

    StdoutRedirect redirect;
    if (!redirect.redirect(*redirect_to)) {
        return Result{.success = false, .exit_code = -1};
    }

    const Result result = run({"-i", input.string()});
    redirect.restore();
    return result;
}

std::optional<std::string> Scetool::content_id_from_info_file(const std::filesystem::path& info_file) {
    std::ifstream in{info_file};
    if (!in) {
        return std::nullopt;
    }

    std::string line;
    for (int skipped = 0; skipped < 3 && std::getline(in, line); ++skipped) {
    }

    while (std::getline(in, line)) {
        std::istringstream iss{line};
        std::string token;
        if (!(iss >> token)) {
            continue;
        }
        if (token == "ContentID") {
            std::string content_id;
            if (iss >> content_id) {
                return content_id;
            }
            if (std::getline(iss, content_id)) {
                const auto start = content_id.find_first_not_of(" \t");
                if (start != std::string::npos) {
                    return content_id.substr(start);
                }
            }
        }
    }
    return std::nullopt;
}

bool Scetool::ensure_initialized() {
    return ensure_crypto_assets_loaded();
}

std::optional<std::string> Scetool::klicensee_for_content_id(const std::string& content_id) {
    if (!ensure_initialized()) {
        return std::nullopt;
    }

    u8 klicensee[16]{};
    if (klicensee_by_content_id(content_id.c_str(), klicensee) == FALSE) {
        return std::nullopt;
    }

    std::string hex;
    hex.reserve(32);
    for (const auto byte : klicensee) {
        hex += std::format("{:02X}", byte);
    }
    return hex;
}

SelfEncryptBuilder::SelfEncryptBuilder(std::filesystem::path input, std::filesystem::path output)
    : params_{.input = std::move(input), .output = std::move(output)} {}

SelfEncryptBuilder& SelfEncryptBuilder::verbose(const bool value) {
    params_.verbose = value;
    return *this;
}

SelfEncryptBuilder& SelfEncryptBuilder::compress_data(const bool value) {
    params_.compress_data = value;
    return *this;
}

SelfEncryptBuilder& SelfEncryptBuilder::skip_sections(const bool value) {
    params_.skip_sections = value;
    return *this;
}

SelfEncryptBuilder& SelfEncryptBuilder::key_revision(std::string revision) {
    params_.key_revision = std::move(revision);
    return *this;
}

SelfEncryptBuilder& SelfEncryptBuilder::firmware_version(std::string version) {
    params_.self_fw_version = std::move(version);
    return *this;
}

SelfEncryptBuilder& SelfEncryptBuilder::self_type(std::string type) {
    params_.self_type = std::move(type);
    return *this;
}

SelfEncryptBuilder& SelfEncryptBuilder::add_section_headers(const bool value) {
    params_.self_add_shdrs = value;
    return *this;
}

SelfEncryptBuilder& SelfEncryptBuilder::control_flags(std::string flags) {
    params_.self_ctrl_flags = std::move(flags);
    return *this;
}

SelfEncryptBuilder& SelfEncryptBuilder::capability_flags(std::string flags) {
    params_.self_cap_flags = std::move(flags);
    return *this;
}

SelfEncryptBuilder& SelfEncryptBuilder::npdrm(
    std::string content_id,
    std::string app_type,
    std::string real_fname) {
    params_.self_type = "NPDRM";
    params_.np_license_type = "FREE";
    params_.np_content_id = std::move(content_id);
    params_.np_app_type = std::move(app_type);
    params_.np_real_fname = std::move(real_fname);
    return *this;
}

SelfEncryptBuilder& SelfEncryptBuilder::np_klicensee(std::string klicensee) {
    params_.np_klicensee = std::move(klicensee);
    return *this;
}

SelfEncryptParams SelfEncryptBuilder::build() const {
    return params_;
}

Result SelfEncryptBuilder::encrypt() const {
    return Scetool::encrypt(params_);
}

} // namespace ps3::sce
