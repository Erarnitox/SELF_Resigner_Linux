#include "application.hpp"

namespace resigner {

Application::Application()
    : sce_ops_{settings_},
      eboot_service_{settings_, sce_ops_},
      self_service_{settings_, sce_ops_},
      menu_{settings_, eboot_service_, self_service_} {}

int Application::run() {
    while (true) {
        menu_.run_once();
    }
}

} // namespace resigner
