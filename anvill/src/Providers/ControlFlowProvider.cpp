#include "ControlFlowProvider.h"

namespace anvill {

struct ControlFlowProvider::PrivateData final {
  PrivateData(const Program &program_) : program(program_) {}

  const Program &program;
};

ControlFlowProvider::ControlFlowProvider(const Program &program)
    : d(new PrivateData(program)) {}

ControlFlowProvider::~ControlFlowProvider(void) = default;

OptionalTargetList
ControlFlowProvider::GetTargetList(std::uint64_t address) const {
  return d->program.GetControlFlowTargetList(address);
}

TargetList ControlFlowProvider::GetTargetListOr(
    std::uint64_t address,
    std::optional<std::uint64_t> opt_default_value) const {

  auto opt_target_list = GetTargetList(address);
  if (opt_target_list.has_value()) {
    return opt_target_list.value();
  }

  auto default_value{address};
  if (opt_default_value.has_value()) {
    default_value = opt_default_value.value();
  }

  return {default_value};
}

std::uint64_t ControlFlowProvider::GetRedirection(std::uint64_t address) const {
  std::uint64_t destination{};
  if (!d->program.GetControlFlowRedirection(destination, address)) {
    destination = address;
  }

  return destination;
}

Result<IControlFlowProvider::Ptr, ControlFlowProviderError>
IControlFlowProvider::Create(const Program &program) {
  try {
    return Ptr(new ControlFlowProvider(program));

  } catch (const std::bad_alloc &) {
    return ControlFlowProviderError::MemoryAllocationError;

  } catch (const ControlFlowProviderError &error) {
    return error;
  }
}
}  // namespace anvill
