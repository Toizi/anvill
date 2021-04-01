#include "ControlFlowProvider.h"

namespace anvill {

struct ControlFlowProvider::PrivateData final {
  PrivateData(const Program &program_) : program(program_) {}

  const Program &program;
};

ControlFlowProvider::ControlFlowProvider(const Program &program)
    : d(new PrivateData(program)) {}

ControlFlowProvider::~ControlFlowProvider(void) = default;

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
