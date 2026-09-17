// Constraint Routing Fabric -- identity rendering.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
#include "constraint_routing_fabric/identity.hpp"

#include <cstdio>

namespace crf {
namespace {

template <class Tag>
[[nodiscard]] std::string render(const StrongId<Tag>& value, const char* prefix) {
  char buffer[48] = {};
  std::snprintf(buffer, sizeof(buffer), "%s:%llu", prefix,
                static_cast<unsigned long long>(value.value()));
  return std::string(buffer);
}

template <class Tag>
[[nodiscard]] std::string render(const Generation<Tag>& value, const char* prefix) {
  char buffer[48] = {};
  std::snprintf(buffer, sizeof(buffer), "%s#%llu", prefix,
                static_cast<unsigned long long>(value.value()));
  return std::string(buffer);
}

}  // namespace

std::string to_string(ConstraintSetId value) { return render(value, "ConstraintSet"); }
std::string to_string(ConstraintId value) { return render(value, "Constraint"); }
std::string to_string(ConstraintEvaluationId value) { return render(value, "Evaluation"); }
std::string to_string(PathId value) { return render(value, "Path"); }
std::string to_string(NodeId value) { return render(value, "Node"); }
std::string to_string(LinkId value) { return render(value, "Link"); }
std::string to_string(PublisherId value) { return render(value, "Publisher"); }
std::string to_string(WorkerBootId value) { return render(value, "Boot"); }
std::string to_string(MutationAttemptId value) { return render(value, "Attempt"); }
std::string to_string(RequestId value) { return render(value, "Request"); }
std::string to_string(CoordinatorEpoch value) { return render(value, "Epoch"); }
std::string to_string(ConstraintSetGeneration value) { return render(value, "SetGeneration"); }
std::string to_string(ConstraintGeneration value) { return render(value, "ConstraintGeneration"); }
std::string to_string(EvaluationGeneration value) { return render(value, "EvaluationGeneration"); }
std::string to_string(PathAuthorityGeneration value) { return render(value, "PathAuthority"); }
std::string to_string(TopologyGeneration value) { return render(value, "Topology"); }
std::string to_string(LinkStateGeneration value) { return render(value, "LinkState"); }
std::string to_string(CapabilityGeneration value) { return render(value, "Capability"); }
std::string to_string(FailureDomainGeneration value) { return render(value, "FailureDomain"); }
std::string to_string(PolicyGeneration value) { return render(value, "Policy"); }
std::string to_string(PlannerGeneration value) { return render(value, "Planner"); }

}  // namespace crf
