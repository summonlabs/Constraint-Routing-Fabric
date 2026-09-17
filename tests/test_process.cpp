// Constraint Routing Fabric -- real process proofs.
// Copyright 2026 Summon Software Labs.
// SPDX-License-Identifier: Apache-2.0
//
// These tests start real OS processes, kill them for real, and prove the
// authority and recovery behaviour end to end. No sleep is used for semantic
// correctness: every step is driven by the child's own output or by process
// termination.
#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <string>
#include <vector>

#include "crf_fixture.hpp"
#include "test_support.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace {

using namespace crf;           // NOLINT(google-build-using-namespace)
using namespace crf::fixture;  // NOLINT(google-build-using-namespace)

[[nodiscard]] std::string host_executable() {
#if defined(CRF_HOST_EXECUTABLE)
  return std::string(CRF_HOST_EXECUTABLE);
#else
  return std::string();
#endif
}

/// CreateProcess resolves a module path most reliably with native separators.
[[nodiscard]] std::string native_path(const std::string& value) {
  std::string text = value;
  std::replace(text.begin(), text.end(), '/', '\\');
  return text;
}

[[nodiscard]] std::string quote(const std::string& value) {
  std::string quoted = "\"";
  quoted += value;
  quoted += "\"";
  return quoted;
}

#if defined(_WIN32)

/// A real child process with a captured standard output pipe.
class ChildProcess {
 public:
  ChildProcess() = default;
  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;
  ~ChildProcess() { release(); }

  [[nodiscard]] bool start(const std::string& executable, const std::string& arguments) {
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE output_read = nullptr;
    HANDLE output_write = nullptr;
    if (CreatePipe(&output_read, &output_write, &attributes, 0) == 0) {
      return false;
    }
    SetHandleInformation(output_read, HANDLE_FLAG_INHERIT, 0);

    // Standard input is the read end of a pipe the parent keeps open and never
    // writes to, so a child that waits on input waits indefinitely and is only
    // ever stopped by a real kill.
    HANDLE input_read = nullptr;
    HANDLE input_write = nullptr;
    if (CreatePipe(&input_read, &input_write, &attributes, 0) == 0) {
      CloseHandle(output_read);
      CloseHandle(output_write);
      return false;
    }
    SetHandleInformation(input_write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(output_write, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    SetHandleInformation(input_read, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);

    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = output_write;
    startup.hStdError = output_write;
    startup.hStdInput = input_read;

    const std::string application = native_path(executable);
    std::string command = quote(application);
    if (!arguments.empty()) {
      command += " ";
      command += arguments;
    }
    std::vector<char> mutable_command(command.begin(), command.end());
    mutable_command.push_back('\0');

    PROCESS_INFORMATION information{};
    const BOOL created = CreateProcessA(application.c_str(), mutable_command.data(), nullptr, nullptr,
                                        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup,
                                        &information);
    CloseHandle(output_write);
    CloseHandle(input_read);
    if (created == 0) {
      CloseHandle(output_read);
      CloseHandle(input_write);
      return false;
    }
    process_ = information.hProcess;
    CloseHandle(information.hThread);
    read_end_ = output_read;
    write_end_ = input_write;
    return true;
  }

  /// Reads one line. Returns false when the child closed its output.
  [[nodiscard]] bool read_line(std::string& out) {
    out.clear();
    for (;;) {
      const std::size_t newline = pending_.find('\n');
      if (newline != std::string::npos) {
        out = pending_.substr(0, newline);
        pending_.erase(0, newline + 1);
        if (!out.empty() && out.back() == '\r') {
          out.pop_back();
        }
        return true;
      }
      char buffer[512] = {};
      DWORD produced = 0;
      const BOOL ok = ReadFile(read_end_, buffer, sizeof(buffer), &produced, nullptr);
      if (ok == 0 || produced == 0) {
        out = pending_;
        pending_.clear();
        return !out.empty();
      }
      pending_.append(buffer, produced);
    }
  }

  /// Reads lines until one starts with the given prefix.
  [[nodiscard]] bool read_until(const std::string& prefix, std::string& out) {
    for (;;) {
      std::string line;
      if (!read_line(line)) {
        return false;
      }
      if (line.rfind(prefix, 0) == 0) {
        out = line;
        return true;
      }
    }
  }

  [[nodiscard]] bool running() const {
    if (process_ == nullptr) {
      return false;
    }
    return WaitForSingleObject(process_, 0) == WAIT_TIMEOUT;
  }

  /// Waits for natural termination. Returns the exit code.
  [[nodiscard]] int wait() {
    if (process_ == nullptr) {
      return -1;
    }
    WaitForSingleObject(process_, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(process_, &code);
    release();
    return static_cast<int>(code);
  }

  /// Hard kill: TerminateProcess, exactly as an operator would kill a worker.
  void kill() {
    if (process_ != nullptr) {
      (void)TerminateProcess(process_, 0x1);
      WaitForSingleObject(process_, INFINITE);
      release();
    }
  }

 private:
  void release() {
    if (write_end_ != nullptr) {
      CloseHandle(write_end_);
      write_end_ = nullptr;
    }
    if (read_end_ != nullptr) {
      CloseHandle(read_end_);
      read_end_ = nullptr;
    }
    if (process_ != nullptr) {
      CloseHandle(process_);
      process_ = nullptr;
    }
    pending_.clear();
  }

  HANDLE process_{nullptr};
  HANDLE read_end_{nullptr};
  HANDLE write_end_{nullptr};
  std::string pending_{};
};

class ScratchDir {
 public:
  explicit ScratchDir(const std::string& name) {
    path_ = std::filesystem::temp_directory_path() / ("crf_process_" + name);
    std::error_code error;
    std::filesystem::remove_all(path_, error);
    std::filesystem::create_directories(path_, error);
  }
  ScratchDir(const ScratchDir&) = delete;
  ScratchDir& operator=(const ScratchDir&) = delete;
  ~ScratchDir() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }
  [[nodiscard]] std::string store() const { return (path_ / "coordinator.bin").string(); }

 private:
  std::filesystem::path path_{};
};

[[nodiscard]] std::uint64_t parse_u64(const std::string& line, const std::string& key) {
  const std::size_t position = line.find(key + "=");
  if (position == std::string::npos) {
    return 0;
  }
  return std::stoull(line.substr(position + key.size() + 1));
}

#endif  // _WIN32

}  // namespace

CRF_TEST(Process, RealWorkerDeathIsDetectedAndTheBootIsFenced) {
#if defined(_WIN32)
  const std::string executable = host_executable();
  CRF_CHECK(!executable.empty());
  if (executable.empty()) {
    return;
  }
  ScratchDir scratch("worker_death");
  const std::string store = scratch.store();

  ChildProcess coordinator;
  CRF_CHECK(coordinator.start(executable, "coordinator --store=" + quote(store)));
  std::string ready;
  CRF_CHECK(coordinator.read_until("READY", ready));
  const std::uint64_t port = parse_u64(ready, "PORT");
  CRF_CHECK(port != 0);
  CRF_CHECK_EQ(parse_u64(ready, "EPOCH"), std::uint64_t{1});

  ChildProcess worker;
  CRF_CHECK(worker.start(executable,
                         "worker --port=" + std::to_string(port) + " --publisher=1 --hold"));
  std::string line;
  CRF_CHECK(worker.read_until("BOOT", line));
  const std::uint64_t fenced_boot = parse_u64(line, "BOOT");
  CRF_CHECK(fenced_boot != 0);
  CRF_CHECK(worker.read_until("PUBLISHED", line));
  CRF_CHECK(worker.read_until("RANK", line));
  CRF_CHECK_EQ(line, std::string("RANK=201"));
  CRF_CHECK(worker.read_until("COMMITTED", line));
  CRF_CHECK_EQ(line, std::string("COMMITTED=1"));
  CRF_CHECK(worker.read_until("HOLDING", line));
  CRF_CHECK(worker.running());
  // Kill the worker process outright.
  worker.kill();
  CRF_CHECK(!worker.running());

  // A fresh worker re-registers and proves the durable definitions survived the
  // death of the publisher that created them.
  ChildProcess successor;
  CRF_CHECK(successor.start(
      executable,
      "worker --port=" + std::to_string(port) + " --publisher=2 --scenario=revalidate"));
  CRF_CHECK(successor.read_until("DEFINITIONS", line));
  CRF_CHECK(line.find("STATE=Active") != std::string::npos);
  CRF_CHECK(successor.read_until("SCENARIO_OK", line));
  CRF_CHECK_EQ(successor.wait(), 0);

  // The killed worker's identity is permanently fenced: a process that tries to
  // reuse it is refused by the coordinator.
  ChildProcess impostor;
  CRF_CHECK(impostor.start(executable, "worker --port=" + std::to_string(port) +
                                            " --publisher=1 --boot=" +
                                            std::to_string(fenced_boot) + " --scenario=probe"));
  CRF_CHECK(impostor.read_until("ERROR", line));
  CRF_CHECK_EQ(impostor.wait(), 1);

  coordinator.kill();
#else
  CRF_FAIL("real-process proofs are only exercised on the validated Windows target");
#endif
}

CRF_TEST(Process, RealCoordinatorRestartPreservesDefinitionsAndAdvancesTheEpoch) {
#if defined(_WIN32)
  const std::string executable = host_executable();
  CRF_CHECK(!executable.empty());
  if (executable.empty()) {
    return;
  }
  ScratchDir scratch("coordinator_restart");
  const std::string store = scratch.store();

  std::string first_digest;
  std::uint64_t first_boot = 0;
  std::uint64_t port = 0;
  {
    ChildProcess coordinator;
    CRF_CHECK(coordinator.start(executable, "coordinator --store=" + quote(store)));
    std::string ready;
    if (!coordinator.read_until("READY", ready)) {
      std::string diagnostic;
      while (coordinator.read_line(diagnostic)) {
        std::fprintf(stderr, "coordinator diagnostic: %s\n", diagnostic.c_str());
      }
      CRF_FAIL("the coordinator did not report readiness");
      return;
    }
    port = parse_u64(ready, "PORT");
    CRF_CHECK_EQ(parse_u64(ready, "EPOCH"), std::uint64_t{1});

    ChildProcess worker;
    CRF_CHECK(worker.start(executable,
                           "worker --port=" + std::to_string(port) + " --publisher=1"));
    std::string line;
    CRF_CHECK(worker.read_until("BOOT", line));
    first_boot = parse_u64(line, "BOOT");
    CRF_CHECK(worker.read_until("PUBLISHED", line));
    first_digest = line.substr(line.find("DIGEST=") + 7);
    CRF_CHECK(worker.read_until("RANK", line));
    CRF_CHECK_EQ(line, std::string("RANK=201"));
    CRF_CHECK_EQ(worker.wait(), 0);

    // Hard kill the coordinator: no orderly shutdown, no flush on exit.
    coordinator.kill();
  }

  // Restart on the same store: the epoch advances and nothing is restored as
  // live authority.
  ChildProcess restarted;
  CRF_CHECK(restarted.start(executable, "coordinator --store=" + quote(store)));
  std::string ready;
  const bool restarted_ready = restarted.read_until("READY", ready);
  if (!restarted_ready) {
    // Report the child's own words rather than a bare assertion failure.
    std::string diagnostic;
    while (restarted.read_line(diagnostic)) {
      std::fprintf(stderr, "restart diagnostic: %s\n", diagnostic.c_str());
    }
    CRF_FAIL("the restarted coordinator did not report readiness");
    return;
  }
  const std::uint64_t second_port = parse_u64(ready, "PORT");
  CRF_CHECK(second_port != 0);
  CRF_CHECK_EQ(parse_u64(ready, "EPOCH"), std::uint64_t{2});

  ChildProcess worker;
  CRF_CHECK(worker.start(
      executable,
      "worker --port=" + std::to_string(second_port) + " --publisher=3 --scenario=revalidate"));
  std::string line;
  CRF_CHECK(worker.read_until("DEFINITIONS", line));
  CRF_CHECK_EQ(line.substr(line.find("DIGEST=") + 7), first_digest);
  CRF_CHECK(line.find("STATE=Active") != std::string::npos);
  // Definitions are restored conservatively: no result is current yet.
  CRF_CHECK(worker.read_until("RECOVERED", line));
  CRF_CHECK_EQ(parse_u64(line, "CURRENT"), std::uint64_t{0});
  CRF_CHECK(worker.read_until("RESULT", line));
  CRF_CHECK(worker.read_until("SCENARIO_OK", line));
  CRF_CHECK_EQ(worker.wait(), 0);

  // The boot from the previous coordinator incarnation can never register again.
  ChildProcess impostor;
  CRF_CHECK(impostor.start(executable, "worker --port=" + std::to_string(second_port) +
                                            " --publisher=1 --boot=" +
                                            std::to_string(first_boot) + " --scenario=probe"));
  CRF_CHECK(impostor.read_until("ERROR", line));
  CRF_CHECK_EQ(impostor.wait(), 1);

  // A second restart still advances the epoch monotonically.
  restarted.kill();
  ChildProcess third;
  CRF_CHECK(third.start(executable, "coordinator --store=" + quote(store)));
  CRF_CHECK(third.read_until("READY", line));
  CRF_CHECK_EQ(parse_u64(line, "EPOCH"), std::uint64_t{3});
  third.kill();
#else
  CRF_FAIL("real-process proofs are only exercised on the validated Windows target");
#endif
}
