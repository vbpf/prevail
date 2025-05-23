// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <map>
#include <string>

#include "crab_utils/lazy_allocator.hpp"

namespace prevail {

class Stopwatch {
    long started;
    long finished;
    long timeElapsed;

    long systemTime() const;

  public:
    Stopwatch();
    void start();
    void stop();
    void resume();
    long getTimeElapsed() const;
    void Print(std::ostream& out) const;
    double toSeconds() const;
};

inline std::ostream& operator<<(std::ostream& OS, const Stopwatch& sw) {
    sw.Print(OS);
    return OS;
}

class CrabStats {
    /// Controls whether statistics collection is active.
    /// When false, all statistics methods become no-ops for better performance.
    static constexpr bool enabled = false;
    static thread_local LazyAllocator<std::map<std::string, unsigned>> counters;
    static thread_local LazyAllocator<std::map<std::string, Stopwatch>> sw;

  public:
    static void clear_thread_local_state();

    static void reset();

    /* counters */
    static unsigned get(const std::string& n);
    static unsigned uset(const std::string& n, unsigned v);
    static void count(const std::string& name) {
        if constexpr (enabled) {
            ++(*counters)[name];
        }
    }
    static void count_max(const std::string& name, unsigned v);

    /* stop watch */
    static void start(const std::string& name) {
        if constexpr (enabled) {
            (*sw)[name].start();
        }
    }
    static void stop(const std::string& name) {
        if constexpr (enabled) {
            (*sw)[name].stop();
        }
    }
    static void resume(const std::string& name) {
        if constexpr (enabled) {
            (*sw)[name].resume();
        }
    }

    /** Outputs all statistics to std output */
    static void Print(std::ostream& OS);
    static void PrintBrunch(std::ostream& OS);
};

class ScopedCrabStats {
    std::string m_name;

  public:
    explicit ScopedCrabStats(const std::string& name, bool reset = false);
    ~ScopedCrabStats();
};
} // namespace prevail
