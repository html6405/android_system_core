/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "uevent_listener.h"

#include <fcntl.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

#include <memory>

#include <android-base/logging.h>
#include <cutils/uevent.h>

namespace android {
namespace init {
static int crash_counter = 0;

static void ParseEvent(const char* msg, Uevent* uevent) {
    constexpr int kMaxTokens = 64;
    int token_count = 0;

    uevent->partition_num = -1;
    uevent->major = -1;
    uevent->minor = -1;
    uevent->action.clear();
    uevent->path.clear();
    uevent->subsystem.clear();
    uevent->firmware.clear();
    uevent->partition_name.clear();
    uevent->device_name.clear();
    uevent->modalias.clear();

    while (*msg && token_count++ < kMaxTokens) {
        LOG(ERROR) << "[UEVENTD] token = " << msg;

        if (!strncmp(msg, "ACTION=", 7)) {
            msg += 7;
            uevent->action = msg;
            LOG(ERROR) << "[UEVENTD] ACTION = " << uevent->action;
        } else if (!strncmp(msg, "DEVPATH=", 8)) {
            msg += 8;
            uevent->path = msg;
            LOG(ERROR) << "[UEVENTD] DEVPATH = " << uevent->path;
        } else if (!strncmp(msg, "SUBSYSTEM=", 10)) {
            msg += 10;
            uevent->subsystem = msg;
            LOG(ERROR) << "[UEVENTD] SUBSYSTEM = " << uevent->subsystem;
        } else if (!strncmp(msg, "FIRMWARE=", 9)) {
            msg += 9;
            uevent->firmware = msg;
            LOG(ERROR) << "[UEVENTD] FIRMWARE = " << uevent->firmware;
        } else if (!strncmp(msg, "MAJOR=", 6)) {
            msg += 6;
            char* end;
            long val = strtol(msg, &end, 10);
            if (*end == '\0') {
                uevent->major = static_cast<int>(val);
            } else {
                LOG(ERROR) << "[UEVENTD] Invalid MAJOR field: " << msg;
            }
        } else if (!strncmp(msg, "MINOR=", 6)) {
            msg += 6;
            char* end;
            long val = strtol(msg, &end, 10);
            if (*end == '\0') {
                uevent->minor = static_cast<int>(val);
            } else {
                LOG(ERROR) << "[UEVENTD] Invalid MINOR field: " << msg;
            }
        } else if (!strncmp(msg, "PARTN=", 6)) {
            msg += 6;
            char* end;
            long val = strtol(msg, &end, 10);
            if (*end == '\0') {
                uevent->partition_num = static_cast<int>(val);
            } else {
                LOG(ERROR) << "[UEVENTD] Invalid PARTN field: " << msg;
            }
        } else if (!strncmp(msg, "PARTNAME=", 9)) {
            msg += 9;
            uevent->partition_name = msg;
        } else if (!strncmp(msg, "DEVNAME=", 8)) {
            msg += 8;
            uevent->device_name = msg;
        } else if (!strncmp(msg, "MODALIAS=", 9)) {
            msg += 9;
            uevent->modalias = msg;
            LOG(ERROR) << "[UEVENTD] MODALIAS = " << uevent->modalias;
        } else {
            LOG(ERROR) << "[UEVENTD] Unknown field = " << msg;
        }

        while (*msg++)
            ;
    }

    if (token_count >= kMaxTokens) {
        LOG(ERROR) << "[UEVENTD] Exceeded token limit (" << kMaxTokens << "), aborting";
    }

    if (LOG_UEVENTS) {
        LOG(INFO) << "event { '" << uevent->action << "', '" << uevent->path << "', '"
                  << uevent->subsystem << "', '" << uevent->firmware << "', " << uevent->major
                  << ", " << uevent->minor << " }";
    }
}

UeventListener::UeventListener(size_t uevent_socket_rcvbuf_size) {
    device_fd_.reset(uevent_open_socket(uevent_socket_rcvbuf_size, true));
    if (device_fd_ == -1) {
        LOG(FATAL) << "Could not open uevent socket";
    }

    fcntl(device_fd_.get(), F_SETFL, O_NONBLOCK);
}

ReadUeventResult UeventListener::ReadUevent(Uevent* uevent) const {
    char filename[PATH_MAX];

    snprintf(filename, sizeof(filename),
             "/data/local/tmp/uevent_dump_%d.bin", crash_counter++);

    if (uevent == nullptr) {
        LOG(ERROR) << "[UEVENTD] uevent pointer is null (CRITICAL)";
        return ReadUeventResult::kFailed;
    }

    char msg[UEVENT_MSG_LEN + 2] = {0};
    int n = uevent_kernel_multicast_recv(device_fd_.get(), msg, UEVENT_MSG_LEN);

    if (n <= 0) {
        PLOG(ERROR) << "[UEVENTD] Invalid uevent length from kernel: " << n;
        return ReadUeventResult::kFailed;
    }

    if (n >= UEVENT_MSG_LEN) {
        LOG(ERROR) << "[UEVENTD] Uevent overflowed buffer, discarding (" << n << " bytes)";
        return ReadUeventResult::kInvalid;
    }

    msg[n] = '\0';
    msg[n + 1] = '\0';

    // Dump raw message to file for binary analysis
    if (n > 0 && n < UEVENT_MSG_LEN) {
        int fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0644);
        if (fd >= 0) {
            write(fd, msg, n);
            close(fd);
        } else {
            PLOG(ERROR) << "[UEVENTD] Failed to write raw uevent to /data/anr/uevent_raw.bin";
        }
    }

    LOG(ERROR) << "[UEVENTD] Calling ParseEvent...";
    ParseEvent(msg, uevent);
    LOG(ERROR) << "[UEVENTD] ParseEvent completed";

    return ReadUeventResult::kSuccess;
}

// RegenerateUevents*() walks parts of the /sys tree and pokes the uevent files to cause the kernel
// to regenerate device add uevents that have already happened.  This is particularly useful when
// starting ueventd, to regenerate all of the uevents that it had previously missed.
//
// We drain any pending events from the netlink socket every time we poke another uevent file to
// make sure we don't overrun the socket's buffer.
//

ListenerAction UeventListener::RegenerateUeventsForDir(DIR* d,
                                                       const ListenerCallback& callback) const {
    int dfd = dirfd(d);

    int fd = openat(dfd, "uevent", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        write(fd, "add\n", 4);
        close(fd);

        Uevent uevent;
        ReadUeventResult result;
        while ((result = ReadUevent(&uevent)) != ReadUeventResult::kFailed) {
            // Skip processing the uevent if it is invalid.
            if (result == ReadUeventResult::kInvalid) continue;
            if (callback(uevent) == ListenerAction::kStop) return ListenerAction::kStop;
        }
    }

    dirent* de;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_type != DT_DIR || de->d_name[0] == '.') continue;

        fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) continue;

        std::unique_ptr<DIR, decltype(&closedir)> d2(fdopendir(fd), closedir);
        if (d2 == 0) {
            close(fd);
        } else {
            if (RegenerateUeventsForDir(d2.get(), callback) == ListenerAction::kStop) {
                return ListenerAction::kStop;
            }
        }
    }

    // default is always to continue looking for uevents
    return ListenerAction::kContinue;
}

ListenerAction UeventListener::RegenerateUeventsForPath(const std::string& path,
                                                        const ListenerCallback& callback) const {
    std::unique_ptr<DIR, decltype(&closedir)> d(opendir(path.c_str()), closedir);
    if (!d) return ListenerAction::kContinue;

    return RegenerateUeventsForDir(d.get(), callback);
}

static const char* kRegenerationPaths[] = {"/sys/devices"};

void UeventListener::RegenerateUevents(const ListenerCallback& callback) const {
    for (const auto path : kRegenerationPaths) {
        if (RegenerateUeventsForPath(path, callback) == ListenerAction::kStop) return;
    }
}

void UeventListener::Poll(const ListenerCallback& callback,
                          const std::optional<std::chrono::milliseconds> relative_timeout) const {
    using namespace std::chrono;

    pollfd ufd = {
            .events = POLLIN,
            .fd = device_fd_.get(),
    };

    auto start_time = steady_clock::now();

    while (true) {
        ufd.revents = 0;

        int timeout_ms = -1;
        if (relative_timeout) {
            auto now = steady_clock::now();
            auto time_elapsed = duration_cast<milliseconds>(now - start_time);
            if (time_elapsed > *relative_timeout) return;

            auto remaining_timeout = *relative_timeout - time_elapsed;
            timeout_ms = remaining_timeout.count();
        }

        int nr = poll(&ufd, 1, timeout_ms);
        if (nr == 0) return;
        if (nr < 0) {
            PLOG(ERROR) << "poll() of uevent socket failed, continuing";
            continue;
        }
        if (ufd.revents & POLLIN) {
            // We're non-blocking, so if we receive a poll event keep processing until
            // we have exhausted all uevent messages.
            Uevent uevent;
            ReadUeventResult result;
            while ((result = ReadUevent(&uevent)) != ReadUeventResult::kFailed) {
                // Skip processing the uevent if it is invalid.
                if (result == ReadUeventResult::kInvalid) continue;
                if (callback(uevent) == ListenerAction::kStop) return;
            }
        }
    }
}

}  // namespace init
}  // namespace android
