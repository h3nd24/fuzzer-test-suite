/*
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


#define LIBSSH_STATIC 1
#include <libssh/libssh.h>
#include <libssh/server.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int socket_fds[2];
    int res = socketpair(AF_UNIX, SOCK_STREAM, 0, socket_fds);
    assert(res >= 0);
    ssize_t send_res = send(socket_fds[1], data, size, 0);
    assert(send_res == size);
    res = shutdown(socket_fds[1], SHUT_WR);
    assert(res == 0);

    ssh_bind sshbind = ssh_bind_new();
    ssh_session session = ssh_new();

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "pem.key");

    res = ssh_bind_accept_fd(sshbind, session, socket_fds[0]);
    assert(res == SSH_OK);

    if (ssh_handle_key_exchange(session) == SSH_OK) {
        while (true) {
            ssh_message message = ssh_message_get(session);
            if (!message) {
                break;
            }
            ssh_message_free(message);
        }
    }

    close(socket_fds[0]);
    close(socket_fds[1]);

    ssh_disconnect(session);
    ssh_free(session);
    ssh_bind_free(sshbind);

    return 0;
}
