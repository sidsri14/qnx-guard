/*
 * Sample QNX 8.0 Neutrino Service with IPC safety issues detected by qnx-guard.
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/neutrino.h>
#include <sys/iofunc.h>

#define SENSOR_PULSE_CODE -1  // QNX002: Negative pulse code collides with kernel-reserved pulses

int start_telemetry_client(int coid) {
    char send_buf[64] = "STATUS_QUERY";
    char reply_buf[64];

    // QNX001: Synchronous MsgSend without TimerTimeout guard
    int status = MsgSend(coid, send_buf, sizeof(send_buf), reply_buf, sizeof(reply_buf));
    return status;
}

int create_dispatch_channel() {
    // QNX003: ChannelCreate with 0 flags risks priority inversion
    int chid = ChannelCreate(0);
    return chid;
}

int handle_incoming(int chid) {
    char buf[128];
    // QNX006: Unchecked MsgReceive buffer without rcvid == 0 pulse handler
    int rcvid = MsgReceive(chid, buf, sizeof(buf), NULL);
    return rcvid;
}
