/* ISM43362 implementation of NetworkInterfaceAPI
 * Copyright (c) STMicroelectronics 2017
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <string.h>
#include "ISM43362Interface.h"
#include "mbed_debug.h"

// ao activate  / de-activate debug
#define ism_debug false

// Various timeouts for different ISM43362 operations
#define ISM43362_CONNECT_TIMEOUT 15000 /* milliseconds */
#define ISM43362_SEND_TIMEOUT    1000   /* milliseconds */
#define ISM43362_RECV_TIMEOUT    100   /* milliseconds */
#define ISM43362_MISC_TIMEOUT    100   /* milliseconds */

// Tested firmware versions
// Example of versions string returned by the module:
// "ISM43362-M3G-L44-SPI,C3.5.2.3.BETA9,v3.5.2,v1.4.0.rc1,v8.2.1,120000000,Inventek eS-WiFi"
// "ISM43362-M3G-L44-SPI,C3.5.2.2,v3.5.2,v1.4.0.rc1,v8.2.1,120000000,Inventek eS-WiFi"
// Only the first version is checked !
const char supported_fw_versions[2][15] = {"C3.5.2.3.BETA9", "C3.5.2.2"};

#define MIN(a,b) (((a)<(b))?(a):(b))

// ISM43362Interface implementation
ISM43362Interface::ISM43362Interface(PinName mosi, PinName miso, PinName sclk, PinName nss, PinName reset, PinName datareadypin, PinName wakeup, bool debug)
    : _ism(mosi, miso, sclk, nss, reset, datareadypin, wakeup, debug)
{
    memset(_ids, 0, sizeof(_ids));
    memset(_socket_obj, 0, sizeof(_socket_obj));
    memset(_cbs, 0, sizeof(_cbs));
    thread_read_socket.start(callback(this, &ISM43362Interface::socket_check_read));
}

int ISM43362Interface::connect(const char *ssid, const char *pass, nsapi_security_t security,
                                        uint8_t channel)
{
    if (channel != 0) {
        return NSAPI_ERROR_UNSUPPORTED;
    }

    set_credentials(ssid, pass, security);
    return connect();
}

int ISM43362Interface::connect()
{
    const char* read_version;

    _ism.setTimeout(ISM43362_MISC_TIMEOUT);

    // Check all supported firmware versions
    read_version = _ism.get_firmware_version();

    if (!read_version) {
        debug_if(ism_debug, "ISM43362: ERROR cannot read firmware version\r\n");
        return NSAPI_ERROR_DEVICE_ERROR;
    }
    debug_if(ism_debug, "ISM43362: read_version = [%s]\r\n", read_version);

    if ((strcmp(read_version, supported_fw_versions[0]) == 0) || (strcmp(read_version, supported_fw_versions[1]) == 0)) {
        debug_if(ism_debug, "ISM43362: firmware version is OK\r\n");
    } else {
        debug_if(ism_debug, "ISM43362: WARNING this firmware version has not been tested !\r\n");
    }

    if (!_ism.dhcp(true)) {
        return NSAPI_ERROR_DHCP_FAILURE;
    }

    _ism.setTimeout(ISM43362_CONNECT_TIMEOUT);

    if (!_ism.connect(ap_ssid, ap_pass)) {
        return NSAPI_ERROR_NO_CONNECTION;
    }

    _ism.setTimeout(ISM43362_MISC_TIMEOUT);
    if (!_ism.getIPAddress()) {
        return NSAPI_ERROR_DHCP_FAILURE;
    }

    _ism.setTimeout(ISM43362_MISC_TIMEOUT);

    return NSAPI_ERROR_OK;
}

nsapi_error_t ISM43362Interface::gethostbyname(const char *name, SocketAddress *address, nsapi_version_t version)
{
    if (address->set_ip_address(name)) {
        if (version != NSAPI_UNSPEC && address->get_ip_version() != version) {
            return NSAPI_ERROR_DNS_FAILURE;
        }

        return NSAPI_ERROR_OK;
    }
    
    char *ipbuff = new char[NSAPI_IP_SIZE];
    int ret = 0;
    
    if(!_ism.dns_lookup(name, ipbuff)) {
        ret = NSAPI_ERROR_DEVICE_ERROR;
    } else {
        address->set_ip_address(ipbuff);
    }

    delete[] ipbuff;
    return ret;
}

int ISM43362Interface::set_credentials(const char *ssid, const char *pass, nsapi_security_t security)
{
    memset(ap_ssid, 0, sizeof(ap_ssid));
    strncpy(ap_ssid, ssid, sizeof(ap_ssid));

    memset(ap_pass, 0, sizeof(ap_pass));
    strncpy(ap_pass, pass, sizeof(ap_pass));

    ap_sec = security;

    return 0;
}

int ISM43362Interface::set_channel(uint8_t channel)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int ISM43362Interface::disconnect()
{
    _ism.setTimeout(ISM43362_MISC_TIMEOUT);

    if (!_ism.disconnect()) {
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    return NSAPI_ERROR_OK;
}

const char *ISM43362Interface::get_ip_address()
{
    return _ism.getIPAddress();
}

const char *ISM43362Interface::get_mac_address()
{
    return _ism.getMACAddress();
}

const char *ISM43362Interface::get_gateway()
{
    return _ism.getGateway();
}

const char *ISM43362Interface::get_netmask()
{
    return _ism.getNetmask();
}

int8_t ISM43362Interface::get_rssi()
{
    return _ism.getRSSI();
}

int ISM43362Interface::scan(WiFiAccessPoint *res, unsigned count)
{
    _ism.setTimeout(ISM43362_CONNECT_TIMEOUT);
    return _ism.scan(res, count);
}

struct ISM43362_socket {
    int id;
    nsapi_protocol_t proto;
    volatile bool connected;
    SocketAddress addr;
    char read_data[1400];
    volatile uint32_t read_data_size;
};

int ISM43362Interface::socket_open(void **handle, nsapi_protocol_t proto)
{
    // Look for an unused socket
    int id = -1;
    for (int i = 0; i < ISM43362_SOCKET_COUNT; i++) {
        if (!_ids[i]) {
            id = i;
            _ids[i] = true;
            break;
        }
    }

    if (id == -1) {
        return NSAPI_ERROR_NO_SOCKET;
    }
    _mutex.lock();
    struct ISM43362_socket *socket = new struct ISM43362_socket;
    if (!socket) {
        return NSAPI_ERROR_NO_SOCKET;
    }
    socket->id = id;
    debug_if(ism_debug, "socket_open, id=%d", socket->id);
    memset(socket->read_data, 0, sizeof(socket->read_data));
    socket->addr = 0;
    socket->read_data_size = 0;
    socket->proto = proto;
    socket->connected = false;
    *handle = socket;
    _mutex.unlock();

    return 0;
}

int ISM43362Interface::socket_close(void *handle)
{
    _mutex.lock();
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;
    debug_if(ism_debug, "socket_close, id=%d", socket->id);
    int err = 0;
    _ism.setTimeout(ISM43362_MISC_TIMEOUT);
 
    if (!_ism.close(socket->id)) {
        err = NSAPI_ERROR_DEVICE_ERROR;
    }

    socket->connected = false;
    _ids[socket->id] = false;
    _socket_obj[socket->id] = 0;
    _mutex.unlock();
    delete socket;
    return err;
}

int ISM43362Interface::socket_bind(void *handle, const SocketAddress &address)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int ISM43362Interface::socket_listen(void *handle, int backlog)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int ISM43362Interface::socket_connect(void *handle, const SocketAddress &addr)
{
    _mutex.lock();
    int ret = socket_connect_nolock(handle, addr);
    _mutex.unlock();
    return ret;
}

int ISM43362Interface::socket_connect_nolock(void *handle, const SocketAddress &addr)
{
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;
    _ism.setTimeout(ISM43362_CONNECT_TIMEOUT);
    const char *proto = (socket->proto == NSAPI_UDP) ? "1" : "0";
    if (!_ism.open(proto, socket->id, addr.get_ip_address(), addr.get_port())) {
        return NSAPI_ERROR_DEVICE_ERROR;
    }
    _ids[socket->id]  = true;
    _socket_obj[socket->id] = (uint32_t)socket;
    socket->connected = true;
    return 0;

}



void ISM43362Interface::socket_check_read()
{
    while (1) {
        for (int i = 0; i < ISM43362_SOCKET_COUNT; i++) {
            _mutex.lock();
            if (_socket_obj[i] != 0) {
                struct ISM43362_socket *socket = (struct ISM43362_socket *)_socket_obj[i];
                /* Check if there is something to read for this socket. But if it */
                /* has already been read : don't read again */
                if ((socket->connected) && (socket->read_data_size == 0) && _cbs[socket->id].callback) {
                    _ism.setTimeout(1);
                    /* if no callback is set, no need to read ?*/
                    int read_amount = _ism.check_recv_status(socket->id, socket->read_data);
                    if (read_amount > 0) {
                        socket->read_data_size = read_amount;
                    } else if (read_amount < 0) {
                        /* Mark donw connection has been lost or closed */
                        socket->connected = false;
                    }
                    if (read_amount != 0) {
                        /* There is something to read in this socket*/
                        if (_cbs[socket->id].callback) {
                            _cbs[socket->id].callback(_cbs[socket->id].data);
                       }
                    }
                }
            }
            _mutex.unlock();
        }
        wait_ms(50);
    }
}

int ISM43362Interface::socket_accept(void *server, void **socket, SocketAddress *addr)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int ISM43362Interface::socket_send(void *handle, const void *data, unsigned size)
{
    _mutex.lock();
    int ret = socket_send_nolock(handle, data, size);
    _mutex.unlock();
    return ret;
}

/*  CAREFULL LOCK must be taken before callling this function */
int ISM43362Interface::socket_send_nolock(void *handle, const void *data, unsigned size)
{
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;
    _ism.setTimeout(ISM43362_SEND_TIMEOUT);

    if (size > ES_WIFI_MAX_RX_PACKET_SIZE) {
        size = ES_WIFI_MAX_RX_PACKET_SIZE;
    }

    if (!_ism.send(socket->id, data, size)) {
        debug_if(ism_debug, "socket_send ERROR\r\n");
        return NSAPI_ERROR_DEVICE_ERROR; // or WOULD_BLOCK ?
    }

    return size;
}

int ISM43362Interface::socket_recv(void *handle, void *data, unsigned size)
{
    _mutex.lock();
    unsigned recv = 0;
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;
    char *ptr = (char *)data;

    debug_if(ism_debug, "[socket_recv] req=%d\r\n", size);

    if (!socket->connected) {
        _mutex.unlock();
        return NSAPI_ERROR_CONNECTION_LOST;
    }

    _ism.setTimeout(ISM43362_RECV_TIMEOUT);

    if (socket->read_data_size == 0) {
        /* if no callback is set, no need to read ?*/
        int read_amount = _ism.check_recv_status(socket->id, socket->read_data);
        if (read_amount > 0) {
            socket->read_data_size = read_amount;
        } else if (read_amount < 0) {
            socket->connected = false;
            _mutex.unlock();
            return NSAPI_ERROR_CONNECTION_LOST;
        }
    }

    if (socket->read_data_size != 0) {
        debug_if(ism_debug, "read_data_size=%d\r\n", socket->read_data_size);
        uint32_t i=0;
        while ((i < socket->read_data_size) && (i < size)) {
            *ptr++ = socket->read_data[i];
            i++;
        }

        debug_if(ism_debug, "Copied i bytes=%d, vs %d requestd\r\n", i, size);
        recv += i;

        if (i >= socket->read_data_size) {
            /* All the storeed data has been read, reset buffer */
            memset(socket->read_data, 0, sizeof(socket->read_data));
            socket->read_data_size = 0;
            debug_if(ism_debug, "Socket_recv buffer reset\r\n");
        } else {
            /*  In case there is remaining data in buffer, update socket content
             *  For now by shift copy of all data (not very efficient to be
             *  revised */
            while (i < socket->read_data_size) {
                socket->read_data[i - size] = socket->read_data[i];
                i++;
            }

            socket->read_data_size -= size;
        }
    } else {
        debug_if(ism_debug, "Nothing in buffer\r\n");
    }

    debug_if(ism_debug, "[socket_recv]read_datasize=%d, recv=%d\r\n", socket->read_data_size, recv);
    _mutex.unlock();

    if (recv > 0) {
        return recv;
    } else {
        debug_if(ism_debug, "sock_recv returns WOULD BLOCK\r\n");
        return NSAPI_ERROR_WOULD_BLOCK;
    }
}

int ISM43362Interface::socket_sendto(void *handle, const SocketAddress &addr, const void *data, unsigned size)
{
    _mutex.lock();
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;

    if (socket->connected && socket->addr != addr) {
        _ism.setTimeout(ISM43362_MISC_TIMEOUT);
        if (!_ism.close(socket->id)) {
            debug_if(ism_debug, "socket_send ERROR\r\n");
            _mutex.unlock();
            return NSAPI_ERROR_DEVICE_ERROR;
        }
        socket->connected = false;
        _ids[socket->id] = false;
        _socket_obj[socket->id] = 0;
    }

    if (!socket->connected) {
        int err = socket_connect_nolock(socket, addr);
        if (err < 0) {
            _mutex.unlock();
            return err;
        }
        socket->addr = addr;
    }

    int ret = socket_send_nolock(socket, data, size);

    _mutex.unlock();

    return ret;
}

int ISM43362Interface::socket_recvfrom(void *handle, SocketAddress *addr, void *data, unsigned size)
{
    int ret = socket_recv(handle, data, size);
    _mutex.lock();
    if ((ret >= 0) && addr) {
        struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;
        *addr = socket->addr;
    }
    _mutex.unlock();
    return ret;
}

void ISM43362Interface::socket_attach(void *handle, void (*cb)(void *), void *data)
{
    _mutex.lock();
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;
    _cbs[socket->id].callback = cb;
    _cbs[socket->id].data = data;
    _mutex.unlock();
}

void ISM43362Interface::event() {
    for (int i = 0; i < ISM43362_SOCKET_COUNT; i++) {
        if (_cbs[i].callback) {
            _cbs[i].callback(_cbs[i].data);
        }
    }
}
