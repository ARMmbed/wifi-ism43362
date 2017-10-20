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

// Various timeouts for different ISM43362 operations
#define ISM43362_CONNECT_TIMEOUT 15000 /* milliseconds */
#define ISM43362_SEND_TIMEOUT    500   /* milliseconds */
#define ISM43362_RECV_TIMEOUT    500   /* milliseconds */
#define ISM43362_MISC_TIMEOUT    500   /* milliseconds */

// Firmware version
#define ISM43362_VERSION 35239 /*C3.5.2.3BETA9 */

// ISM43362Interface implementation
ISM43362Interface::ISM43362Interface(PinName mosi, PinName miso, PinName sclk, PinName nss, PinName reset, PinName datareadypin, PinName wakeup, bool debug)
    : _ism(mosi, miso, sclk, nss, reset, datareadypin, wakeup, debug)
{
    memset(_ids, 0, sizeof(_ids));
    memset(_cbs, 0, sizeof(_cbs));

    _ism.attach(this, &ISM43362Interface::event); // not applicable in SPI ? to be removed ?
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
    _ism.setTimeout(ISM43362_MISC_TIMEOUT);
    
    if (_ism.get_firmware_version() != ISM43362_VERSION) {
        debug("ISM43362: ERROR: Firmware incompatible with this driver.\
               \r\nUpdate to C3.5.2.3BETA9 - https://developer.mbed.org/teams/ISM43362/wiki/Firmware-Update\r\n");  // TODO change the link
        return NSAPI_ERROR_DEVICE_ERROR;
    }
    
    _ism.setTimeout(ISM43362_CONNECT_TIMEOUT);

    /* don't see the related mode in Inventek specification : remove for the moment*/
  //  if (!_ism.startup(3)) {
  //      return NSAPI_ERROR_DEVICE_ERROR;
  //  }

    if (!_ism.dhcp(true)) {
        return NSAPI_ERROR_DHCP_FAILURE;
    }

    if (!_ism.connect(ap_ssid, ap_pass)) {
        return NSAPI_ERROR_NO_CONNECTION;
    }

    if (!_ism.getIPAddress()) {
        return NSAPI_ERROR_DHCP_FAILURE;
    }

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
    return _ism.scan(res, count);
}

struct ISM43362_socket {
    int id;
    nsapi_protocol_t proto;
    bool connected;
    SocketAddress addr;
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
    
    struct ISM43362_socket *socket = new struct ISM43362_socket;
    if (!socket) {
        return NSAPI_ERROR_NO_SOCKET;
    }
    
    socket->id = id;
    socket->proto = proto;
    socket->connected = false;
    *handle = socket;
    return 0;
}

int ISM43362Interface::socket_close(void *handle)
{
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;
    int err = 0;
    _ism.setTimeout(ISM43362_MISC_TIMEOUT);
 
    if (socket->connected && !_ism.close(socket->id)) {
        err = NSAPI_ERROR_DEVICE_ERROR;
    }

    socket->connected = false;
    _ids[socket->id] = false;
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
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;
    _ism.setTimeout(ISM43362_MISC_TIMEOUT);

    const char *proto = (socket->proto == NSAPI_UDP) ? "1" : "0";
    if (!_ism.open(proto, socket->id, addr.get_ip_address(), addr.get_port())) {
        return NSAPI_ERROR_DEVICE_ERROR;
    }
    
    socket->connected = true;
    return 0;
}
    
int ISM43362Interface::socket_accept(void *server, void **socket, SocketAddress *addr)
{
    return NSAPI_ERROR_UNSUPPORTED;
}

int ISM43362Interface::socket_send(void *handle, const void *data, unsigned size)
{
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;
    _ism.setTimeout(ISM43362_SEND_TIMEOUT);
 
    if (!_ism.send(socket->id, data, size)) {
        return NSAPI_ERROR_DEVICE_ERROR;
    }
 
    return size;
}

int ISM43362Interface::socket_recv(void *handle, void *data, unsigned size)
{
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;
    _ism.setTimeout(ISM43362_RECV_TIMEOUT);
 
    int32_t recv = _ism.recv(socket->id, data, size);
    if (recv < 0) {
        return NSAPI_ERROR_WOULD_BLOCK;
    }
 
    return recv;
}

int ISM43362Interface::socket_sendto(void *handle, const SocketAddress &addr, const void *data, unsigned size)
{
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;

    if (socket->connected && socket->addr != addr) {
        _ism.setTimeout(ISM43362_MISC_TIMEOUT);
        if (!_ism.close(socket->id)) {
            return NSAPI_ERROR_DEVICE_ERROR;
        }
        socket->connected = false;
    }

    if (!socket->connected) {
        int err = socket_connect(socket, addr);
        if (err < 0) {
            return err;
        }
        socket->addr = addr;
    }
    
    return socket_send(socket, data, size);
}

int ISM43362Interface::socket_recvfrom(void *handle, SocketAddress *addr, void *data, unsigned size)
{
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;
    int ret = socket_recv(socket, data, size);
    if (ret >= 0 && addr) {
        *addr = socket->addr;
    }

    return ret;
}

void ISM43362Interface::socket_attach(void *handle, void (*callback)(void *), void *data)
{
    struct ISM43362_socket *socket = (struct ISM43362_socket *)handle;    
    _cbs[socket->id].callback = callback;
    _cbs[socket->id].data = data;
}

void ISM43362Interface::event() {
    for (int i = 0; i < ISM43362_SOCKET_COUNT; i++) {
        if (_cbs[i].callback) {
            _cbs[i].callback(_cbs[i].data);
        }
    }
}
