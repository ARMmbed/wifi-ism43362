/* ISM43362 Example
*
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
#include "ISM43362.h"
#include "mbed_debug.h"

// ao activate  / de-activate debug
#define ism_debug false

ISM43362::ISM43362(PinName mosi, PinName miso, PinName sclk, PinName nss, PinName resetpin, PinName datareadypin, PinName wakeup, bool debug)
    : _bufferspi(mosi, miso, sclk, nss, datareadypin), _parser(_bufferspi), _resetpin(resetpin),
      _packets(0), _packets_end(&_packets)
{
    DigitalOut wakeup_pin(wakeup);
    ISM43362::setTimeout((uint32_t)5000);
    _bufferspi.format(16, 0); /* 16bits, ploarity low, phase 1Edge, master mode */
    _bufferspi.frequency(10000000); /* up to 20 MHz */
    _active_id = 0xFF;

    reset();

    _parser.debugOn(debug);
}

/**
  * @brief  Parses and returns number from string.
  * @param  ptr: pointer to string
  * @param  cnt: pointer to the number of parsed digit
  * @retval integer value.
  */
#define CHARISHEXNUM(x)                 (((x) >= '0' && (x) <= '9') || \
                                         ((x) >= 'a' && (x) <= 'f') || \
                                         ((x) >= 'A' && (x) <= 'F'))
#define CHARISNUM(x)                    ((x) >= '0' && (x) <= '9')
#define CHAR2NUM(x)                     ((x) - '0')


extern "C" int32_t ParseNumber(char* ptr, uint8_t* cnt) 
{
    uint8_t minus = 0, i = 0;
    int32_t sum = 0;
    
    if (*ptr == '-') {                                		/* Check for minus character */
        minus = 1;
        ptr++;
        i++;
    }
    while (CHARISNUM(*ptr) || (*ptr=='.')) {   /* Parse number */
        if (*ptr == '.') {
            ptr++; // next char
        } else {
            sum = 10 * sum + CHAR2NUM(*ptr);
            ptr++;
            i++;
        }
    }

    if (cnt != NULL) {                   /* Save number of characters used for number */
        *cnt = i;
    }
    if (minus) {                         /* Minus detected */
        return 0 - sum;
    }
    return sum;                          /* Return number */
}

const char *ISM43362::get_firmware_version(void)
{
    char tmp_buffer[250];
    char *ptr, *ptr2;

    if(!(_parser.send("I?") && _parser.recv("%s\r\n", tmp_buffer) && check_response())) {
        debug_if(ism_debug, "get_firmware_version is FAIL\r\n");
        return 0;
    }

    // Get the first version in the string
    ptr = strtok((char *)tmp_buffer, ",");
    ptr = strtok(NULL, ",");
    ptr2 = strtok(NULL, ",");
    if (ptr == NULL) {
        debug_if(ism_debug, "get_firmware_version decoding is FAIL\r\n");
        return 0;
    }
    strncpy(_fw_version, ptr , ptr2-ptr);

    debug_if(ism_debug, "get_firmware_version = [%s]\r\n", _fw_version);

    return _fw_version;
}

bool ISM43362::reset(void)
{
    debug_if(ism_debug,"Reset Module\r\n");
    _resetpin = 0;
    wait_ms(10);
    _resetpin = 1;
    wait_ms(500);

    /*  Wait for prompt line */
    if (!_parser.recv("> \r\n")) {
        debug_if(ism_debug,"Reset Module failed\r\n");
        return false;
    }

    return true;
}

void ISM43362::print_rx_buff(void) {
    char tmp[150] = {0};
    uint16_t i = 0;
    while(i  < 150) {
        int c = _parser.getc();
        if (c < 0)
            break;
        tmp[i] = c;
        debug_if(ism_debug," 0x%2X",c);
        i++;
    }
    debug_if(ism_debug,"Buffer content =====%s=====\r\n",tmp);
}

/*  checks the standard OK response of the WIFI module, shouldbe:
 *  \r\nDATA\r\nOK\r\n>sp
 *  or
 *  \r\nERROR\r\nUSAGE\r\n>sp
 *  function returns true if OK, false otherwise. In case of error,
 *  print error content then flush buffer */
bool ISM43362::check_response(void)
{
    if(!_parser.recv("OK\r\n")) {
        print_rx_buff();
        _parser.flush();
        return false;
    }

    /*  Then we should get "> ", but sometimes it seems it's missing,
     *  let's make it optional */
    if(!_parser.recv("> \r\n")) {
        debug_if(ism_debug, "Missing prompt in WIFI resp\r\n");
        print_rx_buff();
        _parser.flush();
        return false;
    }

    /*  Inventek module do stuffing / padding of data with 0x15,
     *  in case buffer containes such */
    while(1) {
        int c = _parser.getc();
        if ( c == 0x15) {
            continue;
        } else {
            /*  How to put it back if needed ? */
            break;
        }
    }

    return true;
}

bool ISM43362::dhcp(bool enabled)
{
    return (_parser.send("C4=%d", enabled ? 1:0) && check_response());
}

bool ISM43362::connect(const char *ap, const char *passPhrase)
{
    if (!(_parser.send("C1=%s", ap) && check_response())) {
        return false;
    }

    if (!(_parser.send("C2=%s", passPhrase) && check_response())) {
        return false;
    }
    /* TODO security level = 3 , is it hardcoded or not ???? */
    if (!(_parser.send("C3=3") && check_response())) {
        return false;
    }
    /* now connect */
    /* connect response contains more data that we don't need now,
     * So we only look for OK, the flush the end of it */
    if (!(_parser.send("C0") && check_response())) {
        return false;
    }

    return true;
}

bool ISM43362::disconnect(void)
{
    return (_parser.send("CD") && check_response());
}

const char *ISM43362::getIPAddress(void)
{
    char tmp_ip_buffer[250];
    char *ptr, *ptr2;

    if(!(_parser.send("C?")
                && _parser.recv("%s\r\n", tmp_ip_buffer) && check_response())) {
        debug_if(ism_debug,"getIPAddress LINE KO: %s", tmp_ip_buffer);
        return 0;
    }

    /* Get the IP address in the result */
    /* TODO : check if the begining of the string is always = "eS-WiFi_AP_C47F51011231," */
    ptr = strtok((char *)tmp_ip_buffer, ",");
    ptr = strtok(NULL, ",");
    ptr = strtok(NULL, ",");
    ptr = strtok(NULL, ",");
    ptr = strtok(NULL, ",");
    ptr = strtok(NULL, ",");
    ptr2 = strtok(NULL, ",");
    if (ptr == NULL) return 0;
    strncpy(_ip_buffer, ptr , ptr2-ptr);

    tmp_ip_buffer[59] = 0;
    debug_if(ism_debug,"receivedIPAddress: %s\n", _ip_buffer);

    return _ip_buffer;
}

const char *ISM43362::getMACAddress(void)
{
    if(!(_parser.send("Z5") && _parser.recv("%s\r\n", _mac_buffer) && check_response())) {
        debug_if(ism_debug,"receivedMacAddress LINE KO: %s", _mac_buffer);
        return 0;
    }

    debug_if(ism_debug,"receivedMacAddress:%s, size=%d\r\n", _mac_buffer, sizeof(_mac_buffer));

    return _mac_buffer;
}

const char *ISM43362::getGateway()
{
    char tmp[250];

    if(!(_parser.send("C?") && _parser.recv("%s\r\n", tmp) && check_response())) {
        debug_if(ism_debug,"getGateway LINE KO: %s\r\n", tmp);
        return 0;
    }

    /* Extract the Gateway in the received buffer */
    char *ptr;
    ptr = strtok(tmp,",");
    for (int i = 0; i< 7;i++) {
        if (ptr == NULL) break;
         ptr = strtok(NULL,",");
    }

    strncpy(_gateway_buffer, ptr, sizeof(_gateway_buffer));

    debug_if(ism_debug,"getGateway: %s\r\n", _gateway_buffer);

    return _gateway_buffer;
}

const char *ISM43362::getNetmask()
{
    char tmp[250];

    if(!(_parser.send("C?") && _parser.recv("%s\r\n", tmp) && check_response())) {
        debug_if(ism_debug,"getNetmask LINE KO: %s", tmp);
        return 0;
    }

    /* Extract Netmask in the received buffer */
    char *ptr;
    ptr = strtok(tmp,",");
    for (int i = 0; i< 6;i++) {
        if (ptr == NULL) break;
         ptr = strtok(NULL,",");
    }

    strncpy(_netmask_buffer, ptr, sizeof(_netmask_buffer));

    debug_if(ism_debug,"getNetmask: %s\r\n", _netmask_buffer);

    return _netmask_buffer;
}

int8_t ISM43362::getRSSI()
{
    int8_t rssi;
    char tmp[25];

    if(!(_parser.send("CR") && _parser.recv("%s\r\n", tmp) && check_response())) {
        debug_if(ism_debug,"getRSSI LINE KO: %s\r\n", tmp);
        return 0;
    }

    rssi = ParseNumber(tmp, NULL);

    debug_if(ism_debug,"getRSSI: %d\r\n", rssi);

    return rssi;
}
/**
  * @brief  Parses Security type.
  * @param  ptr: pointer to string
  * @retval Encryption type.
  */
extern "C" nsapi_security_t ParseSecurity(char* ptr) 
{
  if(strstr(ptr,"Open")) return NSAPI_SECURITY_NONE;
  else if(strstr(ptr,"WEP")) return NSAPI_SECURITY_WEP;
  else if(strstr(ptr,"WPA")) return NSAPI_SECURITY_WPA;   
  else if(strstr(ptr,"WPA2 AES")) return NSAPI_SECURITY_WPA2; 
  else if(strstr(ptr,"WPA WPA2")) return NSAPI_SECURITY_WPA_WPA2; 
  else if(strstr(ptr,"WPA2 TKIP")) return NSAPI_SECURITY_UNKNOWN; // ?? no match in mbed ?   
  else return NSAPI_SECURITY_UNKNOWN;           
}

/**
  * @brief  Convert char in Hex format to integer.
  * @param  a: character to convert
  * @retval integer value.
  */
extern "C"  uint8_t Hex2Num(char a) 
{
    if (a >= '0' && a <= '9') {                             /* Char is num */
        return a - '0';
    } else if (a >= 'a' && a <= 'f') {                      /* Char is lowercase character A - Z (hex) */
        return (a - 'a') + 10;
    } else if (a >= 'A' && a <= 'F') {                      /* Char is uppercase character A - Z (hex) */
        return (a - 'A') + 10;
    }
    
    return 0;
}

/**
  * @brief  Extract a hex number from a string.
  * @param  ptr: pointer to string
  * @param  cnt: pointer to the number of parsed digit
  * @retval Hex value.
  */
extern "C" uint32_t ParseHexNumber(char* ptr, uint8_t* cnt) 
{
    uint32_t sum = 0;
    uint8_t i = 0;
    
    while (CHARISHEXNUM(*ptr)) {         /* Parse number */
        sum <<= 4;
        sum += Hex2Num(*ptr);
        ptr++;
        i++;
    }
    
    if (cnt != NULL) {                  /* Save number of characters used for number */
        *cnt = i;
    }
    return sum;                         /* Return number */
}

bool ISM43362::isConnected(void)
{
    return getIPAddress() != 0;
}

int ISM43362::scan(WiFiAccessPoint *res, unsigned limit)
{
    unsigned cnt = 0, num=0;
    nsapi_wifi_ap_t ap;
    char *ptr;
    char tmp[256];

    if(!(_parser.send("F0"))) {
        debug_if(ism_debug,"scan error\r\n");
        return 0;
    }

    /* Parse the received buffer and fill AP buffer */
    while (_parser.recv("#%s\n", tmp)) {
        debug_if(ism_debug,"received:%s", tmp);
        ptr = strtok(tmp, ",");
        num = 0;
        while (ptr != NULL) {
            if (limit != 0 && cnt >= limit) {
                /* reached end */
                break;
            }
            switch (num++) {
            case 0: /* Ignore index */
            case 4: /* Ignore Max Rate */
            case 5: /* Ignore Network Type */
            case 7: /* Ignore Radio Band */
                break;
            case 1:
                ptr[strlen(ptr) - 1] = 0;
                strncpy((char *)ap.ssid,  ptr+ 1, 32);
                break;
            case 2:
                for (int i=0; i<6; i++) {
                    ap.bssid[i] = ParseHexNumber(ptr + (i*3), NULL);
                }
                break;
            case 3:
                ap.rssi = ParseNumber(ptr, NULL);
                break;
            case 6:
                ap.security = ParseSecurity(ptr);
                break;
            case 8:
                ap.channel = ParseNumber(ptr, NULL);
                res[cnt] = WiFiAccessPoint(ap);
                cnt++;
                num = 1;
                break;
            default:
                break;
            }
            ptr = strtok(NULL, ",");
        }
    }

    /* We may stop before having read all the APs list, so flush the rest of
     * it as well as OK commands */
    _parser.flush();

    debug_if(ism_debug, "End of Scan: cnt=%d\n", cnt);

    return cnt;

}

bool ISM43362::open(const char *type, int id, const char* addr, int port)
{ /* TODO : This is the implementation for the client socket, need to check if need to create openserver too */
    //IDs only 0-3
    if((id < 0) ||(id > 3)) {
        debug_if(ism_debug, "open: wrong id\n");
        return false;
    }
    /* Set communication socket */
    debug_if(ism_debug, "OPEN socket\n");
    _active_id = id;
    if (!(_parser.send("P0=%d", id) && check_response())) {
        return false;
    }
    /* Set protocol */
    if (!(_parser.send("P1=%s", type) && check_response())) {
        return false;
    }
    /* Set address */
    if (!(_parser.send("P3=%s", addr) && check_response())) {
        return false;
    }
    if (!(_parser.send("P4=%d", port) && check_response())) {
        return false;
    }
    /* Start client */
    if (!(_parser.send("P6=1") && check_response())) {
        return false;
    }

    /* request as much data as possible - i.e. module max size */
    if (!(_parser.send("R1=%d", ES_WIFI_MAX_RX_PACKET_SIZE)&& check_response())) {
            return -1;
    }

    return true;
}

bool ISM43362::dns_lookup(const char* name, char* ip)
{
    char tmp[30];

    if (!(_parser.send("D0=%s", name) && _parser.recv("%s\r\n", tmp)
                && check_response())) {
        debug_if(ism_debug,"dns_lookup LINE KO: %s", tmp);
        return 0;
    }

    strncpy(ip, tmp, sizeof(tmp));

    debug_if(ism_debug, "ip of DNSlookup: %s\n", ip);
    return 1;
}

bool ISM43362::send(int id, const void *data, uint32_t amount)
{
    // The Size limit has to be checked on caller side.
    if (amount > ES_WIFI_MAX_RX_PACKET_SIZE) {
        return false;
    }

    /* Activate the socket id in the wifi module */
    if ((id < 0) ||(id > 3)) {
        return false;
    }
    debug_if(ism_debug, "SEND socket amount %d\n", amount);
    if (_active_id != id) {
        _active_id = id;
        if (!(_parser.send("P0=%d",id) && check_response())) {
            return false;
        }
    }

    /* Change the write timeout */
    if (!(_parser.send("S2=%d", _timeout) && check_response())) {
        return false;
    }
    /* set Write Transport Packet Size */
    int i = _parser.printf("S3=%d\r", (int)amount);
    if (i < 0) {
        return false;
    }
    i = _parser.write((const char *)data, amount, i);
    if (i < 0) {
        return false;
    }

    if (!check_response()) {
        return false;
    }

    return true;
}

int ISM43362::check_recv_status(int id, void *data)
{
    int read_amount;
    static int keep_to = 0;

    debug_if(ism_debug, "ISM43362 req check_recv_status\r\n");
    /* Activate the socket id in the wifi module */
    if ((id < 0) ||(id > 3)) {
        return -1;
    }

    if (_active_id != id) {
        _active_id = id;
        if (!(_parser.send("P0=%d",id) && check_response())) {
            return -1;
        }
    }


    /* MBED wifi driver is meant to be non-blocking, but we need anyway to
     * wait for some data on the RECV side to avoid overflow on TX side, the
     * tiemout is defined in higher layer */
    if (keep_to != _timeout) {
        if (!(_parser.send("R2=%d", _timeout) && check_response())) {
            return -1;
        }
        keep_to = _timeout;
    }

    if (!_parser.send("R0")) {
        return -1;
    }
    read_amount = _parser.read((char *)data);

    if(read_amount < 0) {
        debug_if(ism_debug, "ERROR in data RECV, timeout?\r\n");
        return -1; /* nothing to read */
    }

    /*  If there are spurious 0x15 at the end of the data, this is an error
     *  we hall can get rid off of them :-(
     *  This should not happen, but let's try to clean-up anyway
     */
    char *cleanup = (char *) data;
    while ((read_amount > 0) && (cleanup[read_amount-1] == 0x15)) {
        debug_if(ism_debug, "ISM4336 spurious 0X15 trashed\r\n");
        /* Remove the trailling char then search again */
        read_amount--;
    }

    if ((read_amount >= 6) && (strncmp("OK\r\n> ", (char *)data, 6) == 0)) {
        debug_if(ism_debug, "ISM4336 recv 2 nothing to read=%d\r\n", read_amount);
        return 0; /* nothing to read */
    } else if ((read_amount >= 8) && (strncmp((char *)((uint32_t) data + read_amount - 8), "\r\nOK\r\n> ", 8)) == 0) {
        /* bypass ""\r\nOK\r\n> " if present at the end of the chain */
        read_amount -= 8;
    } else {
        debug_if(ism_debug, "ERROR in data RECV?, flushing %d bytes\r\n", read_amount);
        int i = 0;
        for (i = 0; i < read_amount; i++) {
             debug_if(ism_debug, "%2X ", cleanup[i]);
        }
        cleanup[i] = 0;
        debug_if(ism_debug, "\r\n%s\r\n", cleanup);
        return -1; /* nothing to read */
    }

    debug_if(ism_debug, "ISM43362 read_amount=%d\r\n", read_amount);
    return read_amount;
}

bool ISM43362::close(int id)
{
    if ((id <0) || (id > 3)) {
        debug_if(ism_debug,"Wrong socket number\n");
        return false;
    }
    /* Set connection on this socket */
    debug_if(ism_debug,"CLOSE socket id=%d\n", id);
    _active_id = id;
    if (!(_parser.send("P0=%d", id) && check_response())) {
        return false;
    }
    /* close this socket */
    if (!(_parser.send("P6=0") && check_response())) {
        return false;
    }
    return true;
}

void ISM43362::setTimeout(uint32_t timeout_ms)
{
    _timeout = timeout_ms;
    _parser.setTimeout(timeout_ms);
}

bool ISM43362::readable()
{
  /* not applicable with SPI api */
    return true;
}

bool ISM43362::writeable()
{
    /* not applicable with SPI api */
    return true;
}

void ISM43362::attach(Callback<void()> func)
{
    /* not applicable with SPI api */
}

