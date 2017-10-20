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

#include "ISM43362.h"

ISM43362::ISM43362(PinName mosi, PinName miso, PinName sclk, PinName nss, PinName resetpin, PinName datareadypin, PinName wakeup, bool debug)
    : _bufferspi(mosi, miso, sclk, nss, datareadypin), _parser(_bufferspi), _resetpin(resetpin),
      _packets(0), _packets_end(&_packets)
{
    Timer timer;
    uint16_t Prompt[3];
    uint8_t count = 0;
    
    DigitalOut wakeup_pin(wakeup);
    ISM43362::setTimeout((uint32_t)500);
    _bufferspi.format(16, 0); /* 16bits, ploarity low, phase 1Edge, master mode */
    _bufferspi.frequency(10000000); /* up to 20 MHz */

    _resetpin = 0;
    wait_ms(10);
    _resetpin = 1;
    wait_ms(500);

    _bufferspi.enable_nss();

    timer.start();

    while (_bufferspi.dataready.read() == 1) {
      Prompt[count] =(uint16_t)_bufferspi.get16b();
      count += 1;
      if(timer.read_ms() > 0xFFFF) {
        _bufferspi.disable_nss();
        break;
      }    
    }

    if((Prompt[0] != 0x1515) ||(Prompt[1] != 0x0A0D)||
         (Prompt[2] != 0x203E)) {
      _bufferspi.disable_nss();
    }
    _bufferspi.disable_nss();
    
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

int ISM43362::get_firmware_version()
{
    if (!(_parser.send("I?") && _parser.recv("ISM43362-M3G-L44-SPI,C3.5.2.3.BETA9,v3.5.2,v1.4.0.rc1,v8.2.1,120000000,Inventek eS-WiFi"))){
        printf("wrong version number\n");
        return -1;
    }
    return (35239);
}

bool ISM43362::startup(int mode)
{
  return false;
}

bool ISM43362::reset(void)
{
  
    _resetpin = 0;
    wait_ms(10);
    _resetpin = 1;
    wait_ms(500);

    return true;
}

bool ISM43362::dhcp(bool enabled)
{
    return (_parser.send("C4=%d", enabled ? 1:0) && _parser.recv("OK"));
}

bool ISM43362::connect(const char *ap, const char *passPhrase)
{
    if (!(_parser.send("C1=%s", ap) && (_parser.recv("OK")))) {
        return false;
    }
    if (!(_parser.send("C2=%s", passPhrase) && (_parser.recv("OK")))) {
        return false;
    }
    /* TODO security level = 3 , is it hardcoded or not ???? */
    if (!(_parser.send("C3=3") && (_parser.recv("OK")))) {
        return false;
    }
    
    /* now connect */
    if (!(_parser.send("C0") && _parser.recv("OK"))) {
        return false;
    }
    return true;
}

bool ISM43362::disconnect(void)
{
    return _parser.send("CD") && _parser.recv("OK");
}

const char *ISM43362::getIPAddress(void)
{
    char tmp_ip_buffer[60];
    char *ptr, *ptr2;
    if (!_parser.send("C?")) {
        return 0;
    }
    if (!_parser.read(tmp_ip_buffer, sizeof(tmp_ip_buffer))) {
        printf("receivedIPAddress: %s\n", tmp_ip_buffer);
        return 0;
    }

    printf("receivedIPAddress: %s\n", tmp_ip_buffer);

    // Get the IP address in the result
    // TODO : check if the begining of the string is always = "\r\neS-WiFi_AP_C47F51011231,"
    ptr = strtok((char *)tmp_ip_buffer+2, ",");
    ptr = strtok(NULL, ",");
    ptr = strtok(NULL, ",");
    ptr = strtok(NULL, ",");
    ptr = strtok(NULL, ",");
    ptr = strtok(NULL, ",");
    ptr2 = strtok(NULL, ",");
    if (ptr == NULL) return 0;
    strncpy(_ip_buffer, ptr , ptr2-ptr);

    return _ip_buffer;
}

const char *ISM43362::getMACAddress(void)
{
  char tmp_mac_buffer[30];

    _parser.send("Z5"); 

    if (!_parser.read(tmp_mac_buffer, sizeof(tmp_mac_buffer))) {
        printf("receivedIPAddress: %s", tmp_mac_buffer);
        return 0;
    }
    /* Extract the MAC address from the received buffer */
    if (!strncpy(_mac_buffer, tmp_mac_buffer+2, sizeof(_mac_buffer))) {
        return 0;
    }

    return _mac_buffer;
}

const char *ISM43362::getGateway()
{
    char tmp[250];

    _parser.send("C?");
    int res = _parser.read(tmp, 250);
    if (res <0) {
        printf("receivedGateway: %s", tmp);
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

    return _gateway_buffer;
}

const char *ISM43362::getNetmask()
{
    char tmp[250];
    _parser.send("C?");
    int res = _parser.read(tmp, 250);
    if (res <0) {
        printf("receivedNetmask: %s", tmp);
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

    return _netmask_buffer;
}

int8_t ISM43362::getRSSI()
{
    int8_t rssi;
    char tmp[25];
    /* Read SSID */
    if (!(_parser.send("CR"))) {
        return 0;
    }
    int res = _parser.read(tmp, 25);
    if (res <0) {
        printf("receivedNetmask: %s", tmp);
        return 0;
    }
    rssi = ParseNumber(tmp+2, NULL);

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
    char tmp[350];

    /* Get the list of AP */
    if (!(_parser.send("F0") && _parser.read(tmp, 350))) {
        return NSAPI_ERROR_DEVICE_ERROR;
    }

    /* Parse the received buffer and fill AP buffer */
    ptr = strtok(tmp + 2, ",");   
  
    while (ptr != NULL) {
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
        if (limit != 0 && cnt >= limit) {
            break;
        }
    }  

    return cnt;
}

bool ISM43362::open(const char *type, int id, const char* addr, int port)
{ /* TODO : This is the implementation for the client socket, need to check if need to create openserver too */
    //IDs only 0-3
    if((id < 0) ||(id > 3)) {
        printf("open: wrong id\n");
        return false;
    }
    /* Set communication socket */
    if (!(_parser.send("P0=%d", id) && _parser.recv("OK"))) {
        return false;
    }
    /* Set protocol */
    if (!(_parser.send("P1=%s", type) && _parser.recv("OK"))) {
        return false;
    }
    /* Set address */
    if (!(_parser.send("P3=%s", addr) && _parser.recv("OK"))) {
        return false;
    }
    /* set port between 0 and 5024 */
    if ((port < 0) ||(port > 5024)) {
        printf("open: wrong port\n");
        return false;
    }
    if (!(_parser.send("P4=%d", port) && _parser.recv("OK"))) {
        return false;
    }
    /* Start client */
    if (!_parser.send("P6=1")) { // LATER : CHECK OK !!
        return false;
    }
    char tmp[50];
    _parser.recv(tmp,50);
    printf("result of connection: %s\n", tmp);
    return true;
}

bool ISM43362::dns_lookup(const char* name, char* ip)
{
    char tmp[30];
    char *ptr;
    if (!(_parser.send("D0=%s", name) && _parser.read(tmp,30))) {
        return 1;
    }
    ptr = strchr(tmp+2,'\r');
    strncpy(ip, tmp+2, (int)(ptr - tmp - 2));
    *(ip + (ptr - tmp - 2)) = 0;
    printf("ip of DNSlookup: %s\n", ip);
    return 1;
}

bool ISM43362::send(int id, const void *data, uint32_t amount)
{
    // TODO CHECK SIZE NOT > txbuf size !!! if ((amount - 2) > 
    /* Activate the socket id in the wifi module */
    if ((id < 0) ||(id > 3)) {
        return false;
    }
    if (!(_parser.send("P0=%d",id) && _parser.recv("OK"))) {
        return false;
    }
    // TODO change the write timeout
    /* set Write Transport Packet Size */
    if (!(_parser.send("S3=%d\r%s", (amount+2), data) && _parser.recv("OK"))){
        return false;
    }

    return true;
}

void ISM43362::_packet_handler()
{
    int id;
    uint32_t amount;

    // parse out the packet
    if (!_parser.recv(",%d,%d:", &id, &amount)) {
        return;
    }

    struct packet *packet = (struct packet*)malloc(
            sizeof(struct packet) + amount);
    if (!packet) {
        return;
    }

    packet->id = id;
    packet->len = amount;
    packet->next = 0;

    if (!(_parser.read((char*)(packet + 1), amount))) {
        free(packet);
        return;
    }

    // append to packet list
    *_packets_end = packet;
    _packets_end = &packet->next;
}

int32_t ISM43362::recv(int id, void *data, uint32_t amount)
{
    // TODO: check that the amount is not > rxbuff size
    /* Activate the socket id in the wifi module */
    if ((id < 0) ||(id > 3)) {
        return false;
    }
    if (!(_parser.send("P0=%d",id) && _parser.recv("OK"))) {
        return false;
    }
    // TODO change the recv timeout
    if (!(_parser.send("R1=%d", amount) && _parser.recv("OK"))) {
        return false;
    }
    if (!_parser.send("R0")) {
        return false;
    }

    _parser.read((char *)data, amount);
    printf("socket receive: %s\n", (char *)data);
    return true;
}

bool ISM43362::close(int id)
{
    if ((id <0) || (id > 3)) {
        printf ("Wrong socket number\n");
        return false;
    }
    /* Set connection on this socket */
    if (!(_parser.send("P0=%d", id) && _parser.recv("OK"))){
        return false;
    }
    /* close this socket */
    if (!(_parser.send("P7=0") && _parser.recv("OK"))){
        return false;
    }
    return true;
}

void ISM43362::setTimeout(uint32_t timeout_ms)
{
    // TODO: send the timeout value to the wifi ?
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
    /* not applicable with SPI */
}

bool ISM43362::recv_ap(nsapi_wifi_ap_t *ap)
{
    int sec = 0;
    char tmp[350];
    // TO DO : voir ce qu'envoit le wifi en retour
    bool ret = _parser.read(tmp, 350); //!!! 350 IS VERY LONG ...
    /* TODO fill networkaccess points */
    //+CWLAP:(%d,\"%32[^\"]\",%hhd,\"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx\",%d", &sec, ap->ssid,
  //                          &ap->rssi, &ap->bssid[0], &ap->bssid[1], &ap->bssid[2], &ap->bssid[3], &ap->bssid[4],
    //                        &ap->bssid[5], &ap->channel);

    ap->security = sec < 5 ? (nsapi_security_t)sec : NSAPI_SECURITY_UNKNOWN;

    return ret;
}

void ISM43362::reset_module(DigitalOut rstpin)
{
    rstpin = 0;
    wait_ms(10);
    rstpin = 1;
    wait_ms(500);
}

