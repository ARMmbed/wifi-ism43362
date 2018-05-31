# ISM43362 WiFi driver for mbed-os
The mbed OS driver for the ISM43362 WiFi module

## Currently supported platforms
ISM43362 module is soldered on the following platforms from STMicroelectronics
* DISCO_L475VG_IOT01A
* DISCO_F413ZH

## Configuration
Add the following lines to the target_overrides section of mbed_app.json of your application
```
"DISCO_L475VG_IOT1A": {
    "ism43362.wifi-miso": "PC_11",
    "ism43362.wifi-mosi": "PC_12",
    "ism43362.wifi-sclk": "PC_10",
    "ism43362.wifi-nss": "PE_0",
    "ism43362.wifi-reset": "PE_8",
    "ism43362.wifi-dataready": "PE_1",
    "ism43362.wifi-wakeup": "PB_13"
},
"DISCO_F413ZH": {
    "ism43362.wifi-miso": "PB_4",
    "ism43362.wifi-mosi": "PB_5",
    "ism43362.wifi-sclk": "PB_12",
    "ism43362.wifi-nss": "PG_11",
    "ism43362.wifi-reset": "PH_1",
    "ism43362.wifi-dataready": "PG_12",
    "ism43362.wifi-wakeup": "PB_15"
}
```

- MBED_CONF_ISM43362_WIFI_MISO      : spi-miso pin for the ism43362 connection
- MBED_CONF_ISM43362_WIFI__MOSI     : spi-mosi pin for the ism43362 connection
- MBED_CONF_ISM43362_WIFI_SPI_SCLK  : spi-clock pin for the ism43362 connection
- MBED_CONF_ISM43362_WIFI_SPI_NSS   : spi-nss pin for the ism43362 connection
- MBED_CONF_ISM43362_WIFI_RESET     : Reset pin for the ism43362 wifi module
- MBED_CONF_ISM43362_WIFI_DATAREADY : Data Ready pin for the ism43362 wifi module
- MBED_CONF_ISM43362_WIFI_WAKEUP    : Wakeup pin for the ism43362 wifi module


## Firmware version
This driver supports ISM43362-M3G-L44-SPI,C3.5.2.3.BETA9 and C3.5.2.2 firmware version

## wifi module FW update
For more information about the wifi FW version, refer to the detailed procedure in
http://www.st.com/content/st_com/en/products/embedded-software/mcus-embedded-software/stm32-embedded-software/stm32cube-embedded-software-expansion/x-cube-azure.html

```
