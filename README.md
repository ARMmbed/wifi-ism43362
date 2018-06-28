# ISM43362 WiFi driver for mbed-os

The mbed OS driver for the ISM43362 WiFi module

https://www.inventeksys.com/products-page/wifi-modules/ism4336-m3g-l44-e-embedded-serial-to-wifi-module/


## Currently supported platforms

ISM43362 module is soldered on the following platforms from STMicroelectronics

 * [DISCO_L475VG_IOT01A](https://os.mbed.com/platforms/ST-Discovery-L475E-IOT01A/)
 * [DISCO_F413ZH](https://os.mbed.com/platforms/ST-Discovery-F413H/)

## Configuration

Correct pins have already been configured for both supported platforms.

Here is configured pins:

- MBED_CONF_ISM43362_WIFI_MISO      : spi-miso pin for the ism43362 connection
- MBED_CONF_ISM43362_WIFI_MOSI     : spi-mosi pin for the ism43362 connection
- MBED_CONF_ISM43362_WIFI_SPI_SCLK  : spi-clock pin for the ism43362 connection
- MBED_CONF_ISM43362_WIFI_SPI_NSS   : spi-nss pin for the ism43362 connection
- MBED_CONF_ISM43362_WIFI_RESET     : Reset pin for the ism43362 wifi module
- MBED_CONF_ISM43362_WIFI_DATAREADY : Data Ready pin for the ism43362 wifi module
- MBED_CONF_ISM43362_WIFI_WAKEUP    : Wakeup pin for the ism43362 wifi module

## Debug

Some debug print on console can help to debug if necessary.

- in ISM43362Interface.cpp file, set ism_interface_debug to 1
- in ISM43362/ISM43362.cpp file, set ism_debug to 1
- in ISM43362/ATParser/ATParser.cpp file, there are 3 different level : dbg_on / AT_DATA_PRINT / AT_COMMAND_PRINT

Another way to enable these prints is overwrite MBED_CONF_ISM43362_WIFI_DEBUG in your json file:
            "ism43362.wifi-debug": true


## Firmware version

This driver has been tested with C3.5.2.2 and C3.5.2.3.BETA9 firmware version

## wifi module FW update

Only Wifi module from DISCO_L475VG_IOT01A can be updated (HW limitation for DISCO_F413ZH).

For more information about the wifi FW version, refer to the detailed procedure in
http://www.st.com/content/st_com/en/products/embedded-software/mcus-embedded-software/stm32-embedded-software/stm32cube-embedded-software-expansion/x-cube-azure.html
