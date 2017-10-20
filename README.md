# The ISM43362 WiFi driver for mbed-os
The mbed OS driver for the ISM43362 WiFi module

## Firmware version
ISM43362 module is soldered on DISCO_L475_IOT1A from STMicroelectronics
This driver supports ISM43362-M3G-L44-SPI,C3.5.2.3.BETA9 firmware version
For more information about the wifi FW version, refer to the detailed procedure in 
http://www.st.com/content/st_com/en/products/embedded-software/mcus-embedded-software/stm32-embedded-software/stm32cube-embedded-software-expansion/x-cube-azure.html


## Testing
The ISM43362 library has been tested with mbed-os-example-wifi 

There are a couple other options that can be used during testing:
- MBED_CFG_ISM43362_SSID - SSID of the wifi access point to connect to
- MBED_CFG_ISM43362_PASS - Passphrase of the wifi access point to connect to
- MBED_CFG_ISM43362_WIFI_MISO - spi-miso pin for the ism43362 connection
- MBED_CFG_ISM43362_WIFI_MOSI - spi-mosi pin for the ism43362 connection
- MBED_CFG_ISM43362_WIFI_SCLK - spi-clock pin for the ism43362 connection
- MBED_CFG_ISM43362_WIFI_NSS - spi-nss pin for the ism43362 connection

```
