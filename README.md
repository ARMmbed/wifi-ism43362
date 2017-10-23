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
    "wifi-spi_miso": "PC_11",
    "wifi-spi_mosi": "PC_12",
    "wifi-spi_sclk": "PC_10",
    "wifi-spi_nss": "PE_0",
    "wifi-reset": "PE_8",
    "wifi-dataready": "PE_1",
    "wifi-wakeup": "PB_13"
},
"DISCO_F413ZH": {
    "wifi-spi_miso": "PB_4",
    "wifi-spi_mosi": "PB_5",
    "wifi-spi_sclk": "PB_12",
    "wifi-spi_nss": "PG_11",
    "wifi-reset": "PH_1",
    "wifi-dataready": "PG_12",
    "wifi-wakeup": "PB_15"
}
```

- MBED_CFG_ISM43362_SSID - SSID of the wifi access point to connect to
- MBED_CFG_ISM43362_PASS - Passphrase of the wifi access point to connect to
- MBED_CONF_APP_WIFI_SPI_MISO - spi-miso pin for the ism43362 connection
- MBED_CONF_APP_WIFI_SPI_MOSI - spi-mosi pin for the ism43362 connection
- MBED_CONF_APP_WIFI_SPI_SCLK - spi-clock pin for the ism43362 connection
- MBED_CONF_APP_WIFI_SPI_NSS - spi-nss pin for the ism43362 connection
- MBED_CONF_APP_WIFI_RESET - Reset pin for the ism43362 wifi module
- MBED_CONF_APP_WIFI_DATAREADY - Data Ready pin for the ism43362 wifi module
- MBED_CONF_APP_WIFI_WAKEUP - Wakeup pin for the ism43362 wifi module


## Firmware version
This driver supports ISM43362-M3G-L44-SPI,C3.5.2.3.BETA9 and C3.5.2.2 firmware version

## wifi module FW update
For more information about the wifi FW version, refer to the detailed procedure in
http://www.st.com/content/st_com/en/products/embedded-software/mcus-embedded-software/stm32-embedded-software/stm32cube-embedded-software-expansion/x-cube-azure.html

```
