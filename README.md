## Delta Over-the-Air udpate demo

This repository demonstrates example of using AWS IoT OTA Library for delta udpates using binary diff mechanism. It uses the [coreMQTT Agent library](https://github.com/FreeRTOS/coreMQTT-Agent), an extension on top of [coreMQTT](https://github.com/FreeRTOS/coreMQTT) that provides MQTT APIs with thread safety. For creating binary diff the example uses [JojoDiff](http://jojodiff.sourceforge.net) on host and for patching [JANPatch](https://github.com/janjongboom/janpatch) is used on the device. 

## Cloning this repository
This repo uses [Git Submodules](https://git-scm.com/book/en/v2/Git-Tools-Submodules) to bring in dependent components.

**Note:** If you download the ZIP file provided by the GitHub UI, you will not get the contents of the submodules. (The ZIP file is also not a valid git repository)

To clone using HTTPS:
```
git clone https://github.com/FreeRTOS/Labs-Project-Espressif-Demos.git --recurse-submodules
```
Using SSH:
```
git clone git@github.com:FreeRTOS/Labs-Project-Espressif-Demos.git --recurse-submodules
```

If you have downloaded the repo without using the `--recurse-submodules` argument, you need to run:
```
git submodule update --init --recursive
```
## Getting started
The [documentation page](https://freertos.org/mqtt/delta-ota-demo.html) for this repository contains step by step guide to set up device, cloud service and perfrom delta updates. More documentation on OTA library is available at [AWS IoT OTA Documentation](https://freertos.org/ota/index.html).
### Hardware

The example is based on Espressif's ESP32 platform so [ESP32 development board](https://www.espressif.com/en/products/hardware/development-boards) will be required to get started.
### ESP IDF

This project is to be used with Espressif's IoT Development Framework, [ESP IDF](https://github.com/espressif/esp-idf). 

To setup ESP IDF development environment follow the steps [here](https://docs.espressif.com/projects/esp-idf/en/latest/get-started/index.html).
## Building Demos
 
Navigate to the root of the demo and run:

 `$ idf.py build`

Erase your development board's flash memory with the following command.

 `$ idf.py erase_flash`

 Use the idf.py script to flash the application binary to your board.

`$ idf.py flash`

Monitor the output from your board's serial port with the following command.

`$ idf.py monitor`

## Creating patch file

Build a new version of the firmware by making some changes and incrementing the version number. Use [jdiff](https://sourceforge.net/projects/jojodiff/files/jojodiff/jojodiff07/) for creating the delta 

`$ jdiff intial_firmware.bin new_frimware.bin firmware.patch`
## Getting help
You can use your Github login to get support from both the FreeRTOS community and directly from the primary FreeRTOS developers on our [active support forum](https://forums.freertos.org). You can also find a list of frequently asked questions [here](https://www.freertos.org/FAQ.html).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT License. See the [LICENSE](LICENSE.md) file.
