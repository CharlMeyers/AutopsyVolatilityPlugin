# AutopsyVolatilityPlugin

This is a plugin for Autopsy Framework that will create a memory image of a computer and then use Volatility to process this memory image. The results can then be passed off to AUtopsy so that a visual timeline can be created for investigators.

## This Repository includes two items.

* A stand alone scanner
* A plugin for Autopsy Framework

### Standalone scanner
The scanner is just basically a C# program that calls `Dumpit`. After `Dumpit` made a memory image the scanner creates a MD5 hash of the resulting file. This file will be used for validation purposes to make sure the memory dump made by `Dumpit` has not been modified during transport.

### Autopsy plugin
The plugin will create it's own hash of the memory dump given to it and validate it against the hash that comes along with the memory image. If validated it will create a copy of this file and do processing on the copy.

The reason for this is that any possible modification of the memory image is avoided and therefore the change of the evidence being thrown out in court is reduced.

Huge credit must go to **Mark McKinnon** for allowing users to modify the code of his Autopsy Plugins. Go and check out his git profile [here](https://github.com/markmckinnon).

The plugin in this repository is a modified version of his plugin. Most notably volatility plugins do not get chosen, but rather a pre set number of plugins are run

## How to install ##
Firstly go to you can download DumpIt [here](http://qpdownload.com/dumpit/) if you do not have it already. The second thing you need to do is to download Volatility at [Volatility Foundation](http://www.volatilityfoundation.org/26) website. Then go to the releases page of this repository and download the **VolatilityProcessor.zip**. Make sure to put **RAMCollector.exe** and **DumpIt** executable in the same directory. Extract **VolatilityProcessor** into the Autopsy Python Modules folder. You can find that folder by clicking on Tools->Python Plugins in Autopsy. If you do not already have Autopsy you can download it from [here](https://www.sleuthkit.org/autopsy/download.php).

## How to use ##
Double click the RAM collector and follow the instructions to collect ram.

For the plugin. Add the RAM dump to your case as a logical file. Select Volatility processor. Indicate the path to volatility and select the correct operating system profile. Make sure the hash file is in the same directory as the RAM dump. If successfull the plugin will continue to scan the file automatically.