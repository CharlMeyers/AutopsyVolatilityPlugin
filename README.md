# AutopsyVolatilityPlugin

This is a plugin for Autopsy Framework that will create a memory image of a computer and then use Volatility to process this memory image. The results can then be passed off to AUtopsy so that a visual timeline can be created for investigators.

## This Repository includes two items.

* A stand alone scanner
* A pluign for Autopsy Framework

### Standalone scanner
The scanner is just basically a C# program that calls `Dumpit`. After `Dumpit` made a memory image the scanner creates a MD5 hash of the resulting file. This file will be used for validation purposes to make sure the memory dump made by `Dumpit` has not been modified during transport.

### Autopsy plugin
The plugin will create it's own hash of the memory dump given to it and validate it against the hash that comes along with the memory image. If validated it will create a copy of this file and do processing on the copy.

The reason for this is that any possible modification of the memory image is avoided and therefore the change of the evidence being thrown out in court is reduced.