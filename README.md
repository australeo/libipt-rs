# libipt-rs
Rust implementation of a simple user-mode library for interacting with Window's inbuilt Intel Processor Trace driver.

This was initially started as a Rust port of Alex Ionescu's WinIPT (https://github.com/ionescu007/winipt), however as that project has not been updated in some time I found that it was no longer compatible with the latest Windows IPT driver. libipt-rs therefore relies on some of my own reverse engineering as well. Alex's code is probably much better documented however, and I recommend looking at it if you are interested in the driver itself.

Note this library only allows you to interact (start/stop/get) with the IPT driver. It does not contain any functionality for parsing IPT traces for coverage information.

This code is for research purposes only and I have no plans to support or add to it.
