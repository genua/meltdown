# meltdown
Meltdown &amp; Spectre PoC for OpenBSD

### Building

Just run make, there are no dependencies!

```
$ make
```

### Running

Running the program will test for meltdown.
It takes a while to complete.
Verbose mode will give a bit more output while it is running.
There is a quick mode which shortens the test and precision.

```
# ./meltdown
# ./meltdown -q		# (quick)
# ./meltdown -v		# (verbose)
# ./meltdown -qv	# (quick and verbose)
# ./meltdown -m		# (meltdown, default)
# ./meltdown -s		# (spectre)
```
