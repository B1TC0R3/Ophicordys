# Ophicordys

A single file Linux rootkit
This project is currently heavy work in progress and has not been tested yet.

Does absolutely not work on kernel versions > 6.0 due to strict write protection of
the `cr0` register. It will crash if run on said kernel version.
