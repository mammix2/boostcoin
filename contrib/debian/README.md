
Debian
====================
This directory contains files used to package boostcoind/boostcoin-qt
for Debian-based Linux systems. If you compile boostcoind/boostcoin-qt yourself, there are some useful files here.

## bitcoin: URI support ##


boostcoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install boostcoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your boostcoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/bitcoin128.png` to `/usr/share/pixmaps`

boostcoin-qt.protocol (KDE)

