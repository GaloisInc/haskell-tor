# A Tor Implementation in Haskell

    This version of haskell-tor is (C) 2015 Galois, Inc., and distributed under
    a standard, three-clause BSD license. Please see the file LICENSE,
    distributed with this software, for specific terms and conditions.

## What is Tor?

Tor is a secure onion routing network for providing anonymized access to both
the public Internet as well as a series of Tor-internal hidden services. Much
more information about Tor can be found at http://torproject.org.

Many thanks to all the hard work that project has put into developing and
evangelizing Tor.

## What is in this repository?

This repository contains a Tor implementation in Haskell. It is eventually
designed to be a fully-compliant Tor implementation, but at the moment lacks
some features:

  * Support for finding or implementing hidden services.
  * Proper flow-control support.
  * Statistics updating.
  * Directory server support.

Using this library as an entrance node (i.e., to create anonymized connections
to hosts on the Internet) is fairly well tested and should be functional. Relay
and exit node support is implemented but much less well tested. For whichever
use case you have, please report any problems you find to the GitHub issue
tracker.

## Building haskell-tor

This library uses cabal as its build system, and should work for Mac, Unix, and
HaLVM-based installations. Windows support may work ... we just haven't tested
it.

If you're building with the HaLVM, please add the constraints `--constraint "tls
+hans"`, `--constraint "tls -network"`, and `-f-network` to your build flags,
and if you're using the `integer-simple` library (for example, to avoid GPL
entanglements with unikernels), you should add the constraints `--constraint
"cryptonite -integer-gmp"`, `--constraint "scientific +integer-simple"` and
`--constraint "scientific < 0.3.4.1"`.

In either case, we strongly suggest using sandboxes to keep everything nice and
tidy.

## Important Note

This is an early implementation of Tor that has not been peer-reviewed. Those
with a true, deep need for anonymity should strongly consider using the mainline
Tor client until and unless this version receives appropriate extensions,
testing, and review.

## Usage

As with most Haskell packages, this package can either be used as a library or
as a binary package. Currently, the executable binary will simply perform an
example get from whatismyip.com. Extending this to support a wider range of
features is an open issue.
