Arnak 2.1.0
<img align="right" width="120" height="80" src="doc/imgs/logo.png">
===========

What is Arnak?
--------------

[Arnak](https://z.cash/) is an implementation of the "Zerocash" protocol.
Based on Bitcoin's code, Arnak intends to offer a far higher standard of privacy
through a sophisticated zero-knowledge proving scheme that preserves
confidentiality of transaction metadata. More technical details are available
in our [Protocol Specification](https://github.com/arnak/zips/raw/master/protocol/protocol.pdf).

This software is the Arnak client. It downloads and stores the entire history
of Arnak transactions; depending on the speed of your computer and network
connection, the synchronization process could take a day or more once the
blockchain has reached a significant size.

<p align="center">
  <img src="doc/imgs/zcashd_screen.gif" height="500">
</p>

#### :lock: Security Warnings

See important security warnings on the
[Security Information page](https://z.cash/support/security/).

**Arnak is experimental and a work in progress.** Use it at your own risk.

####  :ledger: Deprecation Policy

This release is considered deprecated 16 weeks after the release day. There
is an automatic deprecation shutdown feature which will halt the node some
time after this 16-week period. The automatic feature is based on block
height.

## Getting Started

Please see our [user guide](https://arnak.readthedocs.io/en/latest/rtd_pages/rtd_docs/user_guide.html) for joining the main Arnak network.

### Need Help?

* :blue_book: See the documentation at the [ReadtheDocs](https://arnak.readthedocs.io)
  for help and more information.
* :incoming_envelope: Ask for help on the [Arnak](https://forum.z.cash/) forum.
* :mag: Chat with our support community on [Rocket.Chat](https://chat.zcashcommunity.com/channel/user-support)

Participation in the Arnak project is subject to a
[Code of Conduct](code_of_conduct.md).

### Building

Build Arnak along with most dependencies from source by running the following command:

```
./zcutil/build.sh -j$(nproc)
```

Currently, Arnak is only officially supported on Debian and Ubuntu.

License
-------

For license information see the file [COPYING](COPYING).
