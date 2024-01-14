## Zig implementation (experimental) of TLS 1.2 

Based on Tls 1.2 experimental implementation *iguanaTls* by *Alexander Naskos* who's unfortunately no more with us.

The changes that I made to iguanaTls is the way handsakes were handled in the original code. In original code, it was not able to handle multiple handshakes in the same record, so I made those changes to the iguanaTls.

Any contributions to further enhance the library are welcome.

