# SCION Privacy Proxy

The SCION Privacy Proxy enhances data privacy and security in network communications. By employing a
secret sharing scheme, this proxy divides and transmits data across multiple paths. This approach
significantly increases the difficulty for any potential eavesdropper to obtain any information, as
they would need to intercept multiple data paths simultaneously in order to reassmble the shares
generated by the secret sharing scheme.
 

This project makes up of my bachelor thesis and supervised by the [ETH Zurich Network Security
Group](https://netsec.ethz.ch). It makes deliberate use of the code from an initial proof of concept
also developed at the smae group, the code can be found
[here](https://github.com/vincent10400094/scion/tree/feature-packet-splitting). The project is built
on top of [SCION](http://www.scion-architecture.net) (Scalability, Control and Isolation On
next-generation Networks).


## Acknowledgements
This project makes use of [hashicorp's implementation of Shamir's secret sharing
scheme](github.com/hashicorp/vault). Their License is reproduced in the shamir.go file, which is the
only code copied from their repository. 