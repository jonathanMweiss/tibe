# Treshold-IBE

this is an implementation of a thershold IBE scheme that can be used to do "conditional decryption".
That is, a user can encrypt its message to a specific ID, where once all nodes in a system
signs that ID, the message can be decrypted using the signatures as keys.

Examples of usage can be found in the unit-tests.

Two main APIs:

## VSSIbeNode

A dealer and a player in a distributed setting.
As in VSS schemes, assumes there is access to a valid broadcast channel,
where all nodes published their `exponent polynomial`.
otherwise any VSS cannot perform. So to begin using this API, publish the
`ExponentPoly` of a node to every other node in the system.

The `VssIveNode`

- can store other shares of VSS from other nodes in the system.
- can perform conditional encryption: Encrypt a message to a specific ID.
- validate votes of other nodes.
- can receive votes over a ID
- given enough votes over a ID - can reconstruct a secret key and decrypt all
  messages encrypted to a specific UUID.

## Reporting security problems

This library is offered as-is, and without a guarantee.
It will need an independent security review before it should be considered ready for use
in security-critical applications.
If you integrate `tibe` into your application it is YOUR RESPONSIBILITY
to arrange for that audit.

If you notice a possible security problem, please open an issue.

### TODOs:

- simplify the API, make usage clearer.
- provide example of how to do DKG. 