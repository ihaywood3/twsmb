# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

"""Implement the "security buffer" an intricate sub-protocol
used for authentication

Blobs implemented as DER-encoded ASN.1 objects
which in turn encapsulate NTLMv2 challenge-response authentication


much of code adapted from Mike Teo's pysmb """

from __future__ import absolute_import, division


from pyasn1.type import tag, univ, namedtype, namedval, constraint
from pyasn1.codec.der import encoder, decoder

class BlobManager(object):
    """
    encapsulates the authentication negotiation state
    callers just send blobs in and out and get a credential
    """
    
    def getInitialBlob(self):


    def _generateNegotiateSecurityBlob(self, ntlm_data):
        mech_token = univ.OctetString(ntlm_data).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
        mech_types = MechTypeList().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        mech_types.setComponentByPosition(0, univ.ObjectIdentifier('1.3.6.1.4.1.311.2.2.10'))

        n = NegTokenInit().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
        n.setComponentByName('mechTypes', mech_types)
        n.setComponentByName('mechToken', mech_token)

        nt = NegotiationToken()
        nt.setComponentByName('negTokenInit', n)

        ct = ContextToken()
        ct.setComponentByName('thisMech', univ.ObjectIdentifier('1.3.6.1.5.5.2'))
        ct.setComponentByName('innerContextToken', nt)

        return encoder.encode(ct)



#
# GSS-API ASN.1 (RFC2478 section 3.2.1)
#

RESULT_ACCEPT_COMPLETED = 0
RESULT_ACCEPT_INCOMPLETE = 1
RESULT_REJECT = 2

class NegResultEnumerated(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ( 'accept_completed', 0 ),
        ( 'accept_incomplete', 1 ),
        ( 'reject', 2 )
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + constraint.SingleValueConstraint(0, 1, 2)


class MechTypeList(univ.SequenceOf):
    componentType = univ.ObjectIdentifier()


class ContextFlags(univ.BitString):
    namedValues = namedval.NamedValues(
        ( 'delegFlag', 0 ),
        ( 'mutualFlag', 1 ),
        ( 'replayFlag', 2 ),
        ( 'sequenceFlag', 3 ),
        ( 'anonFlag', 4 ),
        ( 'confFlag', 5 ),
        ( 'integFlag', 6 )
    )


class NegTokenInit(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('mechTypes', MechTypeList().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('reqFlags', ContextFlags().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('mechToken', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.OptionalNamedType('mechListMIC', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)))
    )


class NegTokenTarg(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('negResult', NegResultEnumerated().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('supportedMech', univ.ObjectIdentifier().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('responseToken', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.OptionalNamedType('mechListMIC', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)))
    )


class NegotiationToken(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('negTokenInit', NegTokenInit().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('negTokenTarg', NegTokenTarg().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)))
    )


class ContextToken(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('thisMech', univ.ObjectIdentifier()),
        namedtype.NamedType('innerContextToken', NegotiationToken())
    )