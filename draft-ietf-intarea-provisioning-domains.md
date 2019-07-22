---
title: Discovering Provisioning Domain Names and Data
abbrev: Provisioning Domains
docname: draft-ietf-intarea-provisioning-domains-latest
date:
category: std

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
  -
    ins: P. Pfister
    name: Pierre Pfister
    org: Cisco
    street: 11 Rue Camille Desmoulins
    city: Issy-les-Moulineaux 92130
    country: France
    email: ppfister@cisco.com
  -
    ins: E. Vyncke
    name: Eric Vyncke
    org: Cisco
    street: De Kleetlaan, 6
    city: Diegem 1831
    country: Belgium
    email: evyncke@cisco.com
  -
    ins: T. Pauly
    name: Tommy Pauly
    org: Apple Inc.
    street: One Apple Park Way
    city: Cupertino, California 95014
    country: United States of America
    email: tpauly@apple.com
  -
    ins: D. Schinazi
    name: David Schinazi
    org: Google LLC
    street: 1600 Amphitheatre Parkway
    city: Mountain View, California 94043
    country: United States of America
    email: dschinazi.ietf@gmail.com
  -
    ins: W. Shao
    name: Wenqin Shao
    org: Cisco
    street: 11 Rue Camille Desmoulins
    city: Issy-les-Moulineaux 92130
    country: France
    email: wenshao@apple.com

informative:
    IEEE8021X:
      title: IEEE Standards for Local and Metropolitan Area Networks, Port-based Network Access Control, IEEE Std
      authors:
        -
          org: IEEE
    URN:
      title: URN Namespaces
      url: https://www.iana.org/assignments/urn-namespaces/urn-namespaces.xhtml#urn-namespaces-1
      authors:
        -
          org: IANA

--- abstract



An increasing number of hosts access the Internet via multiple
interfaces or, in IPv6 multi-homed networks, via multiple IPv6 prefix
configurations context.

This document describes a way for hosts to identify such contexts,
called Provisioning Domains (PvDs), where Fully Qualified Domain Names
(FQDNs) act as PvD identifiers. Those identifiers are advertised in a
new Router Advertisement (RA) option and, when present, are associated
with the set of information included within the RA.

Based on this FQDN, hosts can retrieve additional information about
their network access characteristics via an HTTP over TLS query. This
allows applications to select which Provisioning Domains to use as well
as to provide configuration parameters to the transport layer and
above.

--- middle

# Introduction

It has become very common in modern networks for hosts to access the
internet through different network interfaces, tunnels, or next-hop
routers. For example, if Alice has a mobile phone provider and a
broadband provider in her home, her devices and her applications should
be capable of seamlessly transitioning from one to the other and be able
to use her Wi-Fi to access local resources or use the more suitable link
on a per-application base. This document provides the basic information
necessary to make this choice intelligently. There are similar use cases
for IPsec Virtual Private Networks that are already considered Explicit
PvDs in {{?RFC7556}}.

To describe the set of network configurations associated with each
access method, the concept of Provisioning Domain (PvD) was defined in
{{?RFC7556}}.

This document specifies a way to identify PvDs with Fully Qualified
Domain Names (FQDN), called PvD IDs. Those identifiers are advertised in
a new Router Advertisement (RA) {{!RFC4861}} option called
the PvD ID Router Advertisement option which, when present, associates
the PvD ID with all the information present in the Router Advertisement
as well as any configuration object, such as addresses, deriving from
it. The PVD ID Router Advertisement option may also contain a set of
other RA options. Since such options are only considered by hosts
implementing this specification, network operators may configure hosts
that are 'PvD-aware' with PvDs that are ignored by other hosts.

Since PvD IDs are used to identify different ways to access the
internet, multiple PvDs (with different PvD IDs) could be provisioned on
a single host interface. Similarly, the same PvD ID could be used on
different interfaces of a host in order to inform that those PvDs
ultimately provide identical services.

This document also introduces a way for hosts to retrieve optional
and additional information related to a specific PvD by means of an HTTP
over TLS query using an URI derived from the PvD ID. The retrieved JSON
object contains additional information that would typically be
considered unfit, or too large, to be directly included in the Router
Advertisement, but might be considered useful to the applications, or
even sometimes users, when choosing which PvD should be used.

## Specification of Requirements

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{?RFC2119}} {{?RFC8174}} when, and only when,
they appear in all capitals, as shown here.

# Terminology

This document uses the following terminology:

Provisioning Domain (PvD):
: A set of network configuration information; for more information, see {{?RFC7556}}.

PvD ID:
: A Fully Qualified Domain Name (FQDN) used to identify a PvD.

Explicit PvD:
: A PvD uniquely identified with a PvD ID. For more information, see {{?RFC7556}}.

Implicit PvD:
: A PvD that, in the absence of a PvD ID,
is identified by the host interface to which it is attached and the
address of the advertising router. See also {{?RFC7556}}.

PvD-aware host:
: A host that supports the association of
network configuration information into PvDs and the use of these
PvDs. Also named PvD-aware node in {{?RFC7556}}.

# Provisioning Domain Identification using Router Advertisements {#ra}

Explicit PvDs are identified by a PvD ID. The PvD ID is a Fully
Qualified Domain Name (FQDN) which MUST belong to the network operator
in order to avoid naming collisions. The same PvD ID MAY be used in
several access networks when they ultimately provide identical services
(e.g., in all home networks subscribed to the same service); else, the
PvD ID MUST be different to follow Section 2.4 of {{?RFC7556}}.

## PvD ID Option for Router Advertisements
This document introduces a Router Advertisement (RA) option called
PvD option. It is used to convey the FQDN identifying a given PvD (see
{{format}}, bind the PvD ID with configuration
information received over DHCPv4 (see {{dhcpv4}}), enable
the use of HTTP over TLS to retrieve the PvD Additional Information
JSON object (see {{data}}), as well as contain any other
RA options which would otherwise be valid in the RA.

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |    Length     |H|L|R|     Reserved    | Delay |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Sequence Number         |                             ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                             ...
...                         PvD ID FQDN                       ...
...             +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
...             |                  Padding                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                             ...
...            Router Advertisement message header            ...
...             (Only present when R-flag is set)             ...
...                                                             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Options ...
+-+-+-+-+-+-+-+-+-+-+-+-
~~~
{: #format title="PvD ID Router Advertisements Option Format"}

Type:
: (8 bits) Set to 21.

Length:
: (8 bits) The length of the option in
units of 8 octets, including the Type and Length fields, the
Router Advertisement message header, if any, as well as the RA
options that are included within the PvD Option.

H-flag:
: (1 bit) 'HTTP' flag stating whether
some PvD Additional Information is made available through HTTP
over TLS, as described in {{data}}.

L-flag:
: (1 bit) 'Legacy' flag stating whether
the router is also providing IPv4 information using DHCPv4 (see
{{dhcpv4}}).

R-flag:
: (1 bit) 'Router Advertisement' flag
stating whether the PvD Option is followed (right after padding to
the next 64 bits boundary) by a Router Advertisement message
header (See section 4.2 of {{!RFC4861}}).

Delay:
: (4 bits) Unsigned integer used to
delay HTTP GET queries from hosts by a randomized backoff (see
{{retr}}).

Reserved:
: (13 bits) Reserved for later use. It
MUST be set to zero by the sender and ignored by the receiver.

Sequence Number:
: (16 bits) Sequence number for the
PvD Additional Information, as described in {{data}}.

PvD ID FQDN:
: The FQDN used as PvD ID encoded in
DNS format, as described in Section 3.1 of {{!RFC1035}}. Domain names
compression described in Section 4.1.4 of {{!RFC1035}} MUST NOT be used.

Padding:
: Zero or more padding octets to the
next 8 octets boundary. It MUST be set to zero by the sender, and
ignored by the receiver.

RA message header:
: (16 octets) When the R-flag is
set, a full Router Advertisement message header as specified in
{{!RFC4861}}. The sender MUST set the 'Type' to 134,
the value for "Router Advertisement", and set the 'Code' to 0.
Receivers MUST ignore both of these fields. The 'Checksum' MUST be
set to 0 by the sender; non-zero checksums MUST be ignored by the
receiver. All other fields are to be set and parsed as specified
in {{!RFC4861}} or any updating documents.

Options:
: Zero or more RA options that would
otherwise be valid as part of the Router Advertisement main body,
but are instead included in the PvD Option such as to be ignored
by hosts that are not 'PvD-aware'.

Here is an example of a PvD option with "example.org" as the
PvD ID FQDN and including a RDNSS and prefix information options (it
also have the sequence number 123, presence of additional information
to be fetched with a delay indicated as 5):

~~~
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+-----------------------------------------------+
| Type: 21      |  Length: 12   |1|0|0|     Reserved    |Delay:5|
+---------------+-------------------------------+---------------+
|       Seq number: 123         |      7        |       e       |
+---------------+-----------------------------------------------+
|      x        |       a       |      m        |       p       |
+---------------------------------------------------------------+
|      l        |       e       |      3        |       o       |
+---------------------------------------------------------------+
|      r        |       g       |      0        |   0 (padding) |
+---------------------------------------------------------------+
|   0 (padding) |  0 (padding)  |   0 (padding) |   0 (padding) |
+---------------+---------------+---------------+---------------+
|  RDNSS option (RFC 6106) length: 5                          ...
...                                                           ...
...                                                             |
+---------------------------------------------------------------+
| Prefix Information Option (RFC 4861) length: 4              ...
...                                                             |
...                                                             |
+---------------------------------------------------------------+
~~~
{: #pvd_example }

## Router Behavior {#router}

A router MAY send RAs containing one PvD option, but MUST NOT
include more than one PvD option in each RA. In particular, the PvD
option MUST NOT contain further PvD options.

The PvD Option MAY contain zero, one, or more RA options which
would otherwise be valid as part of the same RA. Such options are
processed by PvD-aware hosts, while ignored by others.

In order to provide multiple different PvDs, a router MUST send
multiple RAs. Different explicit PvDs MAY be advertised with RAs using
the same IPv6 source address; but different implicit PvDs, advertised
by different RAs, MUST use different link-local addresses because
these implicit PvDs are identified by the source addresses of the
RAs.

As specified in {{!RFC4861}}, when the set of options
causes the size of an advertisement to exceed the link MTU, multiple
router advertisements can be sent, each containing a subset of the
options. In such cases, the PvD option header (i.e., all fields except
the 'Options' field) MUST be repeated in all the transmitted RAs. The
options within the 'Options' field, MAY be transmitted only once,
included in one of the transmitted PvD options.

## Non-PvD-aware Host Behavior

As the PvD Option has a new option code, non-PvD-aware hosts will
simply ignore the PvD Option and all the options it contains. This
ensure the backward compatibility required in Section 3.3 of {{?RFC7556}}.
This behavior allows for a mixed-mode network with
a mix of PvD-aware and non-PvD-aware hosts coexist.

## PvD-aware Host Behavior {#host}

Hosts MUST associate received RAs and included configuration
information (e.g., Router Valid Lifetime, Prefix Information {{!RFC4861}}, 
Recursive DNS Server {{?RFC8106}},
Routing Information {{?RFC4191}} options) with the
explicit PvD identified by the first PvD Option present in the
received RA, if any, or with the implicit PvD identified by the host
interface and the source address of the received RA otherwise.

In case multiple PvD options are found in a given RA, hosts MUST
ignore all but the first PvD option.

If a host receives PvD options flags that it does not recognize
(currently in the Reserved field), it MUST ignore these flags.

Similarly, hosts MUST associate all network configuration objects
(e.g., default routers, addresses, more specific routes, DNS Recursive
Resolvers) with the PvD associated with the RA which last updated the
object. For example, addresses that are generated using a received
Prefix Information option (PIO) are associated with the PvD of the
last received RA which included the given PIO.

PvD IDs MUST be compared in a case-insensitive manner (i.e., A=a),
assuming ASCII with zero parity while non-alphabetic codes must match
exactly (see also Section 3.1 of {{!RFC1035}}). For
example, "pvd.example.com." or "PvD.Example.coM." would refer to the
same PvD.

While resolving names, executing the default address selection
algorithm {{?RFC6724}} or executing the default router
selection algorithm when forwarding packets ({{!RFC2461}},
{{?RFC4191}} and {{?RFC8028}}), hosts MAY
consider only the configuration associated with an arbitrary set of
PvDs.

For example, a host MAY associate a given process with a specific
PvD, or a specific set of PvDs, while associating another process with
another PvD. A PvD-aware application might also be able to select, on
a per-connection basis, which PvDs should be used. In particular,
constrained devices such as small battery operated devices (e.g. IoT),
or devices with limited CPU or memory resources may purposefully use a
single PvD while ignoring some received RAs containing different PvD
IDs.

The way an application expresses its desire to use a given PvD, or
a set of PvDs, or the way this selection is enforced, is out of the
scope of this document. Useful insights about these considerations can
be found in {{?I-D.kline-mif-mpvd-api-reqs}}.

### DHCPv6 configuration association {#dhcpv4}

When a host retrieves configuration elements using DHCPv6 (e.g.,
addresses or DNS recursive resolvers), they MUST be associated with
the explicit or implicit PvD of the RA received on the same
interface, sent from the same LLA, and with the O-flag or M-flag set
{{!RFC4861}}. If no such PvD is found, or whenever
multiple different PvDs are found, the host behavior is
unspecified.

This process requires hosts to keep track of received RAs,
associated PvD IDs, and routers LLA; it also assumes that the router
either acts as a DHCPv6 server or relay and uses the same LLA for
DHCPv6 and RA traffic (which may not be the case when the router
uses VRRP to send its RA).


### DHCPv4 configuration association {#dhcpv4}

When a host retrieves configuration elements from DHCPv4, they MUST
be associated with the explicit PvD received on the same interface,
whose PVD Options L-flag is set and, in the case of a non point-to-
point link, using the same datalink address.  If no such PvD is
found, or whenever multiple different PvDs are found, the
configuration elements coming from DHCPv4 MUST be associated with the
implicit PvD identified by the interface on which the DHCPv4
transaction happened.  The case of multiple explicit PvD for an IPv4
interface is undefined.

### Connection Sharing by the Host

The situation when a host shares connectivity from an upstream
interface (e.g. cellular) to a downstream interface (e.g. Wi-Fi) is
known as 'tethering'. Techniques such as ND-proxy {{?RFC4389}}, 
64share {{?RFC7278}} or prefix delegation (e.g. using DHCPv6-PD 
{{?RFC8415}}) may be used for that purpose.

Whenever the RAs received from the upstream interface contain a
PVD RA option, hosts that are sharing connectivity SHOULD include a
PVD Option within the RAs sent downstream with:

- The same PVD-ID FQDN

- The same H-bit, Delay and Sequence Number values

- The L bit set whenever the host is sharing IPv4 connectivity
received from the same upstream interface

- The bits from the Reserved field set to 0

The values of the R-bit, Router Advertisement message
header and Options field depend on whether the connectivity should
be shared only with PvD-aware hosts or not (see {{router}}). In particular,
all options received within the upstream PvD option and included in
the downstream RA SHOULD be included in the downstream PvD option.

### Usage of DNS Servers

PvD-aware hosts can be provisioned with recursive DNS servers via
RA options passed within an explicit PvD, via RA options associated
with an implicit PvD, via DHCPv6 or DHCPv4, or from some other
provisioning mechanism that creates an implicit PvD (such as a VPN).
In all of these cases, the DNS server addresses SHOULD be strongly
associated with the corresponding PvD. Specificially, queries sent
to a configured recursive DNS server SHOULD be sent from a local IP
address that belongs to the matching PvD. Answers received from the
DNS server SHOULD only be used on the same PvD.

Maintaining the correct usage of DNS within PvDs avoids various
practical errors, such as:

- A PvD associated with a VPN or otherwise private network may
provide DNS answers that contain addresses inaccessible over
another PvD.

- A PvD that uses a NAT64 {{?RFC6146}} and DNS64
{{?RFC6147}} will synthesize IPv6 addresses in DNS
answers that are not globally routable, and cannot be used on
other PvDs. Conversely, an IPv4 address resolved via DNS on
another PvD cannot be directly used on a NAT64 network without
the host synthesizing an IPv6 address.

# Provisioning Domain Additional Information {#data}

Additional information about the network characteristics can be
retrieved based on the PvD ID. This set of information is called PvD
Additional Information, and is encoded as a JSON object {{!RFC7159}}.

The purpose of this additional set of information is to securely
provide additional information to applications about the connectivity
that is provided using a given interface and source address pair. It
typically includes data that would be considered too large, or not
critical enough, to be provided within an RA option. The information
contained in this object MAY be used by the operating system, network
libraries, applications, or users, in order to decide which set of PvDs
should be used for which connection, as described in {{host}}.

## Retrieving the PvD Additional Information {#retr}

When the H-flag of the PvD Option is set, hosts MAY attempt to
retrieve the PvD Additional Information associated with a given PvD by
performing an HTTP over TLS {{!RFC2818}} GET query to
https://&lt;PvD-ID&gt;/.well-known/pvd {{?RFC5785}}.
Inversely, hosts MUST NOT do so whenever the H-flag is not set.

HTTP requests and responses for PvD additional information use the
"application/pvd+json" media type (see {{iana}}). Clients
SHOULD include this media type as an Accept header in their GET
requests, and servers MUST mark this media type as their Content-Type
header in responses.

Note that the DNS name resolution of the PvD ID, the PKI checks as
well as the actual query MUST be performed using the considered PvD.
In other words, the name resolution, PKI checks, source address
selection, as well as the next-hop router selection MUST be performed
while using exclusively the set of configuration information attached
with the PvD, as defined in {{host}}. In some cases, it
may therefore be necessary to wait for an address to be available for
use (e.g., once the Duplicate Address Detection or DHCPv6 processes
are complete) before initiating the HTTP over TLS query. If the host
has a temporary address per {{?RFC4941}} in this PvD, then
hosts SHOULD use a temporary address to fetch the PvD Additional
Information and SHOULD deprecate the used temporary address and
generate a new temporary address afterward.

If the HTTP status of the answer is greater than or equal to 400
the host MUST abandon and consider that there is no additional PvD
information. If the HTTP status of the answer is between 300 and 399,
inclusive, it MUST follow the redirection(s). If the HTTP status of
the answer is between 200 and 299, inclusive, the host MAY get a file
containing a single JSON object. When a JSON object could not be
retrieved, an error message SHOULD be logged and/or displayed in a
rate-limited fashion.

After retrieval of the PvD Additional Information, hosts MUST keep
track of the Sequence Number value received in subsequent RAs
including the same PvD ID. In case the new value is greater than the
value that was observed when the PvD Additional Information object was
retrieved (using serial number arithmetic comparisons {{!RFC1982}}),
or whenever the validity time included in the PVD
Additional Information JSON object is expired, hosts MUST either
perform a new query and retrieve a new version of the object, or,
failing that, deprecate the object and stop using the additional
information provided in the JSON object.

Hosts retrieving a new PvD Additional Information object MUST check
for the presence and validity of the mandatory fields specified in
{{aiformat}}. A retrieved object including an expiration
time that is already past or missing a mandatory element MUST be
ignored.

In order to avoid synchronized queries toward the server hosting
the PvD Additional Information when an object expires, object updates
are delayed by a randomized backoff time.

- When a host performs an object update after it detected a
change in the PvD Option Sequence number, it MUST delay the query
by a random time between zero and 2**(Delay * 2) milliseconds,
where 'Delay' corresponds to the 4 bits long unsigned integer in
the last received PvD Option.

- When a host last retrieved an object at time A including a
validity time B, and is configured to keep the object up to date,
it MUST perform the update at a uniformly random time in the
interval [(B-A)/2,B].

In the example {{pvd_example}}, the delay field value
is 5, this means that host MUST delay the query by a random number
between 0 and 2**(5 * 2) milliseconds, i.e., between 0 and 1024
milliseconds.

Since the 'Delay' value is directly within the PvD Option rather
than the object itself, an operator may perform a push-based update by
incrementing the Sequence value while changing the Delay value
depending on the criticality of the update and its PvD Additional
Information servers capacity.

The PvD Additional Information object includes a set of IPv6
prefixes (under the key "prefixes") which MUST be checked against all
the Prefix Information Options advertised in the RA. If any of the
prefixes included in the PIO is not covered by at least one of the
listed prefixes, the PvD associated with the tested prefix MUST be
considered unsafe and MUST NOT be used. While this does not prevent a
malicious network provider, it does complicate some attack scenarios,
and may help detecting misconfiguration.

## Operational Consideration to Providing the PvD Additional Information

Whenever the H-flag is set in the PvD Option, a valid PvD
Additional Information object MUST be made available to all hosts
receiving the RA by the network operator. In particular, when a
captive portal is present, hosts MUST still be allowed to perform DNS,
PKI and HTTP over TLS operations related to the retrieval of the
object, even before logging into the captive portal.

Routers MAY increment the PVD Option Sequence number in order to
inform host that a new PvD Additional Information object is available
and should be retrieved.

The server providing the JSON files SHOULD also check whether the
client address is part of the prefixes listed into the additional
information and SHOULD return a 403 response code if there is no
match.

## PvD Additional Information Format {#aiformat}

The PvD Additional Information is a JSON object.

The following table presents the mandatory keys which MUST be
included in the object:

| JSON key | Description         | Type      | Example      |
|:------------|:-----------------------|:---------------------|:------------|
| name        | Human-readable service name      | UTF-8 string {{!RFC3629}} | "Awesome Wi-Fi" |
| expires     | Date after which this object is no longer valid  | {{?RFC3339}} | "2017-07-23T06:00:00Z" |
| prefixes    | Array of IPv6 prefixes valid for this PvD   | Array of strings | ["2001:db8:1::/48", "2001:db8:4::/48"] |

A retrieved object which does not include a valid string associated
with the "name" key at the root of the object, or a valid date
associated with the "expires" key, also at the root of the object,
MUST be ignored. In such cases, an error message SHOULD be logged
and/or displayed in a rate-limited fashion. If the PIO of the received
RA is not covered by at least one of the "prefixes" key, the retrieved
object SHOULD be ignored.

The following table presents some optional keys which MAY be
included in the object.

| JSON key | Description         | Type      | Example      |
|:------------|:-----------------------|:---------------------|:------------|
| localizedName        | Localized name      | UTF-8 string | "Wi-Fi Genial" |
| dnsZones     | DNS zones searchable and accessible  | Array of strings | "2017-07-23T06:00:00Z" |
| noInternet    | No Internet, set when the PvD is restricted.   | Boolean | ["2001:db8:1::/48", "2001:db8:4::/48"] |

It is worth noting that the JSON format allows for extensions.
Whenever an unknown key is encountered, it MUST be ignored along with
its associated elements.

Private-use or experimental keys MAY be used in the JSON
dictionary. In order to avoid such keys colliding with IANA registry
keys, implementers or vendors defining private-use or experimental
keys MUST create sub-dictionaries, where the sub-dictionary is added
into the top-level JSON dictionary with a key of the format "vendor-*"
where the "*" is replaced by the implementers or vendors denomination.
Upon receiving such a sub-dictionary, host MUST ignore this
sub-dictionary if it is unknown. When the vendor or implementor is
part of an IANA URN namespace {{URN}}, the URN namespace
SHOULD be used rather than the "vendor-*" format.

### Example 

The following examples show how the JSON keys defined in this
document can be used:

~~~
{
  "name": "Foo Wireless",
  "localizedName": "Foo-France Wi-Fi",
  "expires": "2017-07-23T06:00:00Z",
  "prefixes" : ["2001:db8:1::/48", "2001:db8:4::/48"],
}

{
  "name": "Bar 4G",
  "localizedName": "Bar US 4G",
  "expires": "2017-07-23T06:00:00Z",
  "prefixes": ["2001:db8:1::/48", "2001:db8:4::/48"],
}

{
  "name": "Company Network",
  "localizedName": "Company Network",
  "expires": "2017-07-23T06:00:00Z",
  "prefixes": ["2001:db8:1::/48", "2001:db8:4::/48"],
  "vendor-foo": { "private-key": "private-value" },
}
~~~

## Detecting misconfiguration and misuse {#misconfig}

When a host retrieves the PvD Additional Information, it MUST
verify that the TLS server certificate is valid for the performed
request (e.g., that the Subject Name is equal to the PvD ID expressed
as an FQDN). This authentication creates a secure binding between the
information provided by the trusted Router Advertisement, and the
HTTPS server. However, this does not mean the Advertising Router and
the PvD server belong to the same entity.

Hosts MUST verify that all prefixes in the RA PIO are covered by a
prefix from the PvD Additional Information. An adversarial router
willing to fake the use of a given explicit PvD, without any access to
the actual PvD Additional Information, would need to perform NAT66 in
order to circumvent this check.

It is also RECOMMENDED that the HTTPS server checks the IPv6 source
addresses of incoming connections (see {{retr}}). This
check give reasonable assurance that neither NPTv6 {{?RFC6296}}
nor NAT66 were used and restricts the information
to the valid network users.

Note that this check cannot be performed when the HTTPS query is
performed over IPv4. Therefore, the PvD ID FQDN SHOULD NOT have a DNS
A record whenever all hosts using the given PvD have IPv6
connectivity.

# Operational Considerations

This section describes some use cases of PvD. For the sake of
simplicity, the RA messages will not be described in the usual ASCII art
but rather in an indented list. For example, a RA message containing
some options and a PvD option that also contains other options will be
described as:

- RA Header: router lifetime = 6000

- Prefix Information Option: length = 4, prefix =
2001:db8:cafe::/64

- PvD Option header: length = 3 + 5 + 4 , PvD ID FQDN =
example.org., R-flag = 0 (actual length of the header with padding
24 bytes = 3 * 8 bytes)

	- Recursive DNS Server: length = 5, addresses= [2001:db8:cafe::53, 2001:db8:f00d::53]

	- Prefix Information Option: length = 4, prefix = 2001:db8:f00d::/64

It is expected that for some years, networks will have a mixed
environment of PvD-aware hosts and non-PvD-aware hosts. If there is a
need to give specific information to PvD-aware hosts only, then it is
recommended to send TWO RA messages: one for each class of hosts. For
example, here is the RA for non-PvD-aware hosts:

- RA Header: router lifetime = 6000 (non-PvD-aware hosts will use
this router as a default router)

- Prefix Information Option: length = 4, prefix = 2001:db8:cafe::/64

- Recursive DNS Server Option: length = 3, addresses= [2001:db8:cafe::53]

- PvD Option header: length = 3 + 2, PvD ID FQDN = foo.example.org., R-flag = 1 (actual length of the header 24 bytes = 3 * 8 bytes)

	- RA Header: router lifetime = 0 (PvD-aware hosts will not use this router as a default router), implicit length = 2

And here is a RA example for PvD-aware hosts:

- RA Header: router lifetime = 0 (non-PvD-aware hosts will not use
this router as a default router)

- PvD Option header: length = 3 + 2 + 4 + 3, PvD ID FQDN =
example.org., R-flag = 1 (actual length of the header 24 bytes = 3 *
8 bytes)

	- RA Header: router lifetime = 1600 (PvD-aware hosts will use this router as a default router), implicit length = 2

	- Prefix Information Option: length = 4, prefix = 2001:db8:f00d::/64

	- Recursive DNS Server Option: length = 3, addresses = [2001:db8:f00d::53]

In the above example, non-PvD-aware hosts will only use the first RA
sent from their default router and using the 2001:db8:cafe::/64 prefix.
PvD-aware hosts will autonomously configure addresses from both PIOs,
but will only use the source address in 2001:db8:f00d::/64 to
communicate past the first hop router since only the router sending the
second RA will be used as default router; similarly, they will use the
DNS server 2001:db8:f00d::53 when communicating with this adress.

# Security Considerations {#security}

Although some solutions such as IPsec or SeND {{?RFC3971}}
can be used in order to secure the IPv6 Neighbor
Discovery Protocol, in practice actual deployments largely rely on link
layer or physical layer security mechanisms (e.g. 802.1x {{IEEE8021X}})
in conjunction with RA Guard {{?RFC6105}}.

This specification does not improve the Neighbor Discovery Protocol
security model, but extends the purely link-local trust relationship
between the host and the default routers with HTTP over TLS
communications which servers are authenticated as rightful owners of the
FQDN received within the trusted PvD ID RA option.

It must be noted that {{misconfig}} of this document
only provides reasonable assurance against misconfiguration but does not
prevent an hostile network access provider to advertize wrong
information that could lead applications or hosts to select an hostile
PvD. Users should always apply caution when connecting to an unknown
network.

# Privacy Considerations

Retrieval of the PvD Additional Information over HTTPS requires early
communications between the connecting host and a server which may be
located further than the first hop router. Although this server is
likely to be located within the same administrative domain as the
default router, this property can't be ensured. Therefore, hosts willing
to retrieve the PvD Additional Information before using it without
leaking identity information, SHOULD make use of an IPv6 Privacy Address
and SHOULD NOT include any privacy sensitive data, such as User Agent
header or HTTP cookie, while performing the HTTP over TLS query.

From a privacy perspective, retrieving the PvD Additional Information
is not different from establishing a first connection to a remote
server, or even performing a single DNS lookup. For example, most
operating systems already perform early queries to well known web sites,
such as http://captive.example.com/hotspot-detect.html, in order to
detect the presence of a captive portal.

There may be some cases where hosts, for privacy reasons, should
refrain from accessing servers that are located outside a certain
network boundary. In practice, this could be implemented as a whitelist
of 'trusted' FQDNs and/or IP prefixes that the host is allowed to
communicate with. In such scenarios, the host SHOULD check that the
provided PvD ID, as well as the IP address that it resolves into, are
part of the allowed whitelist.

# IANA Considerations {#iana}

Upon publication of this document, IANA is asked to remove the
'reclaimable' tag off the value 21 for the PvD option (from the IPv6
Neighbor Discovery Option Formats registry).

IANA is asked to assign the value "pvd" from the Well-Known URIs
registry.

## Additional Information PvD Keys Registry

IANA is asked to create and maintain a new registry called
"Additional Information PvD Keys", which will reserve JSON keys for
use in PvD additional information. The initial contents of this
registry are given in {{aiformat}}.

New assignments for Additional Information PvD Keys Registry will
be administered by IANA through Expert Review {{!RFC8126}}.

## PvD Option Flags Registry

IANA is also asked to create and maintain a new registry entitled
"PvD Option Flags" reserving bit positions from 0 to 15 to be used in
the PvD option bitmask. Bit position 0, 1 and 2 are reserved by this
document (as specified in {{format}}). Future assignments
require Standards Action {{!RFC8126}}, via a
Standards Track RFC document.

## PvD JSON Media Type Registration

This document registers the media type for PvD JSON text,
"application/pvd+json".

Type Name: application

Subtype Name: pvd+json

Required parameters: None

Optional parameters: None

Encoding considerations: Encoding considerations are identical to
those specified for the "application/json" media type.

Security considerations: See {{security}}.

Interoperability considerations: This document specifies format of
conforming messages and the interpretation thereof.

Published specification: This document

Applications that use this media type: This media type is intended
to be used by network advertising additional Provisioning Domain
information, and clients looking up such information.

Additional information: None

Person and email address to contact for further information: See
Authors' Addresses section

Intended usage: COMMON

Restrictions on usage: None

Author: IETF

Change controller: IETF

# Acknowledgments

Many thanks to M. Stenberg and S. Barth for their earlier work: 
{{?I-D.stenberg-mif-mpvd-dns}}, as well as to Basile Bruneau who
was author of an early version of this document.

Thanks also to Marcus Keane, Mikael Abrahamsson, Ray Bellis, Zhen
Cao, Tim Chow, Lorenzo Colitti, Michael Di Bartolomeo, Ian Farrer,
Phillip Hallam-Baker, Bob Hinden, Tatuya Jinmei, Erik Kline, Ted Lemon,
Jen Lenkova, Veronika McKillop, Mark Townsley and James Woodyatt for
useful and interesting discussions and reviews.

Finally, special thanks to Thierry Danis and Wenqin Shao for their
valuable inputs and implementation efforts,
Tom Jones for his integration effort into the NEAT project and Rigil
Salim for his implementation work.
