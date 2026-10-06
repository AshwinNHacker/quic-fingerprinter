# Legal & Ethical Use

`quicfp` is a defensive network-visibility tool intended for:

- Security operations centers analyzing traffic on networks you own,
  operate, or are explicitly authorized to monitor (corporate
  networks, your own lab, CTF/research environments).
- Security research into QUIC/HTTP3 protocol visibility and traffic
  analysis.
- Building or evaluating NIDS/firewall QUIC-inspection capability.

## What this tool does NOT do

- It does **not** break QUIC's real end-to-end encryption. The Initial
  packet decryption implemented here (`quicfp/initial_crypto.py`) uses
  only a publicly documented salt (published in RFC 9001/9369 text)
  and the packet's own cleartext Destination Connection ID -- exactly
  the mechanism every QUIC-aware NIDS (Zeek, Suricata, Wireshark) uses,
  and one the IETF QUIC working group designed in specifically so that
  network intermediaries retain the visibility they historically had
  into TLS-over-TCP ClientHellos. See `docs/ARCHITECTURE.md` for
  detail.
- It does **not** recover TLS application data, 1-RTT payload content,
  or anything protected by the connection's real negotiated keys.
- It is **not** an interception, decryption-at-scale, or key-exfiltration
  tool, and should not be represented as one.

## Your responsibility

Capturing and analyzing network traffic that you do not own or are not
authorized to monitor may violate wiretapping, computer-misuse, or
privacy laws in your jurisdiction (in the US, this includes but is not
limited to the Wiretap Act, 18 U.S.C. § 2511, and the Computer Fraud
and Abuse Act; equivalent statutes exist in most other countries).
Before using this tool:

- Only capture traffic on networks you own or have explicit written
  authorization to monitor.
- Follow your organization's data handling and retention policies for
  any SNI/metadata this tool extracts.
- If you are a security researcher, follow responsible disclosure
  practices for anything you discover using this tool.

This project is released under the MIT License with no warranty; see
`LICENSE`. The authors are not responsible for misuse.
