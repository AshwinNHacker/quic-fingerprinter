"""
Known-answer test vectors sourced directly from the published IETF
RFCs (not drafts -- see the note in quicfp/initial_crypto.py about an
earlier draft salt that changed before publication). Every hex blob
here is transcribed verbatim from the RFC text so that our
implementation can be checked against ground truth rather than
against itself.

Sources:
    RFC 9369 (QUIC Version 2), Appendix A -- "Sample Packet Protection"
    https://www.rfc-editor.org/rfc/rfc9369.html#appendix-A
"""

# RFC 9369 Appendix A.2 "Client Initial" -- the full protected wire
# packet, transcribed with whitespace removed.
RFC9369_CLIENT_INITIAL_PACKET_HEX = (
    "d76b3343cf088394c8f03e5157080000449ea0c95e82ffe67b6abcdb4298b485"
    "dd04de806071bf03dceebfa162e75d6c96058bdbfb127cdfcbf903388e99ad04"
    "9f9a3dd4425ae4d0992cfff18ecf0fdb5a842d09747052f17ac2053d21f57c5d"
    "250f2c4f0e0202b70785b7946e992e58a59ac52dea6774d4f03b55545243cf1a"
    "12834e3f249a78d395e0d18f4d766004f1a2674802a747eaa901c3f10cda5500"
    "cb9122faa9f1df66c392079a1b40f0de1c6054196a11cbea40afb6ef5253cd68"
    "18f6625efce3b6def6ba7e4b37a40f7732e093daa7d52190935b8da58976ff33"
    "12ae50b187c1433c0f028edcc4c2838b6a9bfc226ca4b4530e7a4ccee1bfa2a3"
    "d396ae5a3fb512384b2fdd851f784a65e03f2c4fbe11a53c7777c023462239dd"
    "6f7521a3f6c7d5dd3ec9b3f233773d4b46d23cc375eb198c63301c21801f6520"
    "bcfb7966fc49b393f0061d974a2706df8c4a9449f11d7f3d2dcbb90c6b877045"
    "636e7c0c0fe4eb0f697545460c806910d2c355f1d253bc9d2452aaa549e27a1f"
    "ac7cf4ed77f322e8fa894b6a83810a34b361901751a6f5eb65a0326e07de7c12"
    "16ccce2d0193f958bb3850a833f7ae432b65bc5a53975c155aa4bcb4f7b2c4e5"
    "4df16efaf6ddea94e2c50b4cd1dfe06017e0e9d02900cffe1935e0491d77ffb4"
    "fdf85290fdd893d577b1131a610ef6a5c32b2ee0293617a37cbb08b847741c3b"
    "8017c25ca9052ca1079d8b78aebd47876d330a30f6a8c6d61dd1ab5589329de7"
    "14d19d61370f8149748c72f132f0fc99f34d766c6938597040d8f9e2bb522ff9"
    "9c63a344d6a2ae8aa8e51b7b90a4a806105fcbca31506c446151adfeceb51b91"
    "abfe43960977c87471cf9ad4074d30e10d6a7f03c63bd5d4317f68ff325ba3bd"
    "80bf4dc8b52a0ba031758022eb025cdd770b44d6d6cf0670f4e990b22347a7db"
    "848265e3e5eb72dfe8299ad7481a408322cac55786e52f633b2fb6b614eaed18"
    "d703dd84045a274ae8bfa73379661388d6991fe39b0d93debb41700b41f90a15"
    "c4d526250235ddcd6776fc77bc97e7a417ebcb31600d01e57f32162a8560cacc"
    "7e27a096d37a1a86952ec71bd89a3e9a30a2a26162984d7740f81193e8238e61"
    "f6b5b984d4d3dfa033c1bb7e4f0037febf406d91c0dccf32acf423cfa1e70710"
    "10d3f270121b493ce85054ef58bada42310138fe081adb04e2bd901f2f13458b"
    "3d6758158197107c14ebb193230cd1157380aa79cae1374a7c1e5bbcb80ee23e"
    "06ebfde206bfb0fcbc0edc4ebec309661bdd908d532eb0c6adc38b7ca7331dce"
    "8dfce39ab71e7c32d318d136b6100671a1ae6a6600e3899f31f0eed19e3417d1"
    "34b90c9058f8632c798d4490da4987307cba922d61c39805d072b589bd52fdf1"
    "e86215c2d54e6670e07383a27bbffb5addf47d66aa85a0c6f9f32e59d85a44dd"
    "5d3b22dc2be80919b490437ae4f36a0ae55edf1d0b5cb4e9a3ecabee93dfc6e3"
    "8d209d0fa6536d27a5d6fbb17641cde27525d61093f1b28072d111b2b4ae5f89"
    "d5974ee12e5cf7d5da4d6a31123041f33e61407e76cffcdcfd7e19ba58cf4b53"
    "6f4c4938ae79324dc402894b44faf8afbab35282ab659d13c93f70412e85cb19"
    "9a37ddec600545473cfb5a05e08d0b209973b2172b4d21fb69745a262ccde96b"
    "a18b2faa745b6fe189cf772a9f84cbfc"
)

RFC9369_CLIENT_INITIAL_DCID_HEX = "8394c8f03e515708"
RFC9369_CLIENT_INITIAL_EXPECTED_HEADER_HEX = "d36b3343cf088394c8f03e5157080000449e00000002"
RFC9369_CLIENT_INITIAL_EXPECTED_PN = 2

RFC9369_INITIAL_SALT_HEX = "0dede3def700a6db819381be6e269dcbf9bd2ed9"
RFC9369_INITIAL_SECRET_HEX = (
    "2062e8b3cd8d52092614b8071d0aa1fb7c2e3ac193f78b280e72d8f5751f6aba"
)
RFC9369_CLIENT_INITIAL_SECRET_HEX = (
    "14ec9d6eb9fd7af83bf5a668bc17a7e283766aade7ecd0891f70f9ff7f4bf47b"
)
RFC9369_CLIENT_KEY_HEX = "8b1a0bc121284290a29e0971b5cd045d"
RFC9369_CLIENT_IV_HEX = "91f73e2351d8fa91660e909f"
RFC9369_CLIENT_HP_HEX = "45b95e15235d6f45a6b19cbcb0294ba9"

# The first 40 bytes of the reassembled TLS ClientHello handshake
# message that this Initial packet's CRYPTO frame carries.
RFC9369_CLIENTHELLO_PREFIX_HEX = (
    "010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e86804fe3a47f06a2b69484c0000"
)
