# External events for this test were generated by tracing the following PTB.
# Change the following addresses to match the account and the published package
# (testnet digest for this PTB transaction is CNiT7vcohmcLhCLKTTwLfiNDLsKLJCk2deCXph835fsf).
OWNER=0xa2a8354e11f917237842554fa8c9b4a3cedee8d452e8ee5a9c6a1406c39240ad
PKG_ID=0x1b8a97ccc6a6d0e4ee653df36b1ba56579191f76cca9c4bbfe73ca3d8faf2c3d

sui client ptb \
    --move-call $PKG_ID::global_assign_ref::create_outer_struct "42" \
    --assign outer_struct \
    --move-call $PKG_ID::global_assign_ref::foo outer_struct "7"
