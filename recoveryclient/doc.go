// Package recoveryclient is the product side of the suite's backup contract with
// KyRecovery: pin the suite recovery public key, pair with a KyRecovery server, seal the
// product's payload into a capsule, deliver it to a local directory and to KyRecovery on a
// schedule, drill a restore against a throwaway key, and restore from custodian shares.
//
// The product supplies what differs per product: a Settings row store, a Sealer under its
// deployment key, a collect func that says what to seal, and a checks func for the drill.
// Config, HTTP handlers, UI, audit and docs stay in the product. Nothing here ever holds
// the suite recovery private key or a share, except Restore, for the duration of one call.
package recoveryclient
