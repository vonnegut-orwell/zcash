bool CheckTransaction(const CTransaction& tx, CValidationState &state,
                      libzcash::ProofVerifier& verifier)
{
    // Don't count coinbase transactions because mining skews the count
    if (!tx.IsCoinBase()) {
        transactionsValidated.increment();
    }

    if (!CheckTransactionWithoutProofVerification(tx, state)) {
        return false;
    } else {
        // Ensure that zk-SNARKs verify
        BOOST_FOREACH(const JSDescription &joinsplit, tx.vjoinsplit) {
            if (!joinsplit.Verify(*pzcashParams, verifier, tx.joinSplitPubKey)) {
                return state.DoS(100, error("CheckTransaction(): joinsplit does not verify"),
                                    REJECT_INVALID, "bad-txns-joinsplit-verification-failed");
            }
        }
        return true;
    }
    
    bool CheckTransactionWithoutProofVerification(const CTransaction& tx, CValidationState &state)
{
    // Basic checks that don't depend on any context

    // Check transaction version
    if (tx.nVersion < MIN_TX_VERSION) {
        return state.DoS(100, error("CheckTransaction(): version too low"),
                         REJECT_INVALID, "bad-txns-version-too-low");
    }

    // Transactions can contain empty `vin` and `vout` so long as
    // `vjoinsplit` is non-empty.
    if (tx.vin.empty() && tx.vjoinsplit.empty())
        return state.DoS(10, error("CheckTransaction(): vin empty"),
                         REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty() && tx.vjoinsplit.empty())
        return state.DoS(10, error("CheckTransaction(): vout empty"),
                         REJECT_INVALID, "bad-txns-vout-empty");

    // Size limits
    BOOST_STATIC_ASSERT(MAX_BLOCK_SIZE > MAX_TX_SIZE); // sanity
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > MAX_TX_SIZE)
        return state.DoS(100, error("CheckTransaction(): size limits failed"),
                         REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    CAmount nValueOut = 0;
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, error("CheckTransaction(): txout.nValue negative"),
                             REJECT_INVALID, "bad-txns-vout-negative");
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, error("CheckTransaction(): txout.nValue too high"),
                             REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, error("CheckTransaction(): txout total out of range"),
                             REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    // Ensure that joinsplit values are well-formed
    BOOST_FOREACH(const JSDescription& joinsplit, tx.vjoinsplit)
    {
        if (joinsplit.vpub_old < 0) {
            return state.DoS(100, error("CheckTransaction(): joinsplit.vpub_old negative"),
                             REJECT_INVALID, "bad-txns-vpub_old-negative");
        }

        if (joinsplit.vpub_new < 0) {
            return state.DoS(100, error("CheckTransaction(): joinsplit.vpub_new negative"),
                             REJECT_INVALID, "bad-txns-vpub_new-negative");
        }

        if (joinsplit.vpub_old > MAX_MONEY) {
            return state.DoS(100, error("CheckTransaction(): joinsplit.vpub_old too high"),
                             REJECT_INVALID, "bad-txns-vpub_old-toolarge");
        }

        if (joinsplit.vpub_new > MAX_MONEY) {
            return state.DoS(100, error("CheckTransaction(): joinsplit.vpub_new too high"),
                             REJECT_INVALID, "bad-txns-vpub_new-toolarge");
        }

        if (joinsplit.vpub_new != 0 && joinsplit.vpub_old != 0) {
            return state.DoS(100, error("CheckTransaction(): joinsplit.vpub_new and joinsplit.vpub_old both nonzero"),
                             REJECT_INVALID, "bad-txns-vpubs-both-nonzero");
        }

        nValueOut += joinsplit.vpub_old;
        if (!MoneyRange(nValueOut)) {
            return state.DoS(100, error("CheckTransaction(): txout total out of range"),
                             REJECT_INVALID, "bad-txns-txouttotal-toolarge");
        }
    }

    // Ensure input values do not exceed MAX_MONEY
    // We have not resolved the txin values at this stage,
    // but we do know what the joinsplits claim to add
    // to the value pool.
    {
        CAmount nValueIn = 0;
        for (std::vector<JSDescription>::const_iterator it(tx.vjoinsplit.begin()); it != tx.vjoinsplit.end(); ++it)
        {
            nValueIn += it->vpub_new;

            if (!MoneyRange(it->vpub_new) || !MoneyRange(nValueIn)) {
                return state.DoS(100, error("CheckTransaction(): txin total out of range"),
                                 REJECT_INVALID, "bad-txns-txintotal-toolarge");
            }
        }
    }


    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, error("CheckTransaction(): duplicate inputs"),
                             REJECT_INVALID, "bad-txns-inputs-duplicate");
        vInOutPoints.insert(txin.prevout);
    }

    // Check for duplicate joinsplit nullifiers in this transaction
    set<uint256> vJoinSplitNullifiers;
    BOOST_FOREACH(const JSDescription& joinsplit, tx.vjoinsplit)
    {
        BOOST_FOREACH(const uint256& nf, joinsplit.nullifiers)
        {
            if (vJoinSplitNullifiers.count(nf))
                return state.DoS(100, error("CheckTransaction(): duplicate nullifiers"),
                             REJECT_INVALID, "bad-joinsplits-nullifiers-duplicate");

            vJoinSplitNullifiers.insert(nf);
        }
    }

    if (tx.IsCoinBase())
    {
        // There should be no joinsplits in a coinbase transaction
        if (tx.vjoinsplit.size() > 0)
            return state.DoS(100, error("CheckTransaction(): coinbase has joinsplits"),
                             REJECT_INVALID, "bad-cb-has-joinsplits");

        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100)
            return state.DoS(100, error("CheckTransaction(): coinbase script size"),
                             REJECT_INVALID, "bad-cb-length");
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, error("CheckTransaction(): prevout is null"),
                                 REJECT_INVALID, "bad-txns-prevout-null");

        if (tx.vjoinsplit.size() > 0) {
            // Empty output script.
            CScript scriptCode;
            uint256 dataToBeSigned;
            try {
                dataToBeSigned = SignatureHash(scriptCode, tx, NOT_AN_INPUT, SIGHASH_ALL);
            } catch (std::logic_error ex) {
                return state.DoS(100, error("CheckTransaction(): error computing signature hash"),
                                 REJECT_INVALID, "error-computing-signature-hash");
            }

            BOOST_STATIC_ASSERT(crypto_sign_PUBLICKEYBYTES == 32);

            // We rely on libsodium to check that the signature is canonical.
            // https://github.com/jedisct1/libsodium/commit/62911edb7ff2275cccd74bf1c8aefcc4d76924e0
            if (crypto_sign_verify_detached(&tx.joinSplitSig[0],
                                            dataToBeSigned.begin(), 32,
                                            tx.joinSplitPubKey.begin()
                                           ) != 0) {
                return state.DoS(100, error("CheckTransaction(): invalid joinsplit signature"),
                                 REJECT_INVALID, "bad-txns-invalid-joinsplit-signature");
            }
        }
    }

    return true;
}
