
#include "Note.hpp"
#include "prf.h"
#include "crypto/sha256.h"

#include "version.h"
#include "streams.h"

#include "zcash/util.h"
#include "JoinSplit.hpp"
#include "sodium.h"

#include <memory>

#include <boost/foreach.hpp>
#include <boost/format.hpp>
#include <boost/optional.hpp>
#include <fstream>
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libsnark/gadgetlib1/gadgets/merkle_tree/merkle_tree_check_read_gadget.hpp"

#include "sync.h"
#include "amount.h"


namespace libzcash {
    
// Задачи: создаем Dummy Note . Что я хочу сделать?
    //(1) Абсолютно рандомно выбираем spending key, из которого выводится paying key
    //(2) rho и r тоже выбираем рандомно 
    //(3) Все входные значения в нашей note(v_i^{old}) задаем нулевыми
    //(4)  Вычисляем nullifier при помощи PseudoRandom function
    //(5) Создаем JoinpSplit Statement и JoinSplit proof.
    // Особенности: 
        //(5a) Путь у нас абсолютно фиктивный, ключа там может и не быть
        //(5b) В Merkle Tree мы должны задать enforceMerklePath_{i}=0
Note::Note() {
    a_pk = random_uint256();  // создаем paying key, т.к мы создаем Dummy Note, то он у нас рандомный (1)
    rho = random_uint256(); // снова выбираем его рандомно, ибо Dummy Note.  (2)
    // Зачем нам нужно это rho?
    // Когда мы будем вычислять nullifier, то мы будем использовать pseudo random function для вычисления nullifier.
    // Она "кушает" spending key и это самое rho. И при помощи SHA256Compress она вычисляет nellifier
    r = random_uint256(); // Выбираем его рандомно. произвольная последовательность, которую мы будем использовать как commitment trapdoor. 
    //Commitment scheme - это отображение из (Commitment trapdoor x Commitment Inputs) -> Commitment Outputs (2)
    value = 0;  // value нашей note: я хочу создать dummy note, поэтому значение у нас нулевое (3)
}

uint256 Note::cm() const {
    unsigned char discriminant = 0xb0;

    CSHA256 hasher; // используем SHA-256 compression function, которая возьмет 512-битный блок и создает 256-битный хеш
    hasher.Write(&discriminant, 1);
    hasher.Write(a_pk.begin(), 32);

    auto value_vec = convertIntToVectorLE(value);

    hasher.Write(&value_vec[0], value_vec.size());
    hasher.Write(rho.begin(), 32);
    hasher.Write(r.begin(), 32);

    uint256 result;
    hasher.Finalize(result.begin());

    return result;
}

uint256 Note::nullifier(const SpendingKey& a_sk) const {
    return PRF_nf(a_sk, rho); // вычисление nullifier происходит при помощи pseudorandom function (4)
    // Сам код для PRF я добавлять не стал - там какая-то криптографическая жуть.
}

 // PRF_nf:=SHA256Compress(252-bit a_sk, 256-bit \rho) - так определяется конкретно эта Pseudo Random в протоколе. (4)
    
    
 // Уже переданные notes хранятся в блокчейне(в зашифрованном виде, конечно) вместе с NoteCommitment. 
 // Вместе с JoinSptit description связан NotePlaintexts, который состоит из значения(value), rho, r(смотри на них выше) и memo. 
 // memo - это что-то типа соглашения между отправителем и получателем.
    
NotePlaintext::NotePlaintext(
    const Note& note,
    boost::array<unsigned char, ZC_MEMO_SIZE> memo) : memo(memo)
{
    value = note.value;
    rho = note.rho;
    r = note.r;
}

Note NotePlaintext::note(const PaymentAddress& addr) const
{
    return Note(addr.a_pk, value, rho, r);
}

NotePlaintext NotePlaintext::decrypt(const ZCNoteDecryption& decryptor,
                                     const ZCNoteDecryption::Ciphertext& ciphertext,
                                     const uint256& ephemeralKey,
                                     const uint256& h_sig,
                                     unsigned char nonce
                                    )
{
    auto plaintext = decryptor.decrypt(ciphertext, ephemeralKey, h_sig, nonce);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << plaintext;

    NotePlaintext ret;
    ss >> ret;

    assert(ss.size() == 0);

    return ret;
}

ZCNoteEncryption::Ciphertext NotePlaintext::encrypt(ZCNoteEncryption& encryptor,
                                                    const uint256& pk_enc
                                                   ) const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << (*this);

    ZCNoteEncryption::Plaintext pt;

    assert(pt.size() == ss.size());

    memcpy(&pt[0], &ss[0], pt.size());

    return encryptor.encrypt(pk_enc, pt);
}

}
// В нашей Note два вида информации: открытая(transparent) и скрытая(shielded). Последняя хранится в JoinSplit Description.
// JoinSplit Description состоит из JoinSplitTransfer - функции, которая "кушает" сколько-то notes и transparent input(NumInputs) и создает сколько-то новых notes(NumOutputs) и какие-то transparent value.

using namespace libsnark;

namespace libzcash {

#include "zcash/circuit/gadget.tcc"

CCriticalSection cs_ParamsIO;
CCriticalSection cs_LoadKeys;

template<typename T>
void saveToFile(std::string path, T& obj) {
    LOCK(cs_ParamsIO);

    std::stringstream ss;
    ss << obj;
    std::ofstream fh;
    fh.open(path, std::ios::binary);
    ss.rdbuf()->pubseekpos(0, std::ios_base::out);
    fh << ss.rdbuf();
    fh.flush();
    fh.close();
}

template<typename T>
void loadFromFile(std::string path, boost::optional<T>& objIn) {
    LOCK(cs_ParamsIO);

    std::stringstream ss;
    std::ifstream fh(path, std::ios::binary);

    if(!fh.is_open()) {
        throw std::runtime_error((boost::format("could not load param file at %s") % path).str());
    }

    ss << fh.rdbuf();
    fh.close();

    ss.rdbuf()->pubseekpos(0, std::ios_base::in);

    T obj;
    ss >> obj;

    objIn = std::move(obj);
}
// Ниже происходит проверка валидности все Input и Output данных. 
template<size_t NumInputs, size_t NumOutputs>
class JoinSplitCircuit : public JoinSplit<NumInputs, NumOutputs> {
public:
    typedef default_r1cs_ppzksnark_pp ppzksnark_ppT;
    typedef Fr<ppzksnark_ppT> FieldT;

    boost::optional<r1cs_ppzksnark_proving_key<ppzksnark_ppT>> pk;
    boost::optional<r1cs_ppzksnark_verification_key<ppzksnark_ppT>> vk;
    boost::optional<r1cs_ppzksnark_processed_verification_key<ppzksnark_ppT>> vk_precomp;
    boost::optional<std::string> pkPath;

    JoinSplitCircuit() {}
    ~JoinSplitCircuit() {}
    
// Указываем путь к нашему proving key и загружаем наш proving key, а затем сохраняем наш файл(и проверяем его существование, конечно).
//Т.к мы создаем Dummy Note, то путь может и не содержать proving Key - проверка JoinSlpit осуществляться не будет.

    void setProvingKeyPath(std::string path) {
        pkPath = path;  // Для Dummy Note мы выбираем асболютно левый путь, т.к проверка JoinSplit Staitment осуществляться не будет.
    }

    void loadProvingKey() {
        LOCK(cs_LoadKeys);

        if (!pk) {
            if (!pkPath) {
                throw std::runtime_error("proving key path unknown");
            }
            loadFromFile(*pkPath, pk);
        }
    }

    void saveProvingKey(std::string path) {
        if (pk) {
            saveToFile(path, *pk);
        } else {
            throw std::runtime_error("cannot save proving key; key doesn't exist"); //Здесь наша проверка и оборвется - proving key просто не существует у Dummy Note.
        }
    }
    
    // Проделываем аналогичное для Verifying Key
    
    void loadVerifyingKey(std::string path) {
        LOCK(cs_LoadKeys);

        loadFromFile(path, vk);

        processVerifyingKey();
    }
    void processVerifyingKey() {
        vk_precomp = r1cs_ppzksnark_verifier_process_vk(*vk);
    }
    void saveVerifyingKey(std::string path) {
        if (vk) {
            saveToFile(path, *vk);
        } else {
            throw std::runtime_error("cannot save verifying key; key doesn't exist");
        }
    }
    void saveR1CS(std::string path) {
        auto r1cs = generate_r1cs();

        saveToFile(path, r1cs);
    }

    r1cs_constraint_system<FieldT> generate_r1cs() {
        protoboard<FieldT> pb;

        joinsplit_gadget<FieldT, NumInputs, NumOutputs> g(pb);
        g.generate_r1cs_constraints();

        return pb.get_constraint_system();
    }

    void generate() {
        LOCK(cs_LoadKeys);

        const r1cs_constraint_system<FieldT> constraint_system = generate_r1cs();
        r1cs_ppzksnark_keypair<ppzksnark_ppT> keypair = r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);

        pk = keypair.pk;
        vk = keypair.vk;
        processVerifyingKey();
    }

    bool verify(
        const ZCProof& proof,
        ProofVerifier& verifier,
        const uint256& pubKeyHash,
        const uint256& randomSeed,
        const boost::array<uint256, NumInputs>& macs,
        const boost::array<uint256, NumInputs>& nullifiers,
        const boost::array<uint256, NumOutputs>& commitments,
        uint64_t vpub_old,
        uint64_t vpub_new,
        const uint256& rt
    ) {
        if (!vk || !vk_precomp) {
            throw std::runtime_error("JoinSplit verifying key not loaded");
        }

        try {
            auto r1cs_proof = proof.to_libsnark_proof<r1cs_ppzksnark_proof<ppzksnark_ppT>>();

            uint256 h_sig = this->h_sig(randomSeed, nullifiers, pubKeyHash);

            auto witness = joinsplit_gadget<FieldT, NumInputs, NumOutputs>::witness_map(
                rt,
                h_sig,
                macs,
                nullifiers,
                commitments,
                vpub_old,
                vpub_new
            );

            return verifier.check(
                *vk,
                *vk_precomp,
                witness,
                r1cs_proof
            );
        } catch (...) {
            return false;
        }
    }

    ZCProof prove(
        const boost::array<JSInput, NumInputs>& inputs,
        const boost::array<JSOutput, NumOutputs>& outputs,
        boost::array<Note, NumOutputs>& out_notes,
        boost::array<ZCNoteEncryption::Ciphertext, NumOutputs>& out_ciphertexts,
        uint256& out_ephemeralKey,
        const uint256& pubKeyHash,
        uint256& out_randomSeed,
        boost::array<uint256, NumInputs>& out_macs,
        boost::array<uint256, NumInputs>& out_nullifiers,
        boost::array<uint256, NumOutputs>& out_commitments,
        uint64_t vpub_old,
        uint64_t vpub_new,
        const uint256& rt,
        bool computeProof
    ) {
        if (computeProof && !pk) {
            throw std::runtime_error("JoinSplit proving key not loaded");
        }

        if (vpub_old > MAX_MONEY) {
            throw std::invalid_argument("nonsensical vpub_old value");           //Тут проверяется валидность всех значений на входе и выходе.
        }

        if (vpub_new > MAX_MONEY) {
            throw std::invalid_argument("nonsensical vpub_new value");
        }

        uint64_t lhs_value = vpub_old;
        uint64_t rhs_value = vpub_new;

        for (size_t i = 0; i < NumInputs; i++) {
            // Делаем нашу проверку inputs
            {
                // Они должны быть ненулевыми
                if (inputs[i].note.value != 0) {
                
                if (inputs[i].witness.root() != rt) {
                        throw std::invalid_argument("joinsplit not anchored to the correct root");
                    }
                    
                    if (inputs[i].note.cm() != inputs[i].witness.element()) {
                        throw std::invalid_argument("witness of wrong element for joinsplit input");
                    }
                }

                // У note должен быть ключ
                if (inputs[i].note.a_pk != inputs[i].key.address().a_pk) {
                    throw std::invalid_argument("input note not authorized to spend with given key");
                }

                // Проверяем, что значения на входе не выходят за доступные значения
                if (inputs[i].note.value > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical input note value");
                }

                lhs_value += inputs[i].note.value;
                
                // Проверяем баланс нашей Joinsplit: говоря грубо, сумма transparent(известных) значений и "скрытых" значений на входе должна быть равна сумме известных и "скрытых" значений ны выходею

                if (lhs_value > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical left hand size of joinsplit balance");
                }
            }

            // Вычисляем nulifier
            out_nullifiers[i] = inputs[i].nullifier();
        }

        // 
        out_randomSeed = random_uint256();

        // 
        uint256 h_sig = this->h_sig(out_randomSeed, out_nullifiers, pubKeyHash);

        // 
        uint252 phi = random_uint252();

        // 
        for (size_t i = 0; i < NumOutputs; i++) {
            // Проверяем наши outputs
            {
                if (outputs[i].value > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical output value");
                }

                rhs_value += outputs[i].value;

                if (rhs_value > MAX_MONEY) {
                    throw std::invalid_argument("nonsensical right hand side of joinsplit balance");
                }
            }

            // Sample r
            uint256 r = random_uint256();

            out_notes[i] = outputs[i].note(phi, r, i, h_sig);
        }

        if (lhs_value != rhs_value) {
            throw std::invalid_argument("invalid joinsplit balance");
        }

        // Вычисляем commitment
        for (size_t i = 0; i < NumOutputs; i++) {
            out_commitments[i] = out_notes[i].cm();
        }

        {
            ZCNoteEncryption encryptor(h_sig);

            for (size_t i = 0; i < NumOutputs; i++) {
                NotePlaintext pt(out_notes[i], outputs[i].memo);

                out_ciphertexts[i] = pt.encrypt(encryptor, outputs[i].addr.pk_enc);
            }

            out_ephemeralKey = encryptor.get_epk();
        }

        for (size_t i = 0; i < NumInputs; i++) {
            out_macs[i] = PRF_pk(inputs[i].key, i, h_sig);
        }

        if (!computeProof) {
            return ZCProof();
        }

        protoboard<FieldT> pb;
        {
            joinsplit_gadget<FieldT, NumInputs, NumOutputs> g(pb);
            g.generate_r1cs_constraints();
            g.generate_r1cs_witness(
                phi,
                rt,
                h_sig,
                inputs,
                out_notes,
                vpub_old,
                vpub_new
            );
        }

        assert(pb.is_satisfied());

        std::vector<FieldT> primary_input = pb.primary_input();
        std::vector<FieldT> aux_input = pb.auxiliary_input();

        pb.constraint_system.swap_AB_if_beneficial();

        return ZCProof(r1cs_ppzksnark_prover<ppzksnark_ppT>(
            *pk,
            primary_input,
            aux_input,
            pb.constraint_system
        ));
    }
};

template<size_t NumInputs, size_t NumOutputs>
JoinSplit<NumInputs, NumOutputs>* JoinSplit<NumInputs, NumOutputs>::Generate()
{
    initialize_curve_params();
    auto js = new JoinSplitCircuit<NumInputs, NumOutputs>();
    js->generate();

    return js;
}

template<size_t NumInputs, size_t NumOutputs>
JoinSplit<NumInputs, NumOutputs>* JoinSplit<NumInputs, NumOutputs>::Unopened()
{
    initialize_curve_params();
    return new JoinSplitCircuit<NumInputs, NumOutputs>();
}

template<size_t NumInputs, size_t NumOutputs>
uint256 JoinSplit<NumInputs, NumOutputs>::h_sig(
    const uint256& randomSeed,
    const boost::array<uint256, NumInputs>& nullifiers,
    const uint256& pubKeyHash
) {
    const unsigned char personalization[crypto_generichash_blake2b_PERSONALBYTES]
        = {'Z','c','a','s','h','C','o','m','p','u','t','e','h','S','i','g'};

    std::vector<unsigned char> block(randomSeed.begin(), randomSeed.end());

    for (size_t i = 0; i < NumInputs; i++) {
        block.insert(block.end(), nullifiers[i].begin(), nullifiers[i].end());
    }

    block.insert(block.end(), pubKeyHash.begin(), pubKeyHash.end());

    uint256 output;

    if (crypto_generichash_blake2b_salt_personal(output.begin(), 32,
                                                 &block[0], block.size(),
                                                 NULL, 0, // No key.
                                                 NULL,    // No salt.
                                                 personalization
                                                ) != 0)
    {
        throw std::logic_error("hash function failure");
    }

    return output;
}

Note JSOutput::note(const uint252& phi, const uint256& r, size_t i, const uint256& h_sig) const {
    uint256 rho = PRF_rho(phi, i, h_sig);

    return Note(addr.a_pk, value, rho, r);
}

JSOutput::JSOutput() : addr(uint256(), uint256()), value(0) {
    SpendingKey a_sk = SpendingKey::random();
    addr = a_sk.address();
}

JSInput::JSInput() : witness(ZCIncrementalMerkleTree().witness()),
                     key(SpendingKey::random()) {
    note = Note(key.address().a_pk, 0, random_uint256(), random_uint256());
    ZCIncrementalMerkleTree dummy_tree;
    dummy_tree.append(note.cm());
    witness = dummy_tree.witness();
}

template class JoinSplit<ZC_NUM_JS_INPUTS,
                         ZC_NUM_JS_OUTPUTS>;

}

// Само вычисление JoinSplit:

using namespace libzcash;

int main(int argc, char **argv)
{
    libsnark::start_profiling();

    auto p = ZCJoinSplit::Unopened();
    p->loadVerifyingKey((ZC_GetParamsDir() / "sprout-verifying.key").string());
    p->setProvingKeyPath((ZC_GetParamsDir() / "sprout-proving.key").string());
    p->loadProvingKey();

    // Тут описание доказательства JoinSplit.

    for (int i = 0; i < 5; i++) {
        uint256 anchor = ZCIncrementalMerkleTree().root();
        uint256 pubKeyHash;

        JSDescription jsdesc(*p,
                             pubKeyHash,
                             anchor,
                             {JSInput(), JSInput()},
                             {JSOutput(), JSOutput()},
                             0,
                             0);
    }
}
