// Задачи: что я хочу сделать?
    //(1) Создаем Dummy Note(все данные выбираются рандомно, кроме значения - оно 0) Строчки: 39-48
        //(1а) Важно! Создание Note Plaintext(которое содержит memo) и notecommitment Строчки: 78-132
    //(2) Вычисляем nullifier при помощи PseudoRandom function Строчки: 69-74
    //(3) Создаем JoinpSplit Statement. Строчки: 133-313 - тут описание всего процесса
        //(3а) непосредственное создание. Строчки: 546-574
    //(4) Создаем JoinSplit Proof       Строчки: 313-543
    //(5) Реализуем JoinSplit Proof     Строчки: 575-592
    //(6) Осуществляем проверку транзакции  Строчки: 594-до конца
        //(6a) Всякие мелочи типа входных значений Строчки: 594-708
        //(6b) Проверка nullifier-а     Строчки: 709-до конца

// Вся работа поделилась на два блока:
        // БЛОК 1: создание самой Note и Note plainext вместе с memo Notes.cpp в zcash/src/zcash

        //Где найти: Notes.cpp

                //1.1 - описание фрагмента, который просто задает Note
                //1.2 - хеширование ключей и прочего
                //1.3 - создание nullifier
                //1.5 - создание NotePlaintText

        // БЛОК 2: создание Joinslpit Statement, влючая сшифровку и расшифровку Note Plaintext и Ciphertext
        // Где найти:Joinsplit.cpp и Create_Joinsplit.cpp

                //2.1 - процесс зашифровки NotePlaintext
                //2.2 - проверка JoinSplit (описание всех тонкостей на языке c++), включая вычисление ZCProof
                //2.3 - непосредственное создание и вычисление JoinSplit
                //2.4 - расшифровка Ciphertext

#include "Note.hpp"  // Подключаем все необходимые "подключаемые файлы(формат hpp), в которых указаны классы функций, имен и т.д. Тут у нас классы и функции, которые нужны для создания N
#include "prf.h"    // Подключаем все, что нужно для pseudo random functions
#include "crypto/sha256.h"  //

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

//БЛОК 1: создание Note. В нем есть функция Note, которая и принадлежит классу Note.
// Подключаем пространство имен libzcash /
namespace libzcash { 
// В файлу "Note.hpp" был определен класс функций Note, который мы и использем. 
// Ниже мы используем оператор разрешения области видимости(двойное двоеточие), который имеет такой общий вид:
// Общий вид: class :: function. В нашем случае есть класс Note, а есть функция Note, у которой нет входных аргументов(они в фигурных скобках).
// БЛОК 1.1: создание самое Dummy Note   
        //Что кушает эта функция: ничего она не кушает. Мы создаем Dummy Note - все вбивается рандомно. 
        //Что этот блок возвращает: у тебя будут paying key, rho и r.
Note::Note() { //В фигурных скобках записано тело программы, который описывает создание Dummy Note
    a_pk = random_uint256();  // создаем paying key, т.к мы создаем Dummy Note, то он у нас рандомный (1)
    rho = random_uint256(); // снова выбираем его рандомно, ибо Dummy Note.  (2)
    // Зачем нам нужно это rho?
    // Когда мы будем вычислять nullifier, то мы будем использовать pseudo random function для вычисления nullifier.
    // Она "кушает" spending key и это самое rho. И при помощи SHA256Compress она вычисляет nellifier
    r = random_uint256(); // Выбираем его рандомно. произвольная последовательность, которую мы будем использовать как commitment trapdoor. 
    //Commitment scheme - это отображение из (Commitment trapdoor x Commitment Inputs) -> Commitment Outputs (2)
    value = 0;  // value нашей note: я хочу создать dummy note, поэтому значение у нас нулевое (3)
}
 // БЛОК 1.2: мы хешируем 
 // Что он кушает: ничего, кроме вышеназванного paying key.
 // Что он возвращает: захешированный paying key
uint256 Note::cm() const { // uinte 256 указывает, что наша функция возвращает 256-bit unsigned integer
    unsigned char discriminant = 0xb0; // тут указываем, что это дискриминант формата unsigned char 

    CSHA256 hasher; //вызываем класс CSHA256, который объявлен в sha256.h
    hasher.Write(&discriminant, 1);
    hasher.Write(a_pk.begin(), 32);

    auto value_vec = convertIntToVectorLE(value);

    hasher.Write(&value_vec[0], value_vec.size());
    hasher.Write(rho.begin(), 32); //Функция Write описана в "sha256.h"
    hasher.Write(r.begin(), 32);

    uint256 result; // вводим новую переменную results
    hasher.Finalize(result.begin()); //Функция Finalize описана в "sha256.h"

    return result; //Возвращаем нашу переменную result 
    // Конкретно эта часть:
}
 //БЛОК 1.3: создание nullifier
    //Что кушает: a_sk - spending key
    //Что возвращает: результат работы псевдо-рандомной функции для nullifier
uint256 Note::nullifier(const SpendingKey& a_sk) const { // тут она кушает spendingKey и a_sk, но не может их менять - там const рядом)
    return PRF_nf(a_sk, rho); // вычисление nullifier происходит при помощи pseudorandom function (4)
    // Сам код для PRF я добавлять не стал - там какая-то криптографическая жуть.
}

 // PRF_nf:=SHA256Compress(252-bit a_sk, 256-bit \rho) - так определяется конкретно эта Pseudo Random function в протоколе. (4)
 // Возвращаем результат работы нашей псевдо-рандомной функции   
    
 // Уже переданные notes хранятся в блокчейне(в зашифрованном виде, конечно) вместе с NoteCommitment. 
 // Вместе с JoinSptit description связан NotePlaintexts, который состоит из значения(value), rho, r(смотри на них выше) и memo. 
 // memo - это что-то типа соглашения между отправителем и получателем.
 // Блок 1.4: создание NotePlainText   
NotePlaintext::NotePlaintext(
    const Note& note,
    boost::array<unsigned char, ZC_MEMO_SIZE> memo) : memo(memo)
// Тут мы используем библиотеку boost::array - создаем массив. 
{
    value = note.value;
    rho = note.rho;   // Достаем значение из note: стандартный вид(файл, из которого достаем нужное свойство)
    r = note.r;       // Например: note - это файл, а r - это свойсвто
}

Note NotePlaintext::note(const PaymentAddress& addr) const
{
    return Note(addr.a_pk, value, rho, r); 
    // Тут описание самой note - это вывод выходных данных функции Note, которая объявлена в самом начале
}
//БЛОК 2.1: процесс зашифровки NotePlaintext
    //Что кушает: кушает Noteplaintext(который потом обозначат за pt) и один из ephemeral key, который тут обозначен за pk_enc
    //Что выдает: NoteCliphertext, который нужен для JoinSlpit Description - это результат работы функции ecrtypt, которая описана ниже
    
ZCNoteEncryption::Ciphertext NotePlaintext::encrypt(ZCNoteEncryption& encryptor,
                                                    const uint256& pk_enc
                                                   ) const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << (*this);

    ZCNoteEncryption::Plaintext pt; //Обозначаем plaintext за pt

    assert(pt.size() == ss.size());

    memcpy(&pt[0], &ss[0], pt.size());

    return encryptor.encrypt(pk_enc, pt);
}   
    

//БЛОК 2.2: Проверка JoinSplit
// В нашей Note два вида информации: открытая(transparent) и скрытая(shielded). Последняя хранится в JoinSplit Description.
// JoinSplit Description состоит из JoinSplitTransfer - функции, которая "кушает" сколько-то notes и transparent input(NumInputs) и создает сколько-то новых notes(NumOutputs) и какие-то transparent value.
//Что происходит: Ниже дано строгое описание проверки Joinsplit-а. 
//Что кушает: входные и выходные shielded значения, хеш Note CipherText
// Что выдает: зашефрованные CipherText и epc - он нам нужен для рассшифровки. 
    
    
// Тут подробное описание устройства Joinslput, включая ZCProof    

using namespace libsnark;

namespace libzcash {

#include "zcash/circuit/gadget.tcc"

CCriticalSection cs_ParamsIO;
CCriticalSection cs_LoadKeys;

template<typename T>
void saveToFile(std::string path, T& obj) {     //void - это функция, которая ничего не возвращает 
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
    
// Разбераемся со всеми ключами, у нас есть: 
// (1): Payment adress, который создается получателем - он состоит из paying key и transmission key
// (2): Viewing Key - он состоит из Viewing key and Receiving Key
// (3): Spending Key - лежит у получателя 
// (4): Для проверки JoinSplit Description нужны proving и verifying keys - они общедоступны и одинаковые у всех. При помощи этих ключей подтверждается вся информация в JoinSplit
// (5): Уже в самом JoinSplit создаются два ключа - Ephermal Keys. Они нужны для того, чтобы зашифровать Note PlainTexts, а затем его расшифровать после Zk-SNARK.

// Указываем путь к нашему proving key и загружаем наш proving key(нужен путь к файлу "sprout-proving.key")
    void setProvingKeyPath(std::string path) {
        pkPath = path;   
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
            throw std::runtime_error("cannot save proving key; key doesn't exist"); 
        }
    }
    
    // Проделываем аналогичное для Verifying Key(нужен путь к "sprout-verifying.key")
    
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
    // Описание ZCProof. В скобках описаны все-все-все входные параметры, которая она кушает.
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
            throw std::invalid_argument("nonsensical vpub_old value");          
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

            out_ephemeralKey = encryptor.get_epk(); //Здесь мы получаем epk, который будет нужен для  расшифровки.
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

//БЛОК 2.3: создание и вычисление JoinSplit

using namespace libzcash;

int main(int argc, char **argv)
{
    libsnark::start_profiling();

    auto p = ZCJoinSplit::Unopened();
    p->loadVerifyingKey((ZC_GetParamsDir() / "sprout-verifying.key").string());
    p->setProvingKeyPath((ZC_GetParamsDir() / "sprout-proving.key").string());
    p->loadProvingKey();

    // Тут описание доказательства JoinSplit. Сначала мы его строим:

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

     // Затем реализуем:

        proof = js->prove(
            inputs,
            outputs,
            output_notes,
            ciphertexts,
            ephemeralKey,
            pubKeyHash,
            randomSeed,
            macs,
            nullifiers,
            commitments,
            vpub_old,
            vpub_new,
            rt
        );
    }

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

//БЛОК 2.4: тут мы расшифровываем уже проверенный Ciphertext при помощи epk ключа, который был получен при проверке JoinSplit
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
    
