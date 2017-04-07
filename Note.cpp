// В этой директории лежат все-все-все необходимые заголовочные файлы: они тут трех типов: .h и .hpp, а также без формата - это просто системные.
// Мой компилятор предпочитает .hpp, а с .h работает не так хорошо, но фатальных ошибок не выдает. 
// Подробнее про мой компилятор: я использую g++ - у меня он стоит изначально(Mandriva Linux), но его всегда можно скачать самостоятельно или через менеджер пакетов.
// Львиную долю времени заняла работа c .hpp файлами и стандартными библиотеками:
  //Не все .hpp файлы были "согласованы": нужно было указать корректные пути к другим .hpp и .h файлам, т.к видимо разработчики указывали пути к их собственным файлам, которые никак не согласованы с фалами zcash
  //Я решил проблему просто: нашел все заголовочные файлы, которые нам нужны и сбросил в одну папку. Они находятся в моем каталоге zcash
  //Самое замечательное: некоторые файлы были и вовсе "битыми". Так, например, файл с типами для NotePlainText не содержал никаких нужных нам типов и окружений, поэтому компилятор не могу сделать шифровку и расшифровку соответственно
  //Также были проблемы с библиотеками. 
    // Необходимые библиотеки:
    //boost - она загружается в папку include в директории самого компилятора, его я приложу отдельно.
    //Внимание(!!!): папка include под закрытым доступом, поэтому сначала нужно получить root(права администратора) и открыть include именно под правами администратора
    //Boost нам конкретно нужен для всяких массивов и т.п(не самая важная часть)

// Наиподробнейшая инструкция: 
  //(1) Нужно установить компилятор, конечно. Я выбрал g++ - можно смело заходить на сайт и качать оттуда, а затем устанавливать через консоль.
        // Но я пошел легким путем: зашел в менеджер, который отвечает за все пакеты системы(менеджер приложений, говоря грубо), нашел его там и установил
  //(2) После установки g++ советую сразу скачать boost с официального сайта, но я оставлю его в каталоге
  //(3) Дальше скачиваете эту директорию(в GitHub кнопка есть соответствующая) и распаковываете в какую-то одну папку 
  //(!!) Ничего нельзя никуда перекидывать в иные папки, иначе все пути нарушатся
  //(4) Дальше открываете консоль(повторюсь: я работаю на mandriva) в папке, куда распаковали ваши файлы
        //Это можно сделать либо через правую кнопку мыши -> Открыть в терминале
        //Либо просто ручками пропишите путь в терминале. ~/Zcash/zcash-master/src/zcash $ 

  //(5) Дальше начинается сам процесс компиляции. 
  // Прописываете: sudo g++ -std=c++11 Note.cpp
        // sudo - права администратора. Нужны лишь для того, чтобы подключиться к библиотеке boost, которая лежит в include
        // -std=c+11 - там определенные плюшки используют разработчики Zcash, которые есть в версиях >=11, поэтому прописываем это тоже
        //Например: в С++ 11 есть тип данных auto - он выбирается сам
        // Note.cpp - это имя файла
  // (6) Все, дальше терминал выдаст вам все ошибки, если есть
    // Мой никаких фатальных ошибок не выдал - он просто постоянно возмущается на файлы формата .h
  // (7) Единственное, что не получилось: я не могу заставить его выводить значение на экран - мой компилятор просто такое не умеет
  //Алгоритм такой: Все ваши данные в форматах либо uint256, либо uint64 - их printf выводить не умеет 
  //Поэтому сначала их нужно переконвертировать: например, я хочу вывести значение value на экран - он в формате uint64
  //Подключаете библиотеку inttypes.h(она стандартная) : 7.1
  //А затем используйте конвертацию: 7.2
  // Но я не могу ничего проверить, т.к мой компилятор не выводит значение(он не умеет это делать ВООБЩЕ)

//ИТОГО: работают блоки 1 и 2.1(2.4?). Все, что связано с Joinsplit - пока отдыхает 

#include "Note.hpp"
#include "prf.h"
#include "crypto/sha256.h"
#define __STDC_FORMAT_MACROS

#include <fstream>
#include <iostream>
#include <string>

#include "version.h"
#include "streams.h"
#include <inttypes.h>(7.1)
#include <stdint.h>
#include <fstream>
#include "util.h"

namespace libzcash {

Note::Note() {


    a_pk = random_uint256();
    rho = random_uint256();
    r = random_uint256();
    value = 0;
    printf("%" PRIu64 "\n", value); (7.2)

}

uint256 Note::cm() const {
    unsigned char discriminant = 0xb0;

    CSHA256 hasher;
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
    return PRF_nf(a_sk, rho);
}

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
