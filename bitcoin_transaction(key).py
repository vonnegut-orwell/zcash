# Пусть у нас есть произвольный 256-битный private key. Затем The Elliptic Curve DSA algorithm создает из private key наш public key(512-битный):

def privateKeyToPublicKey(s):
    sk = ecdsa.SigningKey.from_string(s.decode('hex'), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    return ('\04' + sk.verifying_key.to_string()).encode('hex')
    
# Дальше я этот 512-битный public key хеширую, используя SHA-256 и RIPEMD алгоритмы. И далее его шифруем в адрес с помощью Base58Check encode. 

def pubKeyToAddr(s):
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(hashlib.sha256(s.decode('hex')).digest())
    return utils.base58CheckEncode(0, ripemd160.digest())

def keyToAddr(s):
    return pubKeyToAddr(privateKeyToPublicKey(s))
    
# Теперь создадим саму транзакцию(one-to-one для простоты). Возьмем левые адреса из coinbase: 
# Ништяки типа scriptSig and scriptPubKey будут разобраны позднее:
def makeRawTransaction(outputTransactionHash, sourceIndex, scriptSig, outputs):
    #Определим функцию makeOutput: она будет брать
    def makeOutput(data):
        redemptionSatoshis, outputScript = data
        return (struct.pack("<Q", redemptionSatoshis).encode('hex') + #struct.pack должен перевести строку в двоичную систему, а затем encode ее хеширует. Как я понимаю, redemptionSatoshis - это количество Сатоши, которые пойдут на output
        '%02x' % len(outputScript.decode('hex')) + outputScript) #len вернет мне значение длины строки
    formattedOutputs = ''.join(map(makeOutput, outputs))
    return (
        "01000000" + #номер версии, а она пока всегда единичка
        "01" + #количество входов. У нас один вход(и выход тоже один, к слову)
        outputTransactionHash.decode('hex')[::-1].encode('hex') + #достаем хеш входа
        struct.pack('<L', sourceIndex).encode('hex') + #struct.pack должен перевести нашу уже хешированую строку(обрати внимание на encode)
        '%02x' % len(scriptSig.decode('hex')) + scriptSig + # Ништяки типа scriptSig and scriptPubKey будут разобраны позднее:
        "ffffffff" + 
        "%02x" % len(outputs) + # количество выходов  
        formattedOutputs +
        "00000000" #время блокировки
        )

