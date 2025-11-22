"""
Зависимости:
  pip install mnemonic bip32utils requests base58
"""
import asyncio
import os
import hashlib
from typing import Optional, Tuple

try:
    from mnemonic import Mnemonic
except Exception as e:
    raise SystemExit("Требуется пакет 'mnemonic'. Установите: pip install mnemonic") from e

try:
    from bip32utils import BIP32Key
except Exception as e:
    raise SystemExit("Требуется пакет 'bip32utils'. Установите: pip install bip32utils") from e

try:
    import requests
except Exception as e:
    raise SystemExit("Требуется пакет 'requests'. Установите: pip install requests") from e

try:
    import base58
except Exception as e:
    raise SystemExit("Требуется пакет 'base58'. Установите: pip install base58") from e


class BTCKey:
    @staticmethod
    def new_mnemonic(strength: int = 256) -> str:
        return Mnemonic("english").generate(strength=strength)

    @staticmethod
    def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
        return Mnemonic("english").to_seed(mnemonic, passphrase=passphrase)

    @staticmethod
    def seed_to_bip32_master(seed: bytes) -> BIP32Key:
        if not seed or len(seed) < 16:
            raise ValueError("Seed слишком короткий")
        return BIP32Key.fromEntropy(seed)


def _sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def _ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()


def pubkey_to_p2pkh_address(pubkey_bytes: bytes, mainnet: bool = True) -> str:
    h160 = _ripemd160(_sha256(pubkey_bytes))
    version = b'\x00' if mainnet else b'\x6f'
    return base58.b58encode_check(version + h160).decode()


def privkey_to_wif(privkey_bytes: bytes, compressed: bool = True, mainnet: bool = True) -> str:
    prefix = b'\x80' if mainnet else b'\xEF'
    payload = prefix + privkey_bytes + (b'\x01' if compressed else b'')
    return base58.b58encode_check(payload).decode()


class BTCWallet:
    HARDEN = 0x80000000

    def __init__(self, network: str = "testnet"):
        self.network = network 
        self.mnemonic: Optional[str] = None
        self.private_wif: Optional[str] = None
        self.address: Optional[str] = None

    async def create_new(self, passphrase: str = "") -> Tuple[str, str]:
        mnemonic = BTCKey.new_mnemonic()
        seed = BTCKey.mnemonic_to_seed(mnemonic, passphrase)
        master = BTCKey.seed_to_bip32_master(seed)
        addr, wif = self._derive_account(master)
        self.mnemonic = mnemonic
        self.private_wif = wif
        self.address = addr
        return mnemonic, addr

    async def restore_from_mnemonic(self, mnemonic: str, passphrase: str = "") -> str:
        seed = BTCKey.mnemonic_to_seed(mnemonic, passphrase)
        master = BTCKey.seed_to_bip32_master(seed)
        addr, wif = self._derive_account(master)
        self.mnemonic = mnemonic
        self.private_wif = wif
        self.address = addr
        return addr

    def _derive_account(self, master: BIP32Key) -> Tuple[str, str]:
        coin = 0 if self.network == "mainnet" else 1
        node = master.ChildKey(44 + self.HARDEN).ChildKey(coin + self.HARDEN).ChildKey(0 + self.HARDEN).ChildKey(0).ChildKey(0)
        # предполагаем стандартные методы у bip32utils
        pub = node.PublicKey()
        priv = node.PrivateKey()
        addr = pubkey_to_p2pkh_address(pub, mainnet=(self.network == "mainnet"))
        wif = privkey_to_wif(priv, compressed=True, mainnet=(self.network == "mainnet"))
        return addr, wif

    def get_address(self) -> Optional[str]:
        return self.address

    def get_private_wif(self) -> Optional[str]:
        return self.private_wif

    async def get_balance(self) -> float:
        if not self.address:
            raise RuntimeError("Wallet not initialized")
        base = "https://blockstream.info/api" if self.network == "mainnet" else "https://blockstream.info/testnet/api"
        url = f"{base}/address/{self.address}"
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        data = r.json()
        chain = data.get("chain_stats", {})
        funded = int(chain.get("funded_txo_sum", 0))
        spent = int(chain.get("spent_txo_sum", 0))
        return float(funded - spent) / 1e8


async def demo_cli():
    cli = BTCWallet(network="testnet")
    try:
        while True:
            os.system("cls" if os.name == "nt" else "clear")
            print("Bitcoin Wallet (BIP39 -> BIP44 P2PKH)")
            print("1) Создать новый кошелёк (mnemonic)")
            print("2) Восстановить из мнемоники")
            print("3) Показать адрес и приватный WIF (если есть)")
            print("4) Показать баланс")
            print("5) Выход")
            choice = input("Выберите: ").strip()
            if choice == "1":
                passphrase = input("Passphrase (optional): ").strip()
                mnemonic, addr = await cli.create_new(passphrase)
                print("\nMnemonic (SAVE THIS):")
                print(mnemonic)
                print("\nPrivate WIF:")
                print(cli.get_private_wif())
                input("\nНажмите Enter для продолжения...")
            elif choice == "2":
                m = input("Введите мнемонику (через пробел): ").strip()
                passphrase = input("Passphrase (если есть): ").strip()
                try:
                    addr = await cli.restore_from_mnemonic(m, passphrase)
                    print("Адрес:", addr)
                    print("Private WIF:", cli.get_private_wif())
                except Exception as e:
                    print("Ошибка:", e)
                input("\nНажмите Enter для продолжения...")
            elif choice == "3":
                print("Address:", cli.get_address())
                print("Private WIF:", cli.get_private_wif())
                input("\nНажмите Enter для продолжения...")
            elif choice == "4":
                if not cli.address:
                    print("Сначала создайте или восстановите кошелёк.")
                else:
                    try:
                        bal = await cli.get_balance()
                        print(f"Balance: {bal:.8f} BTC")
                    except Exception as e:
                        print("Ошибка получения баланса:", e)
                input("\nНажмите Enter для продолжения...")
            elif choice == "5":
                break
            else:
                continue
    finally:
        pass


if __name__ == "__main__":
    try:
        asyncio.run(demo_cli())
    except KeyboardInterrupt:
        print("\nExit")